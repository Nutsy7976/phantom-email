# --- Imports ---
import os
import redis
import hashlib
import requests # For Mailgun API calls
import uuid # <-- For generating unique IDs
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash

# --- App and Redis Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_default_and_insecure_secret_key')

redis_url = os.environ.get('REDIS_URL')
redis_client = None # Initialize as None
if not redis_url:
    print("Warning: REDIS_URL environment variable not set. Free trial limiting and paid flow will not work.")
else:
    try:
        redis_client = redis.from_url(redis_url, decode_responses=True) # decode_responses=True helps work with strings
        redis_client.ping()
        print("Successfully connected to Redis.")
    except redis.exceptions.ConnectionError as e:
        print(f"Error connecting to Redis: {e}")
        print("Warning: Redis-dependent features (free trial limit, paid flow) will not work.")
        redis_client = None # Set back to None on error

# --- Mailgun Configuration ---
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY')
MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN')

# --- Real Mailgun Function ---
def send_email_via_mailgun(recipient, subject, body, from_name, reply_to_email, attachments=None):
    """Sends an email using the Mailgun API."""
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("Error: Mailgun API Key or Domain not configured in environment variables.")
        return False
    mailgun_url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    auth = ('api', MAILGUN_API_KEY)
    # Use a consistent sender address that Mailgun is verified for
    sender_email = f"sender@{MAILGUN_DOMAIN}" 
    from_header = f"{from_name} <{sender_email}>"
    
    data = {
        "from": from_header, 
        "to": [recipient], 
        "subject": subject,
        "text": body, 
        "h:Reply-To": reply_to_email # Mailgun uses 'h:Header-Name' for custom headers
    }
    
    # TODO: Implement file attachment handling for Mailgun
    files = None # This needs to be structured correctly for requests library files parameter
    
    print(f"Sending email via Mailgun to {recipient} from {from_header} (Reply-To: {reply_to_email})")
    try:
        response = requests.post(mailgun_url, auth=auth, data=data, files=files)
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
        print(f"Mailgun API response status: {response.status_code}")
        print(f"Mailgun API response body: {response.text}") # Log response for debugging
        return 200 <= response.status_code < 300 # Check for success status
    except requests.exceptions.RequestException as e:
        print(f"Error sending email via Mailgun: {e}")
        if hasattr(e, 'response') and e.response is not None:
             print(f"Mailgun Response (Error): {e.response.text}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during email sending: {e}")
        return False

# --- Basic Page Routes ---
@app.route('/')
def index(): return render_template('index.html')
@app.route('/mailer')
def mailer(): return render_template('mailer.html')
@app.route('/about')
def about(): return render_template('about.html')
@app.route('/terms')
def terms(): return render_template('terms.html')
@app.route('/privacy')
def privacy(): return render_template('privacy.html')
@app.route('/thankyou')
def thankyou(): return render_template('thankyou.html')


# --- Form Submission Route ---
@app.route('/start-payment', methods=['POST'])
def start_payment():
    if request.method == 'POST':
        # --- Get Form Data ---
        from_name = request.form.get('from_name')
        from_email = request.form.get('from_email') # This is the Reply-To
        to_email = request.form.get('to_email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        is_free_trial = 'free_trial' in request.form # Check if checkbox name exists in submitted data

        # TODO: Add file attachment handling: request.files.get('file1'), etc.
        # TODO: Add CAPTCHA validation

        print("\n--- Received Form Data ---")
        print(f"  From Name: {from_name}")
        print(f"  Reply-To Email: {from_email}")
        print(f"  To Email: {to_email}")
        print(f"  Subject: {subject}")
        # print(f"  Message: {message}") # Be cautious printing full messages
        print(f"  Free Trial Checkbox Sent: {is_free_trial}")
        print("--------------------------\n")

        if is_free_trial:
            # --- FREE TRIAL LOGIC ---
            print("Processing FREE trial request...")
            if not redis_client:
                 print("Error: Redis not available for free trial check.")
                 flash('Free trial system is temporarily unavailable.', 'error')
                 return redirect(url_for('mailer'))

            # Get IP Address (Handle proxies like Render's)
            if request.headers.getlist("X-Forwarded-For"):
               ip_address = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
            else:
               ip_address = request.remote_addr

            if not ip_address:
                 print("Error: Could not determine IP address.")
                 flash('Could not determine IP for free trial limit.', 'error')
                 return redirect(url_for('mailer'))

            ip_hash = hashlib.sha256(ip_address.encode('utf-8')).hexdigest()
            redis_key = f"free_trial_ip:{ip_hash}"
            block_duration = timedelta(days=1) # Limit to 1 per day

            try: 
                if redis_client.exists(redis_key):
                    print(f"Free trial limit reached for IP hash: {ip_hash[:10]}...")
                    flash('Free trial limit reached for your network (limit 1 per day). Please uncheck the box or try again later.', 'error')
                    return redirect(url_for('mailer'))
            except redis.exceptions.ConnectionError as e:
                print(f"Redis Error during exists check: {e}")
                flash('Could not check free trial status. Please try again.', 'error')
                return redirect(url_for('mailer'))

            # If limit not reached, send email and record usage
            print(f"Granting free trial for IP hash: {ip_hash[:10]}...")
            email_sent = send_email_via_mailgun(
                recipient=to_email, subject=subject, body=message,
                from_name=from_name, reply_to_email=from_email
                # attachments=processed_attachments # TODO Pass attachments later
            )

            if email_sent:
                try:
                    # Record usage in Redis
                    redis_client.setex(redis_key, block_duration, "used")
                    print(f"Recorded free trial usage for IP hash: {ip_hash[:10]}")
                    flash('Free email sent successfully!', 'success')
                    return redirect(url_for('thankyou'))
                except redis.exceptions.ConnectionError as e:
                     print(f"Redis Error during setex after sending free email: {e}")
                     # Email was sent, but log the warning
                     flash('Free email sent, but usage recording failed.', 'warning') 
                     return redirect(url_for('thankyou')) # Still redirect to thank you
            else:
                # Mailgun sending failed
                flash('Failed to send free email via provider. Please try again later.', 'error')
                return redirect(url_for('mailer'))
        
        else:
            # --- PAID FLOW LOGIC (Step 1: Store in Redis) --- # <-- THIS IS THE UPDATED SECTION
            print("Handling PAID request...")

            if not redis_client:
                print("Error: Redis is not connected. Cannot process paid request.")
                flash('Payment system is temporarily unavailable.', 'error')
                return redirect(url_for('mailer'))

            # 1. Create a unique ticket number (ID)
            email_id = str(uuid.uuid4()) 
            print(f"Generated unique Email ID: {email_id}")

            # 2. Gather the email details from the form
            email_data = {
                "to_email": to_email,
                "subject": subject,
                "message": message,
                "from_name": from_name,
                "from_email": from_email # Reply-To address
                # TODO: Add file handling info here later
                # "attachments": [ {'filename': 'doc.pdf', 'temp_path': '/tmp/xyz.pdf', 'content_type': 'application/pdf'} ] 
            }

            # 3. Store these details in Redis using the ID as the key
            redis_key = f"email:{email_id}"
            # Store it for 60 minutes (3600 seconds). Adjust if needed.
            storage_duration = timedelta(minutes=60) 

            try:
                # For now, store as a simple string. Later we might use JSON.
                # Note: Storing large messages/files directly as strings isn't ideal
                data_to_store = str(email_data) 
                
                redis_client.setex(redis_key, storage_duration, data_to_store)
                print(f"Stored email data in Redis with key: {redis_key} for {storage_duration.total_seconds()} seconds")

                # --- Placeholder for Next Step (Stripe Integration) ---
                print("TODO: Implement Stripe Checkout Session creation and redirect here.")
                flash('Data stored, ready for Stripe payment! (Stripe integration needed)', 'info') # Temp message
                # For now, just redirect back to the mailer page. 
                # **** THIS redirect WILL BE REPLACED by the redirect to Stripe ****
                return redirect(url_for('mailer')) 
                # --- End Placeholder ---

            except redis.exceptions.ConnectionError as e:
                print(f"Redis Error during setex for paid email: {e}")
                flash('Payment system error. Could not save email details.', 'error')
                return redirect(url_for('mailer'))
            except Exception as e:
                print(f"An unexpected error occurred storing data for paid email: {e}")
                flash('An unexpected error occurred. Please try again.', 'error')
                return redirect(url_for('mailer'))
            # --- End of PAID FLOW LOGIC (Step 1) ---

    # If GET request, redirect away
    return redirect(url_for('mailer'))


# --- Run the Flask development server ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Set debug=False when deploying to Render for production
    # Use '0.0.0.0' to be accessible on your network if needed, default is '127.0.0.1'
    app.run(debug=True, host='0.0.0.0', port=port) 