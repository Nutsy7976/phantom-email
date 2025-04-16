# --- Imports ---
import os
import redis
import hashlib
import requests # <-- Import requests
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash

# --- App and Redis Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_default_and_insecure_secret_key')

redis_url = os.environ.get('REDIS_URL')
redis_client = None # Initialize as None
if not redis_url:
    print("Warning: REDIS_URL environment variable not set. Free trial limiting will not work.")
else:
    try:
        redis_client = redis.from_url(redis_url, decode_responses=True)
        redis_client.ping()
        print("Successfully connected to Redis.")
    except redis.exceptions.ConnectionError as e:
        print(f"Error connecting to Redis: {e}")
        print("Warning: Free trial limiting will not work.")
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
    sender_email = f"sender@{MAILGUN_DOMAIN}" # Use a fixed sender for Mailgun
    from_header = f"{from_name} <{sender_email}>"
    data = {
        "from": from_header, "to": [recipient], "subject": subject,
        "text": body, "h:Reply-To": reply_to_email
    }
    files = None # TODO: Implement file handling later
    print(f"Sending email via Mailgun to {recipient} from {from_header} (Reply-To: {reply_to_email})")
    try:
        response = requests.post(mailgun_url, auth=auth, data=data, files=files)
        response.raise_for_status()
        print(f"Mailgun API response status: {response.status_code}")
        print(f"Mailgun API response body: {response.text}") # Log response for debugging
        # Check if Mailgun response indicates success (usually 200 OK)
        # Mailgun API might return other 2xx codes depending on setup
        return 200 <= response.status_code < 300
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


# --- Form Submission Route (with Debug Print) ---
@app.route('/start-payment', methods=['POST'])
def start_payment():
    if request.method == 'POST':
        from_name = request.form.get('from_name')
        from_email = request.form.get('from_email') # Reply-To
        to_email = request.form.get('to_email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # --- *** PRINT ALL RECEIVED FORM DATA FOR DEBUGGING *** ---
        print("\n--- Received Form Data ---")
        print(request.form)
        print("--------------------------\n")
        # --- *** END DEBUG PRINT *** ---

        is_free_trial = 'free_trial' in request.form # Use the robust check

        # TODO: Add file attachment handling
        # TODO: Add CAPTCHA validation

        print(f"Form submitted details:") # Combined prints
        print(f"  From Name: {from_name}")
        print(f"  To Email: {to_email}")
        print(f"  Subject: {subject}")
        print(f"  Free Trial Checkbox Sent: {is_free_trial}")

        if is_free_trial:
            # --- FREE TRIAL LOGIC ---
            if not redis_client:
                 flash('Free trial system is temporarily unavailable.', 'error')
                 return redirect(url_for('mailer'))

            # Get IP Address (Handle proxies)
            if request.headers.getlist("X-Forwarded-For"):
               ip_address = request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
            else:
               ip_address = request.remote_addr

            if not ip_address:
                 flash('Could not determine IP for free trial limit.', 'error')
                 return redirect(url_for('mailer'))

            ip_hash = hashlib.sha256(ip_address.encode('utf-8')).hexdigest()
            redis_key = f"free_trial_ip:{ip_hash}"
            block_duration = timedelta(days=1) # 24 hours

            try: # Wrap Redis check in try/except for connection errors
                if redis_client.exists(redis_key):
                    flash('Free trial limit reached for your network (limit 1 per day). Please uncheck the box or try again later.', 'error')
                    return redirect(url_for('mailer'))
            except redis.exceptions.ConnectionError as e:
                print(f"Redis Error during exists check: {e}")
                flash('Could not check free trial status. Please try again.', 'error')
                return redirect(url_for('mailer'))

            # If we get here, the IP hasn't used a free trial recently
            print(f"Granting free trial for IP hash: {ip_hash[:10]}...")
            email_sent = send_email_via_mailgun(
                recipient=to_email, subject=subject, body=message,
                from_name=from_name, reply_to_email=from_email
                # attachments=processed_attachments # TODO Pass attachments later
            )

            if email_sent:
                try:
                    redis_client.setex(redis_key, block_duration, "used")
                    flash('Free email sent successfully!', 'success')
                    return redirect(url_for('thankyou'))
                except redis.exceptions.ConnectionError as e:
                     print(f"Redis Error during setex: {e}")
                     flash('Free email sent, but usage recording failed.', 'warning')
                     return redirect(url_for('thankyou')) # Still redirect as email was sent
            else:
                flash('Failed to send free email via provider. Please try again later.', 'error')
                return redirect(url_for('mailer'))
        else:
            # --- PAID FLOW LOGIC (Still Placeholder) ---
            print("Proceeding to PAID flow (Placeholder)...")
            # TODO: Implement paid logic (Redis temp store + Stripe redirect)
            flash('Paid flow not implemented yet. Please use free trial for now.', 'info')
            return redirect(url_for('mailer'))

    # If GET request, redirect away
    return redirect(url_for('mailer'))


# --- Run the Flask development server ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Set debug=False when deploying to Render for production
    app.run(debug=True, host='0.0.0.0', port=port)