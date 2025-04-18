# --- START OF FILE app.py ---

import os
import redis
import hashlib
import requests
import uuid
import stripe
import json
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-fallback-secret'

# --- Configuration ---
# Redis setup
redis_url = os.environ.get('REDIS_URL')
redis_client = None
if redis_url:
    try:
        redis_client = redis.from_url(redis_url)
    except Exception as e:
        print(f"Error connecting to Redis: {e}")
        print("Warning: Redis-dependent features will not work locally if connection fails.")
else:
    print("Warning: REDIS_URL not set; Redis features disabled.")

# Service configurations
MAILGUN_API_KEY        = os.environ.get('MAILGUN_API_KEY')
MAILGUN_DOMAIN         = os.environ.get('MAILGUN_DOMAIN')
STRIPE_SECRET_KEY      = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET')
TURNSTILE_SECRET_KEY   = os.getenv("TURNSTILE_SECRET_KEY")
TURNSTILE_SITE_KEY     = os.getenv("TURNSTILE_SITEKEY") or os.getenv("TURNSTILE_SITE_KEY")

# Application Constants
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_TOTAL_ATTACHMENT_SIZE_BYTES = 15 * 1024 * 1024 # 15 MB limit (matches frontend)
# --- End Configuration ---


if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    print("Warning: STRIPE_SECRET_KEY not set; paid flow disabled.")


# --- Helper Functions ---
def verify_turnstile(token, remoteip=None):
    """Verify Cloudflare Turnstile token server-side."""
    if not TURNSTILE_SECRET_KEY or not token:
         # If secret key isn't set, don't attempt verification (allows local dev)
         # Or if no token provided by client
        return True if not TURNSTILE_SECRET_KEY else False
    payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
    if remoteip:
        payload["remoteip"] = remoteip
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=5 # Add a timeout
        )
        r.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return r.json().get("success", False)
    except requests.exceptions.RequestException as e:
        print(f"Turnstile verification network error: {e}")
        return False
    except Exception as e:
        print(f"Turnstile verification error: {e}")
        return False


def allowed_file(filename):
    """Return True if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size(file_storage):
    """Safely get the size of a FileStorage object's stream."""
    try:
        # Check if the stream is seekable
        if file_storage.stream.seekable():
            original_pos = file_storage.stream.tell()
            file_storage.stream.seek(0, os.SEEK_END)
            size = file_storage.stream.tell()
            file_storage.stream.seek(original_pos) # Reset position
            return size
        else:
            # If not seekable, read into memory (less ideal, fallback)
            # This might happen in specific WSGI server configs
            print("Warning: File stream not seekable. Reading into memory to get size.")
            content = file_storage.read()
            size = len(content)
            # We need to be able to read it again later, so reset if possible (though read consumed it)
            # This part is tricky if not seekable. Saving might be required.
            # For now, assume seekable is the common case.
            file_storage.stream.seek(0) # Try seeking back anyway
            return size
    except Exception as e:
        print(f"Error getting file size: {e}")
        return -1 # Indicate error

def send_email_via_mailgun(recipient, subject, body, from_name, reply_to_email, attachments_for_mg=None):
    """Sends email using Mailgun API."""
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("Mailgun credentials missing; cannot send email.")
        return False

    url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    auth = ('api', MAILGUN_API_KEY)
    data = {
        "from": f"{from_name} <sender@{MAILGUN_DOMAIN}>", # Use a verified sender domain
        "to": [recipient],
        "subject": subject,
        "text": body,
        "h:Reply-To": reply_to_email,
        # Disable Mailgun tracking
        "o:tracking": 'false',
        "o:tracking-clicks": 'false',
        "o:tracking-opens": 'false'
    }

    files = attachments_for_mg or []

    try:
        resp = requests.post(url, auth=auth, data=data, files=files, timeout=30) # Add timeout
        resp.raise_for_status() # Check for HTTP errors
        print(f"Mailgun response: {resp.status_code} - {resp.text}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending via Mailgun (Network/HTTP): {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Mailgun Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Error sending via Mailgun (Other): {e}")
        return False
# --- End Helper Functions ---


# --- Basic Page Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mailer')
def mailer():
    return render_template('mailer.html', turnstile_sitekey=TURNSTILE_SITE_KEY)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')
# --- End Basic Page Routes ---


# --- Payment and Email Submission ---
@app.route('/start-payment', methods=['POST'])
def start_payment():
    # No need for 'if request.method != 'POST':' check due to methods=['POST']

    # 1. Read form fields first (needed for context even if checks fail)
    fn   = request.form.get('from_name', '').strip()
    fe   = request.form.get('from_email', '').strip()
    te   = request.form.get('to_email', '').strip()
    subj = request.form.get('subject', 'No Subject').strip()
    msg  = request.form.get('message', '').strip()
    free = 'free_trial' in request.form

    # Basic validation (optional but good)
    if not all([fn, fe, te, msg]):
        flash('Missing required fields.', 'error')
        return redirect(url_for('mailer'))

    # --- Attachment Processing and Size Check ---
    valid_file_objects = [] # Store valid FileStorage objects temporarily
    total_attachment_size = 0
    MAX_TOTAL_MB = MAX_TOTAL_ATTACHMENT_SIZE_BYTES / (1024 * 1024)

    for key in ('file1', 'file2'):
        f = request.files.get(key)
        # Check if a file was actually uploaded and has a name
        if f and f.filename:
            if not allowed_file(f.filename):
                flash(f"Invalid file type for '{f.filename}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
                return redirect(url_for("mailer"))

            file_size = get_file_size(f)
            if file_size == -1:
                flash(f"Could not determine size of file '{f.filename}'.", "error")
                return redirect(url_for("mailer"))

            total_attachment_size += file_size
            valid_file_objects.append(f) # Keep track of the valid FileStorage object

    # Perform the total size check
    if total_attachment_size > MAX_TOTAL_ATTACHMENT_SIZE_BYTES:
        current_size_mb = round(total_attachment_size / (1024 * 1024), 1)
        flash(f"Total attachment size ({current_size_mb}MB) exceeds the limit ({MAX_TOTAL_MB}MB).", "error")
        return redirect(url_for("mailer"))

    # Prepare attachments list for Mailgun *only if* checks passed
    attachments_for_mg = []
    for f in valid_file_objects:
        # Ensure stream position is at the beginning before adding
        try:
            f.stream.seek(0)
        except Exception as e:
             # This might happen if the stream was non-seekable and read in get_file_size
             flash(f"Error preparing attachment '{f.filename}' for sending.", "error")
             print(f"Seek error before Mailgun prep: {e}")
             return redirect(url_for("mailer"))

        attachments_for_mg.append((
            'attachment',
            (f.filename, f.stream, f.mimetype)
        ))
    # --- End Attachment Processing ---


    # 2. CAPTCHA validation (do this *after* basic checks like size limit)
    token = request.form.get("cf-turnstile-response")
    client_ip = request.remote_addr
    if TURNSTILE_SECRET_KEY: # Only verify if the secret key is configured
        if not verify_turnstile(token, client_ip):
            flash("CAPTCHA verification failed. Please try again.", "error")
            return redirect(url_for("mailer"))

    # 3. Free‑trial branch
    if free:
        # Use client_ip obtained earlier
        ip_for_limit = client_ip or request.environ.get('HTTP_X_FORWARDED_FOR') # Fallback
        if not ip_for_limit:
            flash('Could not determine IP address for free trial limit.', 'error')
            return redirect(url_for('mailer'))

        if not redis_client:
             flash('Free trial temporarily unavailable (Redis connection issue).', 'error')
             return redirect(url_for('mailer'))

        try:
            ip_hash = hashlib.sha256(ip_for_limit.encode()).hexdigest()
            redis_key = f"free_trial_ip:{ip_hash}"
            if redis_client.exists(redis_key):
                flash('Free trial limit reached for your IP address (1 per day).', 'error')
                return redirect(url_for('mailer'))

            # Send the email
            ok = send_email_via_mailgun(te, subj, msg, fn, fe, attachments_for_mg)
            if ok:
                redis_client.setex(redis_key, timedelta(days=1), "used")
                print(f"Free email sent successfully. IP Hash: {ip_hash}")
                return redirect(url_for('thankyou'))
            else:
                flash('Failed to send free email. Please try again later.', 'error')
                return redirect(url_for('mailer'))
        except redis.RedisError as e:
             print(f"Redis error during free trial check: {e}")
             flash('Error checking free trial status. Please try again.', 'error')
             return redirect(url_for('mailer'))
        except Exception as e:
            print(f"Unexpected error during free trial processing: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')
            return redirect(url_for('mailer'))


    # 4. Paid branch
    if not STRIPE_SECRET_KEY:
        flash('Paid service is currently unavailable.', 'error')
        return redirect(url_for('mailer'))

    if not redis_client:
         flash('Paid service temporarily unavailable (Redis connection issue).', 'error')
         return redirect(url_for('mailer'))

    # CRITICAL FIX: Handle attachments for paid flow
    # Option 1: Store file paths (Requires saving files first) - More complex, robust
    # Option 2: Store file content in Redis (Not recommended for large files, but simpler if files are small enough)
    # Option 3: Don't support attachments in paid flow via webhook easily without storage
    # Let's proceed WITHOUT attachment support in the *webhook* path for now, as it requires
    # significant changes (e.g., temporary file storage). The user gets the file size check,
    # but the webhook won't resend them if this flow is interrupted.
    # If attachments MUST work for paid, temporary storage (e.g., S3, local disk with cleanup) is needed.

    email_id = str(uuid.uuid4())
    redis_email_key = f"email:{email_id}"
    # Store *only* text data in Redis for the webhook
    email_data_for_redis = {
        "to_email": te,
        "subject": subj,
        "message": msg,
        "from_name": fn,
        "from_email": fe,
        # Add identifiers or paths here if implementing temp storage
        "attachment_filenames": [f.filename for f in valid_file_objects] # Store names for potential logging/reference
    }

    try:
        redis_client.setex(redis_email_key, timedelta(minutes=60), json.dumps(email_data_for_redis))
    except redis.RedisError as e:
        print(f"Redis error saving email data for payment: {e}")
        flash('Error preparing payment session. Please try again.', 'error')
        return redirect(url_for('mailer'))

    # Create Stripe session
    try:
        # Use a generic product name or the subject
        product_name = f"Phantom Mail: {subj}" if subj else "Phantom Mail Service"
        if len(product_name) > 100: # Stripe limit might apply here too
             product_name = product_name[:97] + "..."

        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': product_name},
                    'unit_amount': 100 # Example: $1.00
                },
                'quantity': 1
            }],
            mode='payment',
            success_url=url_for('thankyou', _external=True) + "?session_id={CHECKOUT_SESSION_ID}", # Recommended practice
            cancel_url=url_for('mailer', _external=True),
            metadata={'redis_email_key': redis_email_key} # Link session to Redis data
        )
        print(f"Created Stripe session {checkout_session.id} for Redis key {redis_email_key}")
        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        print(f"Stripe API error: {e}")
        # Clean up Redis key if Stripe fails
        if redis_client:
            try:
                redis_client.delete(redis_email_key)
            except redis.RedisError as redis_err:
                 print(f"Redis cleanup error after Stripe failure: {redis_err}")
        flash(f'Payment processor error: {e.user_message}' if hasattr(e, 'user_message') else 'Could not initiate payment.', 'error')
        return redirect(url_for('mailer'))
    except Exception as e:
        print(f"Unexpected error creating Stripe session: {e}")
        # Clean up Redis key
        if redis_client:
             try:
                redis_client.delete(redis_email_key)
             except redis.RedisError as redis_err:
                 print(f"Redis cleanup error after unexpected failure: {redis_err}")
        flash('An unexpected error occurred during payment setup.', 'error')
        return redirect(url_for('mailer'))

# --- End Payment and Email Submission ---


# --- Stripe Webhook Handler ---
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    # Ensure webhook secret is configured
    if not STRIPE_WEBHOOK_SECRET:
        print("Error: Stripe webhook secret not configured.")
        abort(500) # Internal Server Error if not configured

    payload = request.data # Use request.data for raw bytes
    sig_header = request.headers.get('Stripe-Signature')

    if not payload or not sig_header:
        print("Webhook error: Missing payload or signature header.")
        abort(400)

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        print(f"Webhook error: Invalid payload - {e}")
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        print(f"Webhook error: Invalid signature - {e}")
        return "Invalid signature", 400
    except Exception as e:
        print(f"Webhook construction error: {e}")
        return "Webhook error", 500

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        print(f"Webhook received for session: {session.id}, status: {session.payment_status}")

        # Retrieve the email key from metadata
        redis_email_key = session.get('metadata', {}).get('redis_email_key')

        if not redis_email_key:
            print(f"Webhook error: Missing 'redis_email_key' in metadata for session {session.id}")
            # Don't abort necessarily, just log it. Might be other metadata uses.
            return "Metadata key missing", 200 # Acknowledge receipt but note issue

        if not redis_client:
            print(f"Webhook error: Redis client unavailable for key {redis_email_key}")
            # This is tricky. The payment succeeded. Maybe retry later? For now, abort.
            abort(500) # Can't process without Redis

        # Retrieve email data from Redis
        try:
            raw_data = redis_client.get(redis_email_key)
            if not raw_data:
                print(f"Webhook warning: No data found in Redis for key {redis_email_key} (session {session.id}). Already processed or expired?")
                return "Data not found or already processed", 200 # Acknowledge, but nothing to do

            email_data = json.loads(raw_data)

            # --- Send the email ---
            # NOTE: Attachments are NOT included here because they weren't stored.
            # This requires the temporary file storage implementation mentioned earlier.
            print(f"Processing paid email for key {redis_email_key} (session {session.id})")
            ok = send_email_via_mailgun(
                recipient=email_data["to_email"],
                subject=email_data["subject"],
                body=email_data["message"],
                from_name=email_data["from_name"],
                reply_to_email=email_data["from_email"],
                attachments_for_mg=None # Pass None explicitly
            )

            if ok:
                print(f"Paid email sent successfully via webhook for key {redis_email_key}")
                # Clean up Redis key after successful processing
                redis_client.delete(redis_email_key)
            else:
                print(f"Webhook error: Failed to send email via Mailgun for key {redis_email_key}")
                # Don't delete the key yet, might need manual retry or investigation
                # Consider implementing a retry mechanism or logging for manual action
                abort(500) # Abort to signal Stripe to retry (if configured) or log failure

        except redis.RedisError as e:
            print(f"Webhook error: Redis error processing key {redis_email_key} - {e}")
            abort(500) # Abort, likely needs retry
        except json.JSONDecodeError as e:
            print(f"Webhook error: Invalid JSON data in Redis key {redis_email_key} - {e}")
            # Data is corrupt, likely can't recover automatically. Delete key? Log & alert.
            redis_client.delete(redis_email_key) # Delete bad data
            abort(400) # Bad request essentially, data corrupted
        except Exception as e:
            print(f"Webhook error: Unexpected error processing key {redis_email_key} - {e}")
            abort(500) # Signal failure

    else:
        print(f"Webhook received unhandled event type: {event['type']}")

    # Acknowledge receipt of the event
    return "Success", 200
# --- End Stripe Webhook Handler ---


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Default debug to False in production environments unless explicitly set
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() in ('true', '1', 't')
    print(f"Starting Flask app on port {port} with debug mode: {debug_mode}")
    # Use waitress or gunicorn in production instead of app.run()
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
# --- End Main Execution ---

# --- END OF FILE app.py ---