# --- START OF FILE app.py ---

import os
import redis # Ensure redis is imported
import hashlib
import requests
import uuid
import stripe
import json
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from dotenv import load_dotenv
import logging # Ensure logging is imported

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
# Configure basic logging (ensure this runs)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(name)s:%(message)s')
app.logger.setLevel(logging.INFO) # Set level for app logger

app.secret_key = os.environ.get('SECRET_KEY') or 'dev-fallback-secret'

# --- Configuration ---
# Redis setup
redis_url = os.environ.get('REDIS_URL')
redis_client = None
app.logger.info(f"Read REDIS_URL from environment: {redis_url}") # Log the URL read

if redis_url:
    try:
        app.logger.info(f"Attempting to connect to Redis at: {redis_url}") # Use logger
        redis_client = redis.from_url(redis_url, socket_timeout=5) # Add timeout
        app.logger.info("Attempting Redis PING...") # Log before ping
        redis_client.ping() # <--- ADD PING TEST HERE
        app.logger.info("Redis connection successful and PING successful.") # Use logger
    except redis.exceptions.ConnectionError as ce:
        # Catch specific connection errors
        app.logger.error(f"Redis connection error during startup: {ce}", exc_info=True)
        app.logger.error("Check REDIS_URL, network connectivity, and Redis server status.")
        redis_client = None # Ensure it's None
    except redis.exceptions.AuthenticationError as ae:
         # Catch specific auth errors
        app.logger.error(f"Redis authentication error during startup: {ae}", exc_info=True)
        app.logger.error("Check password in REDIS_URL.")
        redis_client = None
    except Exception as e:
        # Catch any other exceptions during connection
        app.logger.error(f"Generic error connecting to Redis during startup: {e}", exc_info=True)
        redis_client = None # Ensure it's None
else:
    app.logger.warning("REDIS_URL not set; Redis features disabled.") # Use logger

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
    app.logger.warning("Warning: STRIPE_SECRET_KEY not set; paid flow disabled.")


# --- Helper Functions ---
def verify_turnstile(token, remoteip=None):
    """Verify Cloudflare Turnstile token server-side."""
    if not TURNSTILE_SECRET_KEY :
         # If secret key isn't set, don't attempt verification (allows local dev)
        app.logger.warning("Turnstile secret key not set, skipping verification.")
        return True
    if not token:
        app.logger.warning("No Turnstile token provided by client.")
        return False # Explicitly fail if key is set but token is missing

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
        response_json = r.json()
        app.logger.info(f"Turnstile verification response: {response_json}")
        return response_json.get("success", False)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Turnstile verification network error: {e}", exc_info=True)
        return False
    except Exception as e:
        app.logger.error(f"Turnstile verification error: {e}", exc_info=True)
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
            app.logger.warning("Warning: File stream not seekable. Reading into memory to get size.")
            # We need to read the content to get the size
            # Be cautious about memory usage with large non-seekable files
            content = file_storage.read()
            size = len(content)
            # Try seeking back - might fail if truly non-seekable after read
            try:
                file_storage.stream.seek(0)
            except Exception:
                 app.logger.error(f"Could not seek back non-seekable stream for {file_storage.filename} after reading size.", exc_info=True)
                 # Cannot reliably re-read, might cause issues later
                 return -2 # Indicate error state where stream is consumed
            return size
    except Exception as e:
        app.logger.error(f"Error getting file size: {e}", exc_info=True)
        return -1 # Indicate general error

def send_email_via_mailgun(recipient, subject, body, from_name, reply_to_email, attachments_for_mg=None):
    """Sends email using Mailgun API."""
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        app.logger.error("Mailgun credentials missing; cannot send email.")
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
        app.logger.info(f"Sending email via Mailgun to {recipient} with subject '{subject}'.")
        resp = requests.post(url, auth=auth, data=data, files=files, timeout=30) # Add timeout
        resp.raise_for_status() # Check for HTTP errors
        app.logger.info(f"Mailgun response: {resp.status_code} - {resp.text}")
        return True
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error sending via Mailgun (Network/HTTP): {e}", exc_info=True)
        if hasattr(e, 'response') and e.response is not None:
            app.logger.error(f"Mailgun Response Content: {e.response.text}")
        return False
    except Exception as e:
        app.logger.error(f"Error sending via Mailgun (Other): {e}", exc_info=True)
        return False
# --- End Helper Functions ---


# --- Basic Page Routes ---
@app.route('/')
def index():
    app.logger.info("Serving index page.")
    return render_template('index.html')

@app.route('/mailer')
def mailer():
    app.logger.info(f"Serving mailer page. Turnstile Site Key: {TURNSTILE_SITE_KEY}")
    return render_template('mailer.html', turnstile_sitekey=TURNSTILE_SITE_KEY)

@app.route('/about')
def about():
    app.logger.info("Serving about page.")
    return render_template('about.html')

@app.route('/terms')
def terms():
    app.logger.info("Serving terms page.")
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    app.logger.info("Serving privacy page.")
    return render_template('privacy.html')

@app.route('/thankyou')
def thankyou():
    app.logger.info("Serving thankyou page.")
    return render_template('thankyou.html')
# --- End Basic Page Routes ---


# --- Payment and Email Submission ---
@app.route('/start-payment', methods=['POST'])
def start_payment():
    app.logger.info("Entered start_payment route.") # <<< LOG 1

    # 1. Read form fields first (needed for context even if checks fail)
    fn   = request.form.get('from_name', '').strip()
    fe   = request.form.get('from_email', '').strip()
    te   = request.form.get('to_email', '').strip()
    subj = request.form.get('subject', 'No Subject').strip()
    msg  = request.form.get('message', '').strip()
    free = 'free_trial' in request.form

    # Basic validation (optional but good)
    if not all([fn, fe, te, msg]):
        app.logger.warning("Form submission missing required fields.")
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
            app.logger.info(f"Processing uploaded file: {f.filename}")
            if not allowed_file(f.filename):
                app.logger.warning(f"Invalid file type uploaded: {f.filename}")
                flash(f"Invalid file type for '{f.filename}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
                return redirect(url_for("mailer"))

            file_size = get_file_size(f)
            if file_size == -1:
                app.logger.error(f"Could not determine size of file '{f.filename}'.")
                flash(f"Could not determine size of file '{f.filename}'.", "error")
                return redirect(url_for("mailer"))
            elif file_size == -2:
                 app.logger.error(f"Stream consumed while getting size for non-seekable file '{f.filename}'. Cannot proceed.")
                 flash(f"Error processing attachment '{f.filename}'. Please try again.", "error")
                 return redirect(url_for("mailer"))


            app.logger.info(f"File '{f.filename}' size: {file_size} bytes.")
            total_attachment_size += file_size
            valid_file_objects.append(f) # Keep track of the valid FileStorage object

    app.logger.info(f"Total attachment size: {total_attachment_size} bytes.")
    # Perform the total size check
    if total_attachment_size > MAX_TOTAL_ATTACHMENT_SIZE_BYTES:
        current_size_mb = round(total_attachment_size / (1024 * 1024), 1)
        app.logger.warning(f"Attachment size limit exceeded: {current_size_mb}MB > {MAX_TOTAL_MB}MB.")
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
             app.logger.error(f"Seek error before Mailgun prep for file '{f.filename}': {e}", exc_info=True)
             flash(f"Error preparing attachment '{f.filename}' for sending.", "error")
             return redirect(url_for("mailer"))

        attachments_for_mg.append((
            'attachment',
            (f.filename, f.stream, f.mimetype)
        ))
    app.logger.info(f"Prepared {len(attachments_for_mg)} attachments for Mailgun.")
    # --- End Attachment Processing ---


    # 2. CAPTCHA validation (do this *after* basic checks like size limit)
    token = request.form.get("cf-turnstile-response")
    client_ip = request.remote_addr # Use direct remote_addr primarily
    app.logger.info(f"Attempting Turnstile validation. Client IP: {client_ip}. Token received: {'Yes' if token else 'No'}")
    if TURNSTILE_SECRET_KEY: # Only verify if the secret key is configured
        if not verify_turnstile(token, client_ip):
            app.logger.warning(f"Turnstile validation failed for IP {client_ip}.")
            flash("CAPTCHA verification failed. Please try again.", "error")
            return redirect(url_for("mailer"))
        else:
             app.logger.info("Turnstile validation successful.")
    else:
        app.logger.info("Skipping Turnstile validation as secret key is not set.")


    # 3. Free‑trial branch
    if free:
        app.logger.info("Processing free trial branch.") # <<< LOG 2

        # Use client_ip obtained earlier, fallback if needed
        ip_for_limit = client_ip or request.environ.get('HTTP_X_FORWARDED_FOR')
        if not ip_for_limit:
            app.logger.error("Could not determine IP for free trial limit.") # <<< LOG 3
            flash('Could not determine IP address for free trial limit.', 'error')
            return redirect(url_for('mailer'))

        app.logger.info(f"IP address for limit: {ip_for_limit}") # <<< LOG 4

        # Check Redis client *before* try block
        if not redis_client:
             app.logger.error("Redis client is None when trying to process free trial.") # <<< LOG 5 (Added explicit error log)
             flash('Free trial temporarily unavailable (Redis connection issue).', 'error')
             return redirect(url_for('mailer'))

        app.logger.info("Redis client appears available. Entering try block for Redis check.") # <<< LOG 6

        # --- START: RESTORED TRY/EXCEPT BLOCK ---
        try:
            ip_hash = hashlib.sha256(ip_for_limit.encode()).hexdigest()
            redis_key = f"free_trial_ip:{ip_hash}"

            app.logger.info(f"Checking Redis key: {redis_key}") # <<< LOG 7

            # ---> THE ACTUAL REDIS COMMAND <---
            key_exists = redis_client.exists(redis_key)
            # ---> END OF REDIS COMMAND <---

            app.logger.info(f"Result of redis_client.exists({redis_key}): {key_exists}") # <<< LOG 8

            if key_exists:
                app.logger.warning(f"Free trial limit reached for IP Hash: {ip_hash}")
                flash('Free trial limit reached for your IP address (1 per day).', 'error')
                return redirect(url_for('mailer'))

            # Send the email
            app.logger.info("Attempting to send email via Mailgun for free trial.") # <<< LOG 9
            ok = send_email_via_mailgun(te, subj, msg, fn, fe, attachments_for_mg)

            if ok:
                app.logger.info("Mailgun send successful. Attempting to set Redis key.") # <<< LOG 10
                # ---> THE SECOND REDIS COMMAND <---
                redis_client.setex(redis_key, timedelta(days=1), "used")
                # ---> END OF REDIS COMMAND <---
                app.logger.info(f"Set Redis key {redis_key}. Free trial successful.")
                return redirect(url_for('thankyou'))
            else:
                app.logger.error("Mailgun send failed for free trial.") # <<< LOG 11
                flash('Failed to send free email. Please try again later.', 'error')
                return redirect(url_for('mailer'))

        except redis.RedisError as e:
             # This is where the error *is now* caught again
             app.logger.error(f"Redis error during free trial check: {e}", exc_info=True) # <<< LOG 12 (TARGET)
             flash('Error checking free trial status. Please try again.', 'error')
             return redirect(url_for('mailer'))
        except Exception as e:
            # Catching other potential errors within the try block
            app.logger.error(f"Unexpected error during free trial processing: {e}", exc_info=True) # <<< LOG 13
            flash('An unexpected error occurred. Please try again.', 'error')
            return redirect(url_for('mailer'))
        # --- END: RESTORED TRY/EXCEPT BLOCK ---


    # 4. Paid branch
    app.logger.info("Processing paid branch.")
    if not STRIPE_SECRET_KEY:
        app.logger.error("Stripe secret key not configured for paid branch.")
        flash('Paid service is currently unavailable.', 'error')
        return redirect(url_for('mailer'))

    if not redis_client:
         app.logger.error("Redis client is None when trying to process paid flow.")
         flash('Paid service temporarily unavailable (Redis connection issue).', 'error')
         return redirect(url_for('mailer'))

    # CRITICAL FIX Acknowledgement: Attachments not stored for webhook.
    app.logger.info("Preparing paid email data for Redis (attachments not stored).")

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
        app.logger.info(f"Attempting to set Redis key {redis_email_key} for payment.")
        redis_client.setex(redis_email_key, timedelta(minutes=60), json.dumps(email_data_for_redis))
        app.logger.info(f"Successfully set Redis key {redis_email_key}.")
    except redis.RedisError as e:
        app.logger.error(f"Redis error saving email data for payment: {e}", exc_info=True)
        flash('Error preparing payment session. Please try again.', 'error')
        return redirect(url_for('mailer'))

    # Create Stripe session
    try:
        # Use a generic product name or the subject
        product_name = f"Phantom Mail: {subj}" if subj else "Phantom Mail Service"
        if len(product_name) > 100: # Stripe limit might apply here too
             product_name = product_name[:97] + "..."

        app.logger.info(f"Attempting to create Stripe Checkout session for Redis key {redis_email_key}.")
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
        app.logger.info(f"Created Stripe session {checkout_session.id} for Redis key {redis_email_key}")
        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        app.logger.error(f"Stripe API error: {e}", exc_info=True)
        # Clean up Redis key if Stripe fails
        if redis_client:
            try:
                app.logger.info(f"Cleaning up Redis key {redis_email_key} after Stripe API error.")
                redis_client.delete(redis_email_key)
            except redis.RedisError as redis_err:
                 app.logger.error(f"Redis cleanup error after Stripe failure: {redis_err}", exc_info=True)
        user_message = getattr(e, 'user_message', 'Could not initiate payment.')
        flash(f'Payment processor error: {user_message}', 'error')
        return redirect(url_for('mailer'))
    except Exception as e:
        app.logger.error(f"Unexpected error creating Stripe session: {e}", exc_info=True)
        # Clean up Redis key
        if redis_client:
             try:
                app.logger.info(f"Cleaning up Redis key {redis_email_key} after unexpected Stripe error.")
                redis_client.delete(redis_email_key)
             except redis.RedisError as redis_err:
                 app.logger.error(f"Redis cleanup error after unexpected failure: {redis_err}", exc_info=True)
        flash('An unexpected error occurred during payment setup.', 'error')
        return redirect(url_for('mailer'))

# --- End Payment and Email Submission ---


# --- Stripe Webhook Handler ---
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    app.logger.info("Stripe webhook request received.")
    # Ensure webhook secret is configured
    if not STRIPE_WEBHOOK_SECRET:
        app.logger.error("Stripe webhook secret not configured.")
        abort(500) # Internal Server Error if not configured

    payload = request.data # Use request.data for raw bytes
    sig_header = request.headers.get('Stripe-Signature')

    if not payload or not sig_header:
        app.logger.error("Webhook error: Missing payload or signature header.")
        abort(400)

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
        app.logger.info(f"Constructed webhook event: {event.get('id')}, type: {event.get('type')}")
    except ValueError as e:
        # Invalid payload
        app.logger.error(f"Webhook error: Invalid payload - {e}", exc_info=True)
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        app.logger.error(f"Webhook error: Invalid signature - {e}", exc_info=True)
        return "Invalid signature", 400
    except Exception as e:
        app.logger.error(f"Webhook construction error: {e}", exc_info=True)
        return "Webhook error", 500

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        app.logger.info(f"Webhook received for session: {session.id}, status: {session.payment_status}")

        # Retrieve the email key from metadata
        redis_email_key = session.get('metadata', {}).get('redis_email_key')

        if not redis_email_key:
            app.logger.error(f"Webhook error: Missing 'redis_email_key' in metadata for session {session.id}")
            return "Metadata key missing", 200 # Acknowledge receipt but note issue

        if not redis_client:
            app.logger.error(f"Webhook error: Redis client unavailable processing key {redis_email_key} for session {session.id}")
            abort(500) # Can't process without Redis

        # Retrieve email data from Redis
        try:
            app.logger.info(f"Attempting to retrieve Redis key {redis_email_key} for session {session.id}")
            raw_data = redis_client.get(redis_email_key)
            if not raw_data:
                app.logger.warning(f"Webhook: No data found in Redis for key {redis_email_key} (session {session.id}). Already processed or expired?")
                return "Data not found or already processed", 200 # Acknowledge, but nothing to do

            email_data = json.loads(raw_data)
            app.logger.info(f"Retrieved email data from Redis for key {redis_email_key}.")

            # --- Send the email ---
            # NOTE: Attachments are NOT included here because they weren't stored.
            app.logger.info(f"Processing paid email for key {redis_email_key} (session {session.id}) - No attachments.")
            ok = send_email_via_mailgun(
                recipient=email_data["to_email"],
                subject=email_data["subject"],
                body=email_data["message"],
                from_name=email_data["from_name"],
                reply_to_email=email_data["from_email"],
                attachments_for_mg=None # Pass None explicitly
            )

            if ok:
                app.logger.info(f"Paid email sent successfully via webhook for key {redis_email_key}. Deleting key.")
                # Clean up Redis key after successful processing
                redis_client.delete(redis_email_key)
            else:
                app.logger.error(f"Webhook error: Failed to send email via Mailgun for key {redis_email_key}")
                # Don't delete the key yet, might need manual retry or investigation
                abort(500) # Abort to signal Stripe to retry (if configured) or log failure

        except redis.RedisError as e:
            app.logger.error(f"Webhook error: Redis error processing key {redis_email_key} - {e}", exc_info=True)
            abort(500) # Abort, likely needs retry
        except json.JSONDecodeError as e:
            app.logger.error(f"Webhook error: Invalid JSON data in Redis key {redis_email_key} - {e}", exc_info=True)
            # Data is corrupt, likely can't recover automatically. Delete key? Log & alert.
            try:
                redis_client.delete(redis_email_key) # Delete bad data
            except redis.RedisError as del_e:
                 app.logger.error(f"Failed to delete corrupt Redis key {redis_email_key}: {del_e}", exc_info=True)
            abort(400) # Bad request essentially, data corrupted
        except Exception as e:
            app.logger.error(f"Webhook error: Unexpected error processing key {redis_email_key} - {e}", exc_info=True)
            abort(500) # Signal failure

    else:
        app.logger.info(f"Webhook received unhandled event type: {event['type']}")

    # Acknowledge receipt of the event
    return "Success", 200
# --- End Stripe Webhook Handler ---


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Default debug to False in production environments unless explicitly set
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() in ('true', '1', 't')
    app.logger.info(f"Starting Flask app on port {port} with debug mode: {debug_mode}") # Use logger
    # Use waitress or gunicorn in production instead of app.run()
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
# --- End Main Execution ---

# --- END OF FILE app.py ---