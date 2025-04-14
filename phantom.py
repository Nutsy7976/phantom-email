# ==============================================================================
# phantom.py - Backend for the Phantom Anonymous Email Service
# ==============================================================================

# --- 1. Import Necessary Libraries ---
# These lines bring in pre-written code modules to handle different tasks.

import os                     # For accessing environment variables (like secret keys)
import stripe                 # For interacting with the Stripe payment service
import redis                  # For connecting to the Redis temporary database
import requests               # For making HTTP requests (to send email via TES API)
import json                   # For working with JSON data format (used with Redis/Stripe)
import uuid                   # For generating unique IDs for transactions
from datetime import timedelta # For setting time limits (like how long data stays in Redis)
import base64                 # For encoding/decoding file data to store in Redis
import logging                # For logging information and errors
import bleach                 # For cleaning user input to prevent XSS attacks
from flask import (
    Flask, request, redirect, render_template, url_for,
    jsonify, flash, abort
)                             # Core components of the Flask web framework
from werkzeug.utils import secure_filename # For making filenames safe
from werkzeug.exceptions import RequestEntityTooLarge, NotFound # For handling specific errors
from dotenv import load_dotenv # For loading environment variables from a .env file
from flask_limiter import Limiter # For rate limiting (preventing too many requests)
from flask_limiter.util import get_remote_address # Helper for rate limiting
from email_validator import validate_email, EmailNotValidError # For checking if email addresses look valid
from flask_talisman import Talisman # For adding security-related HTTP headers


# --- 2. Load Configuration ---
# Load settings from the .env file (important for keeping secrets safe)
print("Loading environment variables...")
load_dotenv()
print("Environment variables loaded (if .env file exists).")

# --- 3. Initialize Flask App ---
# This creates the main web application object.
print("Initializing Flask application...")
app = Flask(__name__,
            template_folder="templates",  # Tells Flask where your HTML files are
            static_folder="static")       # Tells Flask where your CSS, JS, images are

# --- 4. Configure Application Settings ---

# Secret Key: Needed for session security, flashing messages, etc. VERY IMPORTANT.
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    # If no secret key is set, the app can't run securely.
    print("❌ ERROR: FLASK_SECRET_KEY environment variable is not set. Generate one (e.g., python -c 'import secrets; print(secrets.token_hex(24))') and add it to your .env file.")
    raise SystemExit("FLASK_SECRET_KEY is not set. Exiting.")

# Max File Upload Size: Limit the total size of incoming requests (including files).
# Default is 5 MB, adjust MAX_FILE_SIZE_MB in .env if needed.
MAX_FILE_SIZE_MB_STR = os.getenv("MAX_FILE_SIZE_MB", "5")
try:
    app.config["MAX_CONTENT_LENGTH"] = int(MAX_FILE_SIZE_MB_STR) * 1024 * 1024
    MAX_FILE_SIZE_BYTES = app.config["MAX_CONTENT_LENGTH"]
    print(f"Max request/file size set to: {MAX_FILE_SIZE_MB_STR} MB")
except ValueError:
    print(f"⚠️ WARNING: Invalid MAX_FILE_SIZE_MB value '{MAX_FILE_SIZE_MB_STR}'. Defaulting to 5 MB.")
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
    MAX_FILE_SIZE_BYTES = app.config["MAX_CONTENT_LENGTH"]

# --- 5. Setup Security Middleware ---

# Security Headers (Flask-Talisman): Adds headers like CSP to protect against XSS etc.
print("Configuring security headers (Talisman)...")
# Content Security Policy (CSP): Defines where resources (scripts, styles) can be loaded from.
# Needs careful adjustment based on CAPTCHA provider, external scripts, etc.
csp = {
    'default-src': '\'self\'', # Default: only allow resources from our own domain
    'script-src': [
        '\'self\'',
        'https://js.stripe.com', # Allow Stripe's JavaScript
        # !!! ADD YOUR CAPTCHA PROVIDER'S JS DOMAINS HERE !!!
        # e.g., 'https://js.hcaptcha.com', 'https://*.hcaptcha.com'
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'', # Allow inline styles (used in some templates, try to remove if possible)
        'https://fonts.googleapis.com', # Allow Google Fonts if used in CSS
         # !!! ADD YOUR CAPTCHA PROVIDER'S CSS DOMAINS HERE !!!
         # e.g., 'https://*.hcaptcha.com'
    ],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'], # Allow Google Fonts source
    'img-src': ['\'self\'', 'data:'], # Allow images from own domain and inline 'data:' images
    'frame-src': [
        '\'self\'',
        'https://js.stripe.com',      # Allow Stripe frames
        'https://hooks.stripe.com',   # Allow Stripe webhook simulation frames
        # !!! ADD YOUR CAPTCHA PROVIDER'S FRAME DOMAINS HERE !!!
        # e.g., 'https://*.hcaptcha.com'
    ],
    'connect-src': [
        '\'self\'',
        'https://api.stripe.com', # Allow connections to Stripe API
        # !!! ADD YOUR CAPTCHA PROVIDER'S API DOMAINS HERE !!!
        # e.g., 'https://api.hcaptcha.com', 'https://*.hcaptcha.com'
    ],
}
# Apply Talisman with the CSP settings
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'] # Optional: Helps with inline scripts
)
print("Talisman security headers configured.")

# Rate Limiting (Flask-Limiter): Prevents users from making too many requests too quickly.
print("Configuring rate limiting (Flask-Limiter)...")
# Use Redis for storage if available (essential for production with multiple workers)
redis_url_for_limiter = os.getenv("REDIS_URL")
if not redis_url_for_limiter:
     # Fallback to in-memory storage for local testing ONLY if REDIS_URL not set
     print("⚠️ WARNING: REDIS_URL not set. Flask-Limiter falling back to 'memory://'. This is NOT suitable for production with Gunicorn.")
     redis_url_for_limiter = "memory://limited" # Use different memory store than main redis temp data

limiter = Limiter(
    get_remote_address, # Identify users by their IP address for limiting
    app=app,
    default_limits=["200 per day", "50 per hour", "10 per minute"], # General limits
    storage_uri=redis_url_for_limiter, # Where to store rate limit counts (Redis preferred)
    strategy="fixed-window" # How rate limiting window is calculated
)
print("Rate limiting configured.")

# --- 6. Configure External Services ---

# Stripe Configuration
print("Configuring Stripe...")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
stripe_publishable_key = os.getenv("STRIPE_PUBLISHABLE_KEY")
stripe_webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
if not all([stripe.api_key, stripe_publishable_key, stripe_webhook_secret]):
     # App cannot process payments without these keys.
     print("❌ ERROR: Stripe environment variables (STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET) are not fully set in .env file.")
     raise SystemExit("Stripe configuration incomplete. Exiting.")
print("Stripe configured.")

# Redis Configuration (Used for storing email details temporarily between form submission and payment confirmation)
print("Configuring Redis connection...")
redis_url = os.getenv("REDIS_URL")
if not redis_url:
    # Redis is essential for the payment flow reliability.
    print("❌ ERROR: REDIS_URL environment variable is not set in .env file. Cannot store temporary data reliably.")
    raise SystemExit("REDIS_URL is not set. Exiting.")
try:
    # Connect to Redis. decode_responses=True makes it return strings instead of bytes.
    redis_client = redis.from_url(redis_url, decode_responses=True)
    redis_client.ping() # Test if the connection works
    print(f"✅ Successfully connected to Redis at {redis_url.split('@')[-1] if '@' in redis_url else redis_url}.") # Avoid logging password
except redis.exceptions.ConnectionError as e:
    print(f"❌ ERROR: Failed to connect to Redis at {redis_url.split('@')[-1] if '@' in redis_url else redis_url}: {e}. Check REDIS_URL.")
    raise SystemExit("Redis connection failed. Exiting.")

# Transactional Email Service (TES) Configuration
print("Configuring Transactional Email Service (TES)...")
# !!! IMPORTANT: Replace placeholders below or set in .env file !!!
# Get these from your TES provider (SendGrid, Mailgun, etc.)
TES_API_KEY = os.getenv("TES_API_KEY") # e.g., SENDGRID_API_KEY
# Example for SendGrid, change if using Mailgun etc.
TES_API_ENDPOINT = os.getenv("TES_API_ENDPOINT", "https://api.sendgrid.com/v3/mail/send")
# This *MUST* be an email address you have verified with your TES provider.
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_NAME = os.getenv("SENDER_NAME", "Phantom Mail") # Name shown in the 'From' field

if not all([TES_API_KEY, SENDER_EMAIL]):
    # Cannot send emails without these.
    print("❌ ERROR: Required Email Service environment variables (TES_API_KEY, SENDER_EMAIL) are not set in .env file.")
    raise SystemExit("Email service configuration incomplete. Exiting.")
print(f"TES configured to send from '{SENDER_NAME} <{SENDER_EMAIL}>' via endpoint.")

# --- 7. Define Constants and Configuration Variables ---

# Allowed File Types (Customize as needed)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'}
# How long email data waits in Redis for payment confirmation (e.g., 30 minutes)
TEMP_DATA_TTL = timedelta(minutes=int(os.getenv("TEMP_DATA_TTL_MINUTES", 30)))

# Basic Content Scanning Keywords (!!! ENHANCE THIS SIGNIFICANTLY !!!)
FORBIDDEN_KEYWORDS = [
    'viagra', 'casino', 'loan', 'verify your account', 'urgent action required',
    'inheritance', 'lottery', 'free money', 'make money fast', 'nigerian prince'
]
print(f"Basic content scanning configured with {len(FORBIDDEN_KEYWORDS)} keywords.")

# --- 8. Helper Functions ---
# Reusable pieces of code used in different routes.

def is_allowed_file(filename):
    """Checks if the file extension is in the ALLOWED_EXTENSIONS set."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scan_content(text):
    """
    Performs basic content scanning.
    !!! THIS IS A VERY BASIC PLACEHOLDER - REPLACE WITH A ROBUST SOLUTION !!!
    Consider using external APIs for spam filtering and URL safety checks.
    """
    if not text: # Handle empty text case
        return {'safe': True, 'reason': None}

    text_lower = text.lower()
    for keyword in FORBIDDEN_KEYWORDS:
        if keyword in text_lower:
            app.logger.warning(f"Content scan failed due to keyword: '{keyword}'")
            return {'safe': False, 'reason': f'Message contains potentially problematic content ("{keyword}").'}

    # --- Placeholder for URL Scanning ---
    # import re
    # urls = re.findall(r'(https?://\S+)', text)
    # if urls:
    #     # Call a URL scanning API (e.g., Google Safe Browsing) for each URL
    #     # if any url is malicious:
    #     #    app.logger.warning(f"Content scan failed due to malicious URL found.")
    #     #    return {'safe': False, 'reason': 'Message contains potentially unsafe links.'}
    # --- End Placeholder ---

    return {'safe': True, 'reason': None}

def validate_and_sanitize_input(data, files):
    """
    Validates form data (emails, text) and file uploads.
    Sanitizes text input to prevent cross-site scripting (XSS).
    Checks file types and sizes.
    Returns two values:
        1. validated_data (dictionary with clean data, including base64 encoded files)
        2. errors (dictionary of validation errors, or empty if valid)
    """
    errors = {}
    validated_data = {}
    # Store files base64 encoded, ready for JSON storage in Redis
    validated_files_b64 = []

    # --- Validate Recipient Email ---
    recipient = data.get("to_email", "").strip()
    if not recipient:
        errors['to_email'] = "Recipient email is required."
    else:
        try:
            # Use email_validator library for basic checks
            valid = validate_email(recipient, check_deliverability=False) # Deliverability check is slow/unreliable
            validated_data['recipient'] = valid.normalized # Use normalized version
        except EmailNotValidError as e:
            errors['to_email'] = f"Invalid recipient email format: {e}"

    # --- Validate 'From Email' (used for Reply-To) ---
    reply_to = data.get("from_email", "").strip()
    if not reply_to:
        errors['from_email'] = "'From Email' (for Reply-To) is required."
    else:
        try:
            valid_reply_to = validate_email(reply_to, check_deliverability=False)
            validated_data['reply_to'] = valid_reply_to.normalized
        except EmailNotValidError as e:
            errors['from_email'] = f"Invalid 'From Email' format: {e}"

    # --- Validate and Sanitize 'From Name' ---
    # Use bleach to remove any potentially harmful HTML/JS, limit length
    from_name_raw = data.get("from_name", "").strip()
    if not from_name_raw:
        errors['from_name'] = "Sender Name is required."
    else:
        validated_data['from_name'] = bleach.clean(from_name_raw, tags=[], attributes={}, strip=True)[:100] # Remove all tags, limit length

    # --- Validate and Sanitize Subject ---
    subject_raw = data.get("subject", "").strip()
    if not subject_raw:
        errors['subject'] = "Subject is required."
    else:
        validated_data['subject'] = bleach.clean(subject_raw, tags=[], attributes={}, strip=True)[:200] # Remove all tags, limit length

    # --- Validate and Sanitize Message Body ---
    message_raw = data.get("message", "") # Don't strip leading/trailing whitespace yet
    if not message_raw.strip(): # Check if empty after stripping
        errors['message'] = "Message body is required."
    else:
        # Allow only a very basic set of safe HTML tags for formatting
        allowed_tags = {'p', 'br', 'b', 'strong', 'i', 'em', 'ul', 'ol', 'li', 'blockquote', 'a'}
        allowed_attrs = {'a': ['href', 'title']} # Allow links with href and title
        # Clean the HTML, remove disallowed tags/attributes, limit length
        validated_data['message'] = bleach.clean(message_raw, tags=allowed_tags, attributes=allowed_attrs, strip=True)[:10000] # Limit length

    # --- Validate Files ---
    total_file_size = 0
    # Check files attached to the form (e.g., 'file1', 'file2')
    for key in files:
        file = files.get(key)
        if file and file.filename: # Check if a file was actually uploaded
            if is_allowed_file(file.filename):
                # Make the filename safe for storage/processing
                filename = secure_filename(file.filename)
                try:
                    # Read the entire file content into memory
                    # This is limited by app.config["MAX_CONTENT_LENGTH"]
                    content_bytes = file.read()
                    filesize = len(content_bytes)
                    total_file_size += filesize

                    # Check individual file size (redundant if MAX_CONTENT_LENGTH works, but good defense)
                    if filesize > MAX_FILE_SIZE_BYTES:
                         errors.setdefault('files', []).append(f"File '{filename}' is too large (max {MAX_FILE_SIZE_BYTES // (1024*1024)} MB).")
                    # Check total size accumulated so far
                    elif total_file_size > MAX_FILE_SIZE_BYTES:
                         errors.setdefault('files', []).append(f"Total file size exceeds limit ({MAX_FILE_SIZE_BYTES // (1024*1024)} MB).")
                         break # Stop processing files if total limit exceeded
                    else:
                        # If valid size, encode content in Base64 for storage in Redis (as JSON doesn't handle raw bytes)
                        validated_files_b64.append({
                            'filename': filename,
                            'content_b64': base64.b64encode(content_bytes).decode('utf-8'), # Encode bytes to base64 string
                            'mimetype': file.mimetype or 'application/octet-stream' # Get file type or default
                        })
                except RequestEntityTooLarge:
                     # This error is caught by Flask if the *entire request* is too large
                     errors.setdefault('files', []).append("Upload failed: Total size exceeds server limit.")
                     # No need to check more files if the request was already rejected
                     break
                except Exception as e:
                     app.logger.error(f"Error reading uploaded file '{filename}': {e}")
                     errors.setdefault('files', []).append(f"Error processing file '{filename}'.")
            else:
                # File type (extension) is not allowed
                errors.setdefault('files', []).append(f"File type not allowed for '{file.filename}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    validated_data['files_b64'] = validated_files_b64 # Add the list of processed files

    # --- Perform Basic Content Scan (only if no other errors found yet) ---
    if not errors:
        # Combine subject and message for scanning
        full_content_for_scan = validated_data.get('subject', '') + " " + validated_data.get('message', '')
        scan_results = scan_content(full_content_for_scan)
        if not scan_results['safe']:
            errors['content_scan'] = scan_results['reason'] # Add scan failure reason as an error

    # Return the validated data and any errors found
    return validated_data, errors


def send_email_via_tes(email_data):
    """
    Sends the email using your chosen Transactional Email Service (TES) API.
    Expects email_data dictionary containing validated fields like
    'recipient', 'subject', 'message', 'reply_to', 'from_name',
    and 'files_b64' (list of file dictionaries).

    !!! Needs customization based on your TES provider (SendGrid, Mailgun, etc.) !!!
    """
    app.logger.info(f"Attempting to send email via TES to: {email_data.get('recipient')}")

    # --- SendGrid API Example ---
    # (Replace this section if using Mailgun, AWS SES, etc.)
    headers = {
        "Authorization": f"Bearer {TES_API_KEY}", # Use your SendGrid API Key
        "Content-Type": "application/json"
    }

    # Construct the payload (data) for the SendGrid API
    payload = {
        "personalizations": [{"to": [{"email": email_data['recipient']}]}],
        "from": {"email": SENDER_EMAIL, "name": email_data.get('from_name', SENDER_NAME)}, # Use configured sender
        "reply_to": {"email": email_data.get('reply_to', SENDER_EMAIL)}, # Set the user's desired Reply-To
        "subject": email_data['subject'],
        "content": [{"type": "text/html", "value": email_data['message']}] # Send as HTML email
    }

    # Add attachments if they exist in the data
    if email_data.get('files_b64'):
        payload['attachments'] = []
        for file_info in email_data['files_b64']:
             try:
                 # SendGrid expects base64 content directly
                 payload['attachments'].append({
                    'content': file_info['content_b64'], # Already base64 encoded
                    'filename': file_info['filename'],
                    'type': file_info['mimetype'],
                    'disposition': 'attachment' # Mark as attachment
                })
             except Exception as e:
                 app.logger.error(f"Error processing attachment {file_info.get('filename')} for TES payload: {e}")
                 # Optional: Decide whether to skip the attachment or fail the entire send. Skipping is safer.
                 pass # Skip this potentially problematic attachment

    # --- End of SendGrid Specific Section ---

    # Make the API request to the TES provider
    try:
        response = requests.post(
            TES_API_ENDPOINT,          # The URL of the TES API (e.g., SendGrid's)
            headers=headers,           # API key and content type
            json=payload,              # The email data in JSON format
            timeout=20                 # Set a timeout (e.g., 20 seconds) to prevent hanging
        )
        # Raise an error if the API returned a failure status (4xx or 5xx)
        response.raise_for_status()

        # If successful (status 2xx), log it
        app.logger.info(f"Email sent successfully via TES to: {email_data['recipient']}. Status: {response.status_code}")
        return True, "Email sent successfully."

    except requests.exceptions.HTTPError as e:
         # Handle errors returned by the TES API (e.g., bad request, authentication error)
         app.logger.error(f"TES API HTTP Error sending to {email_data.get('recipient')}: {e.response.status_code} - {e.response.text}")
         # Create a user-friendly error message
         error_msg = f"Email provider rejected the request ({e.response.status_code})."
         if 400 <= e.response.status_code < 500:
              # Try to get more specific error from response (depends on TES provider)
              try:
                  err_details = e.response.json().get("errors", [])
                  if err_details: error_msg = f"Email provider error: {err_details[0].get('message', 'Invalid request')}"
              except json.JSONDecodeError: pass # Ignore if response is not JSON
         elif e.response.status_code in (401, 403):
              error_msg = "Email provider authentication failed. Service configuration issue." # Likely bad API key
         else: # 5xx server errors from TES
              error_msg = "Temporary error with the email provider. Please try again later."
         return False, error_msg
    except requests.exceptions.RequestException as e:
        # Handle network errors (e.g., could not connect to TES API)
        app.logger.error(f"TES Network/Request Error sending to {email_data.get('recipient')}: {e}")
        return False, f"Network error contacting email provider."
    except Exception as e:
        # Handle any other unexpected errors during sending
        app.logger.error(f"Unexpected error in send_email_via_tes sending to {email_data.get('recipient')}: {e}", exc_info=True) # Log full traceback
        return False, "An unexpected server error occurred while sending the email."


# --- 9. Define Flask Routes (URL Handlers) ---

@app.route("/")
def index():
    """Renders the main landing/home page."""
    app.logger.debug("Serving index route ('/')")
    # Assumes your main landing page HTML is named home_page.html
    try:
        return render_template("home_page.html")
    except Exception as e:
        # Fallback or error if template is missing
        app.logger.error(f"Could not render home_page.html: {e}")
        # You might want a very basic fallback HTML string here
        return "Error: Could not load homepage.", 500

@app.route("/mailer")
def mailer_form():
    """Displays the email composition form page."""
    app.logger.debug("Serving mailer route ('/mailer')")
    # Ensure you have 'templates/mailer_page.html'
    # Pass the Stripe publishable key to the template if needed by client-side JS (though we use redirect now)
    # Pass CAPTCHA site key to the template
    # hcaptcha_site_key = os.getenv("HCAPTCHA_SITE_KEY") # Get from .env
    try:
        return render_template(
            "mailer_page.html",
            stripe_key=stripe_publishable_key
            # hcaptcha_site_key=hcaptcha_site_key # Pass to template
            )
    except Exception as e:
        app.logger.error(f"Could not render mailer_page.html: {e}")
        return "Error: Could not load mailer form.", 500

@app.route("/start-payment", methods=["POST"])
@limiter.limit("5 per minute") # Apply rate limiting to this route
def start_payment():
    """
    Handles the submission from the mailer form.
    1. Validates form inputs and files.
    2. Performs CAPTCHA check (!!! NEEDS IMPLEMENTATION !!!).
    3. Performs basic content scan.
    4. If valid, stores data temporarily in Redis.
    5. Creates a Stripe Checkout session and redirects the user to Stripe for payment.
    """
    app.logger.info(f"Received POST request on /start-payment from {request.remote_addr}")

    # --- !!! CAPTCHA Verification Placeholder !!! ---
    # captcha_response = request.form.get('h-captcha-response') # Or 'g-recaptcha-response'
    # captcha_secret = os.getenv("HCAPTCHA_SECRET_KEY")
    # if not captcha_response or not captcha_secret:
    #      flash("CAPTCHA challenge missing or server not configured.", "error")
    #      app.logger.warning("CAPTCHA response or secret key missing.")
    #      return redirect(url_for('mailer_form'))
    #
    # try:
    #      # Make POST request to hCaptcha siteverify endpoint
    #      verify_response = requests.post(
    #          "https://api.hcaptcha.com/siteverify",
    #          data={'response': captcha_response, 'secret': captcha_secret},
    #          timeout=10
    #      )
    #      verify_response.raise_for_status()
    #      verification_data = verify_response.json()
    #      if not verification_data.get('success'):
    #          app.logger.warning(f"CAPTCHA verification failed: {verification_data.get('error-codes')}")
    #          flash("CAPTCHA verification failed. Please try again.", "error")
    #          return redirect(url_for('mailer_form'))
    #      else:
    #          app.logger.info("CAPTCHA verification successful.")
    # except requests.exceptions.RequestException as e:
    #      app.logger.error(f"CAPTCHA verification request failed: {e}")
    #      flash("Could not verify CAPTCHA due to a network issue. Please try again later.", "error")
    #      return redirect(url_for('mailer_form'))
    # --- END CAPTCHA Placeholder ---


    # Validate all inputs (email fields, subject, message, files)
    validated_data, errors = validate_and_sanitize_input(request.form, request.files)

    # If there are any validation errors...
    if errors:
        app.logger.warning(f"Validation errors for /start-payment: {errors}")
        # 'Flash' the error messages to be displayed on the redirected page
        for field, msg_list in errors.items():
             # Handle cases where error value is a list (files) or single string
             msgs = msg_list if isinstance(msg_list, list) else [msg_list]
             for msg in msgs:
                flash(f"{msg}", "error") # Display user-friendly error
        # Redirect back to the mailer form so the user can fix errors
        return redirect(url_for('mailer_form'))

    # --- If validation passes ---
    app.logger.info("Input validation successful.")

    # Generate a unique ID for this specific transaction attempt
    transaction_id = str(uuid.uuid4())
    # Create the key under which data will be stored in Redis
    redis_key = f"phantom_email_tx:{transaction_id}"

    try:
        # Store the validated data (which includes base64 encoded files) in Redis
        # Use json.dumps to convert the Python dictionary to a JSON string for storage
        # Use setex to set the key with an expiration time (TEMP_DATA_TTL)
        redis_client.setex(redis_key, TEMP_DATA_TTL, json.dumps(validated_data))
        app.logger.info(f"Stored email data in Redis for TX ID: {transaction_id} with TTL: {TEMP_DATA_TTL}")
    except redis.exceptions.RedisError as e:
        # Handle errors connecting to or writing to Redis
        app.logger.error(f"Redis SETEX Error for TX ID {transaction_id}: {e}")
        flash("Server error storing temporary data. Please try again later.", "error")
        return redirect(url_for('mailer_form'))
    except Exception as e:
        # Catch other potential errors during Redis operation
        app.logger.error(f"Unexpected error storing data in Redis for TX ID {transaction_id}: {e}", exc_info=True)
        flash("An unexpected server error occurred. Please try again.", "error")
        return redirect(url_for('mailer_form'))

    # --- Create Stripe Checkout Session ---
    # This session represents the payment attempt.
    app.logger.info(f"Creating Stripe Checkout session for TX ID: {transaction_id}")
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"], # Allow card payments
            line_items=[{                  # Define what the user is paying for
                "price_data": {
                    "currency": "usd",         # Currency code (e.g., 'usd', 'eur')
                    "unit_amount": 300,        # Amount in cents (e.g., 300 = $3.00) !!! ADJUST PRICE HERE !!!
                    "product_data": {
                        "name": "Phantom Anonymous Email Service" # Name shown on Stripe page
                    }
                },
                "quantity": 1,             # Usually just one item
            }],
            mode="payment",                # One-time payment mode
            # URL to redirect to on successful *redirect* from Stripe (payment confirmed via webhook)
            success_url=url_for('thankyou', _external=True),
            # URL to redirect to if the user cancels payment on the Stripe page
            cancel_url=url_for('mailer_form', _external=True),
            # ** IMPORTANT: Link this Stripe session to our transaction ID stored in Redis **
            client_reference_id=transaction_id,
            # Optional: Expire the checkout session slightly after Redis data expires
            # expires_at=int((datetime.utcnow() + TEMP_DATA_TTL + timedelta(minutes=5)).timestamp())
        )
        # Log the successful creation of the Stripe session
        app.logger.info(f"Stripe Checkout session created: {checkout_session.id} for TX ID: {transaction_id}. Redirecting user.")
        # Redirect the user's browser to the Stripe payment page
        return redirect(checkout_session.url, code=303)

    except stripe.error.StripeError as e:
        # Handle errors from the Stripe API (e.g., invalid API key, network issues)
        app.logger.error(f"Stripe API error creating session for TX ID {transaction_id}: {e}")
        # Show a user-friendly message from Stripe if available, otherwise a generic one
        flash(f"Payment processor error: {e.user_message or 'Could not initiate payment'}", "error")
        # Clean up the data we stored in Redis since payment failed
        try: redis_client.delete(redis_key)
        except Exception as redis_err: app.logger.error(f"Failed to clean up Redis key {redis_key} after Stripe error: {redis_err}")
        return redirect(url_for('mailer_form')) # Redirect back to form
    except Exception as e:
        # Handle any other unexpected errors during Stripe session creation
        app.logger.error(f"Unexpected error creating Stripe session for TX ID {transaction_id}: {e}", exc_info=True)
        flash("An unexpected server error occurred while preparing payment.", "error")
         # Clean up Redis data
        try: redis_client.delete(redis_key)
        except Exception as redis_err: app.logger.error(f"Failed to clean up Redis key {redis_key} after unexpected error: {redis_err}")
        return redirect(url_for('mailer_form'))


@app.route("/thankyou")
def thankyou():
    """
    Displays a simple 'thank you' page after the user is redirected
    back from Stripe successfully.
    NOTE: Actual payment confirmation and email sending happen via the webhook, NOT here.
    """
    app.logger.debug("Serving thankyou route ('/thankyou')")
    # Ensure you have 'templates/thankyou.html'
    try:
        return render_template("thankyou.html")
    except Exception as e:
        app.logger.error(f"Could not render thankyou.html: {e}")
        return "Payment successful! Processing message.", 200 # Basic fallback text


@app.route("/webhook", methods=["POST"])
@limiter.limit("30 per minute") # Allow a reasonable rate for incoming webhooks
def stripe_webhook():
    """
    Handles incoming webhook events from Stripe.
    Listens specifically for 'checkout.session.completed'.
    1. Verifies the webhook signature to ensure it's genuinely from Stripe.
    2. If payment was successful ('paid'):
        a. Retrieves the corresponding email data from Redis using the transaction ID.
        b. Deletes the data from Redis immediately.
        c. Calls the function to send the email via the TES.
    3. Returns a 200 OK response to Stripe to acknowledge receipt.
    """
    payload_bytes = request.data # Get raw request body as bytes
    sig_header = request.headers.get("Stripe-Signature")
    event = None # Initialize event to None

    # Log the incoming webhook attempt
    # Avoid logging the full payload directly in production if it contains sensitive info
    # Instead, log event ID or type once verified.
    app.logger.info(f"Webhook received from {request.remote_addr}. Verifying signature...")

    # Check if signature header is present
    if not sig_header:
        app.logger.warning("Webhook request missing Stripe-Signature header.")
        abort(400) # Bad request

    # Verify the webhook signature
    try:
        event = stripe.Webhook.construct_event(
            payload_bytes, sig_header, stripe_webhook_secret
        )
        app.logger.info(f"Webhook signature verified. Event ID: {event.id}, Type: {event['type']}")
    except ValueError as e:
        # Invalid payload format
        app.logger.warning(f"Webhook error: Invalid payload. {e}")
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature - potential security issue or misconfiguration
        app.logger.error(f"Webhook signature verification failed! {e}")
        return "Invalid signature", 400
    except Exception as e:
        # Other unexpected errors during event construction
        app.logger.error(f"Webhook error during event construction: {e}", exc_info=True)
        # Use 500 to indicate internal server error
        return "Webhook error", 500

    # --- Handle the 'checkout.session.completed' event ---
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"] # The Stripe Checkout Session object
        transaction_id = session.get("client_reference_id") # Our unique ID linking to Redis data
        payment_status = session.get("payment_status")
        stripe_session_id = session.id

        app.logger.info(f"Processing '{event['type']}' for Stripe Session: {stripe_session_id}, TX ID: {transaction_id}, Payment Status: {payment_status}")

        # Check if we have the transaction ID (client_reference_id)
        if not transaction_id:
            app.logger.error(f"Webhook Error: Missing client_reference_id in completed session {stripe_session_id}")
            # Acknowledge receipt to Stripe, but log the error.
            return "Missing reference ID", 200

        # Check if the payment was successful
        if payment_status == "paid":
            app.logger.info(f"Payment successful for TX ID: {transaction_id}.")
            redis_key = f"phantom_email_tx:{transaction_id}"
            email_data_str = None
            email_data = None

            try:
                # --- Retrieve data from Redis ---
                app.logger.debug(f"Retrieving data from Redis with key: {redis_key}")
                email_data_str = redis_client.get(redis_key)

                if not email_data_str:
                    # Data might have expired, been processed already by a duplicate webhook, or never existed.
                    app.logger.warning(f"No data found in Redis for key: {redis_key} (TX ID: {transaction_id}). May have expired or already processed.")
                    # Acknowledge webhook, nothing more to do.
                    return "Data not found or expired", 200

                # --- Delete data from Redis IMMEDIATELY ---
                # This prevents accidental reprocessing if the webhook is sent again by Stripe.
                app.logger.debug(f"Deleting data from Redis for key: {redis_key}")
                delete_count = redis_client.delete(redis_key)
                if delete_count == 0:
                     # This might indicate a race condition or duplicate webhook arrived very fast.
                     app.logger.warning(f"Redis key {redis_key} was already deleted before processing could complete for TX ID {transaction_id}. Possible duplicate webhook.")
                     # Acknowledge webhook, as data was likely processed by another request.
                     return "Data already processed", 200

                # --- Process the retrieved data ---
                app.logger.debug(f"Deserializing JSON data for TX ID: {transaction_id}")
                # Convert the JSON string back into a Python dictionary
                email_data = json.loads(email_data_str)

                # --- Decode Base64 file content back to bytes ---
                # (Important: send_email_via_tes might expect bytes or base64 depending on provider)
                # SendGrid API expects base64, so no decoding needed here if using the SendGrid example.
                # If your TES needs bytes, decode here:
                # if email_data.get('files_b64'):
                #    for file_info in email_data['files_b64']:
                #        file_info['content_bytes'] = base64.b64decode(file_info['content_b64'])
                #    # Remove or keep 'content_b64' based on what send_email_via_tes needs

                # --- Send the Email ---
                app.logger.info(f"Calling send_email_via_tes for TX ID: {transaction_id}")
                success, message = send_email_via_tes(email_data)

                if success:
                    # Log success
                    app.logger.info(f"Email successfully queued/sent for TX ID: {transaction_id} (Stripe: {stripe_session_id})")
                    # Optional: Store transaction_id in another Redis set for a short time
                    # to more robustly detect duplicate webhooks if needed.
                else:
                    # Log failure details
                    app.logger.error(f"Failed to send email for TX ID: {transaction_id} (Stripe: {stripe_session_id}). Reason: {message}")
                    # !!! Consider what to do on failure:
                    # - Log it (done).
                    # - Alert an admin?
                    # - Implement a retry queue? (More complex)
                    # - Notify the user? (Difficult without storing their contact info)

            except redis.exceptions.RedisError as e:
                 app.logger.error(f"Redis error during webhook processing for TX ID {transaction_id}: {e}", exc_info=True)
                 # Signal internal error, Stripe might retry. Don't delete Redis key here? Risky.
                 return "Internal server error (Redis)", 500
            except json.JSONDecodeError as e:
                 app.logger.error(f"Failed to decode JSON data from Redis for TX ID {transaction_id}: {e}. Data: '{email_data_str[:100]}...'") # Log snippet of bad data
                 # Data is corrupt, don't retry. Acknowledge webhook.
                 return "Failed to process stored data (JSON)", 200
            except Exception as e:
                # Catch any other unexpected errors during processing
                app.logger.error(f"Unexpected error processing webhook for TX ID {transaction_id} (Stripe: {stripe_session_id}): {e}", exc_info=True)
                # Signal internal error to Stripe
                return "Internal server error during processing", 500

        else:
            # Handle other payment statuses if necessary (e.g., 'unpaid', 'no_payment_required')
            app.logger.info(f"Webhook received for session {stripe_session_id} but payment status is '{payment_status}'. No email sent.")

    else:
        # Log if we receive webhook event types we don't explicitly handle
        app.logger.debug(f"Webhook received unhandled event type: {event['type']}")

    # Return 200 OK to Stripe to acknowledge successful receipt of the webhook
    return "OK", 200

# --- Routes for Informational Pages ---

@app.route("/about")
def about():
    """Renders the About page."""
    app.logger.debug("Serving about route ('/about')")
    try:
        # Render 'templates/about.html' (or 'about_with_qr.html' if preferred)
        return render_template("about.html")
    except Exception as e:
        app.logger.error(f"Error rendering about page: {e}")
        abort(404) # Page not found

@app.route("/terms")
def terms():
    """Renders the Terms of Use page."""
    app.logger.debug("Serving terms route ('/terms')")
    try:
        # Render 'templates/terms.html'
        return render_template("terms.html")
    except Exception as e:
        app.logger.error(f"Error rendering terms page: {e}")
        abort(404) # Page not found

@app.route("/privacy")
def privacy():
    """Renders the Privacy Policy / No Receipts page."""
    app.logger.debug("Serving privacy route ('/privacy')")
    try:
        # Render 'templates/privacy.html'
        return render_template("privacy.html")
    except Exception as e:
        app.logger.error(f"Error rendering privacy page: {e}")
        abort(404) # Page not found

# --- 10. Define Error Handlers ---
# Custom pages or responses for common HTTP errors.

@app.errorhandler(404)
@app.errorhandler(NotFound) # Catch Flask/Werkzeug's specific 404 exception
def not_found_error(error):
    """Renders a custom 404 Not Found page."""
    app.logger.warning(f"404 Not Found error for URL: {request.url}")
    # Ensure you have 'templates/404.html'
    try:
        return render_template('404.html'), 404
    except:
        return "404 Not Found", 404 # Basic text fallback

@app.errorhandler(500)
def internal_error(error):
    """Renders a custom 500 Internal Server Error page."""
    # Log the full error details on the server for debugging
    # exc_info=True includes the traceback
    app.logger.error(f"500 Internal Server Error for URL: {request.url}", exc_info=True)
    # Ensure you have 'templates/500.html'
    try:
        return render_template('500.html'), 500
    except:
        return "500 Internal Server Error", 500 # Basic text fallback

@app.errorhandler(429) # Rate limit exceeded
def ratelimit_handler(e):
    """Handles errors when rate limits are hit."""
    # Log the rate limit event
    app.logger.warning(f"Rate limit exceeded: {e.description} from {request.remote_addr} for URL: {request.url}")
    # Return a JSON response indicating the error
    return jsonify(error=f"Rate limit exceeded: {e.description}"), 429

@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(e):
    """Handles errors when uploaded file/request exceeds size limits."""
    app.logger.warning(f"Request entity too large from {request.remote_addr} for URL: {request.url}")
    # Flash a message to the user and redirect back to the form
    flash(f"Upload failed: Content size exceeds the server limit ({app.config['MAX_CONTENT_LENGTH'] // (1024*1024)} MB).", "error")
    return redirect(url_for('mailer_form'))


# --- 11. Setup Logging ---
# Configure how the application logs information and errors.

# Use StreamHandler to output logs to console (which Render captures)
stream_handler = logging.StreamHandler()
# Set the format for log messages
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler.setFormatter(formatter)

# Remove default Flask handlers if they exist, to avoid duplicate logs
# This check might be needed depending on Flask version
if app.logger.hasHandlers():
    app.logger.handlers.clear()

# Add our configured handler
app.logger.addHandler(stream_handler)

# Set the logging level (e.g., INFO, DEBUG, WARNING)
# Use DEBUG for local development, INFO or WARNING for production
log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
app.logger.setLevel(log_level)

app.logger.info(f"Flask logger configured with level: {log_level_str}")


# --- 12. Main Execution Block ---
# This code runs only when you execute the script directly (e.g., `python phantom.py`)
# It's used for local development. Render uses Gunicorn (specified in render.yaml).

if __name__ == "__main__":
    # Get port from environment variable or default to 5001 for local dev
    port = int(os.environ.get("PORT", 5001))
    # Enable debug mode only if explicitly set (e.g., APP_ENV=development in .env)
    # WARNING: Never run with debug=True in production!
    is_debug_mode = os.getenv("APP_ENV") == 'development'
    print(f"Starting Flask development server on http://0.0.0.0:{port}/")
    print(f"Debug mode: {'ON' if is_debug_mode else 'OFF'}")
    # Run the Flask development server
    app.run(host="0.0.0.0", port=port, debug=is_debug_mode)