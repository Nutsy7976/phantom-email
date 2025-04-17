import os
import redis
import hashlib
import requests
import uuid
import stripe
import json
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')

# Redis setup
redis_url = os.environ.get('REDIS_URL')
redis_client = None
if redis_url:
    try:
        redis_client = redis.from_url(redis_url)
    except redis.RedisError as e:
        print(f"Error connecting to Redis: {e}")
        print("Warning: Redis-dependent features will not work locally if connection fails.")
else:
    print("Warning: REDIS_URL not set; Redis features disabled.")

# Service configurations
MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY')
MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')  # used in frontend if needed
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    print("Warning: STRIPE_SECRET_KEY environment variable not set. Payment processing will fail.")

def send_email_via_mailgun(recipient, subject, body, from_name, reply_to_email, attachments=None):
    """Sends an email using the Mailgun API."""
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("Error: Mailgun API Key or Domain not configured in environment variables.")
        return False
    mailgun_url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    auth = ('api', MAILGUN_API_KEY)
    sender_email = f"sender@{MAILGUN_DOMAIN}"
    from_header = f"{from_name} <{sender_email}>"
    data = {
        "from": from_header,
        "to": [recipient],
        "subject": subject,
        "text": body,
        "h:Reply-To": reply_to_email
    }
    files = attachments if attachments else []
    try:
        response = requests.post(mailgun_url, auth=auth, data=data, files=files)
        response.raise_for_status()
        print(f"Mailgun API response status: {response.status_code}")
        print(f"Mailgun API response body: {response.text}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending email via Mailgun: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Mailgun Response (Error): {e.response.text}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during email sending: {e}")
        return False

# --- Page routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mailer')
def mailer():
    return render_template('mailer.html')

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

# --- Payment and email submission ---
@app.route('/start-payment', methods=['POST'])
def start_payment():
    if request.method != 'POST':
        return redirect(url_for('mailer'))

    from_name = request.form.get('from_name')
    from_email = request.form.get('from_email')
    to_email = request.form.get('to_email')
    subject = request.form.get('subject')
    message = request.form.get('message')
    is_free_trial = 'free_trial' in request.form

    # Free trial flow
    if is_free_trial:
        ip_address = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR')
        if not ip_address:
            flash('Could not determine IP for free trial limit.', 'error')
            return redirect(url_for('mailer'))

        ip_hash = hashlib.sha256(ip_address.encode('utf-8')).hexdigest()
        free_key = f"free_trial_ip:{ip_hash}"
        try:
            if redis_client and redis_client.exists(free_key):
                flash('Free trial limit reached for your IP. Try again tomorrow.', 'error')
                return redirect(url_for('mailer'))
        except redis.RedisError:
            flash('Could not check free trial status. Please try again.', 'error')
            return redirect(url_for('mailer'))

        # Send the email
        sent = send_email_via_mailgun(to_email, subject, message, from_name, from_email)
        if sent:
            try:
                if redis_client:
                    redis_client.setex(free_key, timedelta(days=1), "used")
            except redis.RedisError as e:
                print(f"Redis Error recording free trial: {e}")
            return redirect(url_for('thankyou'))
        else:
            flash('Error sending free email. Please try again.', 'error')
            return redirect(url_for('mailer'))

    # Paid flow
    if not STRIPE_SECRET_KEY:
        flash('Payment system error. Cannot process payment.', 'error')
        return redirect(url_for('mailer'))

    # Save email details
    email_id = str(uuid.uuid4())
    email_data = {
        "to_email": to_email,
        "subject": subject,
        "message": message,
        "from_name": from_name,
        "from_email": from_email
    }
    data_key = f"email:{email_id}"
    try:
        if redis_client:
            redis_client.setex(data_key, timedelta(minutes=60), json.dumps(email_data))
    except redis.RedisError as e:
        flash('Payment system error. Could not save email details.', 'error')
        return redirect(url_for('mailer'))

    # Create Stripe Checkout session
    try:
        success_url = url_for('thankyou', _external=True)
        cancel_url = url_for('mailer', _external=True)
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': subject},
                    'unit_amount': 100
                },
                'quantity': 1
            }],
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={'redis_email_key': data_key}
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        print(f"Error creating Stripe session: {e}")
        flash('Payment system error. Please try again.', 'error')
        # Clean up Redis key if set
        if redis_client:
            try:
                redis_client.delete(data_key)
            except Exception:
                pass
        return redirect(url_for('mailer'))

# Stub for webhook integration (to be implemented)
# @app.route('/stripe-webhook', methods=['POST'])
# def stripe_webhook():
#     pass

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
