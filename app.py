import os
import redis
import hashlib
import requests
import uuid
import stripe
import json
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-fallback-secret'

# Redis setup
redis_url = os.environ.get('REDIS_URL')
redis_client = None
if redis_url:
    try:
        redis_client = redis.from_url(redis_url)
    except Exception as e:
        app.logger.error(f"Error connecting to Redis: {e}")
        print("Warning: Redis-dependent features will not work locally if connection fails.")
else:
    app.logger.warning("Warning: REDIS_URL not set; Redis features disabled.")

# Service configurations
MAILGUN_API_KEY        = os.environ.get('MAILGUN_API_KEY')
MAILGUN_DOMAIN         = os.environ.get('MAILGUN_DOMAIN')
STRIPE_SECRET_KEY      = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET')

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    app.logger.warning("Warning: STRIPE_SECRET_KEY not set; paid flow disabled.")


def verify_turnstile(token, remoteip=None):
    """Verify Cloudflare Turnstile token server-side."""
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not secret or not token:
        return False
    payload = {"secret": secret, "response": token}
    if remoteip:
        payload["remoteip"] = remoteip
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload
        )
        return r.ok and r.json().get("success", False)
    except Exception as e:
        app.logger.error(f"Turnstile verification error: {e}")
        return False


def allowed_file(filename):
    """Return True if the file has an allowed extension."""
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def send_email_via_mailgun(recipient, subject, body, from_name, reply_to_email, attachments=None):
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("Mailgun credentials missing; cannot send email.")
        return False
    url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    auth = ('api', MAILGUN_API_KEY)
    data = {
        "from": f"{from_name} <sender@{MAILGUN_DOMAIN}>",
        "to": [recipient],
        "subject": subject,
        "text": body,
        "h:Reply-To": reply_to_email
    }
    files = attachments or []
    try:
        resp = requests.post(url, auth=auth, data=data, files=files)
        resp.raise_for_status()
        return True
    except Exception as e:
        app.logger.error(f"Error sending via Mailgun: {e}")
        return False


# --- Basic page routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mailer')
def mailer():
    # Pass Turnstile sitekey into template
    sitekey = os.getenv("TURNSTILE_SITE_KEY")
    return render_template('mailer.html', turnstile_sitekey=sitekey)

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

    # 1. CAPTCHA validation
    token = request.form.get("cf-turnstile-response")
    client_ip = request.remote_addr
    if not verify_turnstile(token, client_ip):
        flash("CAPTCHA verification failed", "error")
        return redirect(url_for("mailer"))

    # 2. Read form fields
    fn   = request.form.get('from_name')
    fe   = request.form.get('from_email')
    te   = request.form.get('to_email')
    subj = request.form.get('subject')
    msg  = request.form.get('message')
    free = 'free_trial' in request.form

    # 3. Collect attachments
    attachments = []
    for key in ('file1', 'file2'):
        f = request.files.get(key)
        if f and allowed_file(f.filename):
            attachments.append((
                'attachment',
                (f.filename, f.stream, f.mimetype)
            ))

    # 4. Free‑trial branch
    if free:
        ip = client_ip or request.environ.get('HTTP_X_FORWARDED_FOR')
        if not ip:
            flash('IP error', 'error')
            return redirect(url_for('mailer'))
        h   = hashlib.sha256(ip.encode()).hexdigest()
        key = f"free_trial_ip:{h}"
        used = redis_client.exists(key) if redis_client else False
        if used:
            flash('Free trial limit reached', 'error')
            return redirect(url_for('mailer'))
        ok = send_email_via_mailgun(te, subj, msg, fn, fe, attachments)
        if ok:
            if redis_client:
                redis_client.setex(key, timedelta(days=1), "used")
            return redirect(url_for('thankyou'))
        flash('Send failed', 'error')
        return redirect(url_for('mailer'))

    # 5. Paid branch
    if not STRIPE_SECRET_KEY:
        flash('Payment unavailable', 'error')
        return redirect(url_for('mailer'))

    eid = str(uuid.uuid4())
    meta = {'redis_email_key': f"email:{eid}"}
    data = {"to_email": te, "subject": subj, "message": msg, "from_name": fn, "from_email": fe}
    if redis_client:
        redis_client.setex(meta['redis_email_key'], timedelta(minutes=60), json.dumps(data))

    try:
        sess = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': subj},
                    'unit_amount': 100
                },
                'quantity': 1
            }],
            mode='payment',
            success_url=url_for('thankyou', _external=True),
            cancel_url=url_for('mailer', _external=True),
            metadata=meta
        )
        return redirect(sess.url, code=303)
    except Exception as e:
        print(f"Stripe error: {e}")
        if redis_client:
            redis_client.delete(meta['redis_email_key'])
        flash('Payment error', 'error')
        return redirect(url_for('mailer'))


# --- Stripe webhook handler ---

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=False)
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        app.logger.warning("Webhook invalid payload")
        abort(400)
    except stripe.error.SignatureVerificationError:
        app.logger.warning("Webhook signature verification failed")
        abort(400)

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        key = session.get("metadata", {}).get("redis_email_key")
        if key and redis_client:
            raw = redis_client.get(key)
            if raw:
                try:
                    email_data = json.loads(raw)
                    send_email_via_mailgun(
                        email_data["to_email"],
                        email_data["subject"],
                        email_data["message"],
                        email_data["from_name"],
                        email_data["from_email"],
                        # You’ll need to store attachments in metadata if you want to resend them
                    )
                    redis_client.delete(key)
                except Exception as e:
                    app.logger.error(f"Error processing webhook: {e}")
                    abort(500)

    return ("", 200)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)