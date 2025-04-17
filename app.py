
import os
import json
import uuid
import redis
import hashlib
import requests
import stripe
import logging
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "dev-fallback-secret"

# Security headers via Talisman
csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "https://challenges.cloudflare.com"]
}
Talisman(app, content_security_policy=csp)

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute"])

# Logging config
app.logger.setLevel(logging.INFO)

# Redis setup
redis_url = os.getenv("REDIS_URL")
redis_client = None
if redis_url:
    try:
        redis_client = redis.from_url(redis_url)
    except Exception as e:
        app.logger.error(f"Redis connection error: {e}", exc_info=True)
else:
    app.logger.warning("REDIS_URL not set; Redis disabled")

# Stripe config
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    app.logger.warning("STRIPE_SECRET_KEY not set; paid flow disabled")


def verify_turnstile(token, remoteip=None):
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if not secret or not token:
        return False
    data = {"secret": secret, "response": token}
    if remoteip:
        data["remoteip"] = remoteip
    try:
        r = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data)
        return r.ok and r.json().get("success", False)
    except Exception as e:
        app.logger.error(f"Turnstile error: {e}", exc_info=True)
        return False


def allowed_file(filename):
    ALLOWED_EXT = {'txt','pdf','png','jpg','jpeg','gif'}
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT


def send_email_via_mailgun(recipient, subject, body, from_name, reply_to_email, attachments=None):
    MAILGUN_KEY = os.getenv("MAILGUN_API_KEY")
    MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN")
    if not MAILGUN_KEY or not MAILGUN_DOMAIN:
        app.logger.error("Mailgun not configured")
        return False
    url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    auth = ('api', MAILGUN_KEY)
    html_body = render_template('email.html', subject=subject, body=body, from_name=from_name)
    data = {
        "from": f"{from_name} <sender@{MAILGUN_DOMAIN}>",
        "to": [recipient],
        "subject": subject,
        "text": body,
        "html": html_body,
        "h:Reply-To": reply_to_email
    }
    files = attachments or []
    try:
        resp = requests.post(url, auth=auth, data=data, files=files)
        resp.raise_for_status()
        return True
    except Exception as e:
        app.logger.error(f"Mailgun send error: {e}", exc_info=True)
        return False


# Basic routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mailer')
def mailer():
    sitekey = os.getenv("TURNSTILE_SITE_KEY")
    return render_template('mailer.html', turnstile_sitekey=sitekey)

# Health check
@app.route('/healthz')
def healthz():
    try:
        if redis_client:
            redis_client.ping()
        else:
            return ('',503)
    except Exception as e:
        app.logger.error(f"Health error: {e}", exc_info=True)
        return ('',503)
    return ('',200)

# Payment & email route
@app.route('/start-payment', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt  # CSRF token required in form
def start_payment():
    # CSRFProtect will validate token automatically
    token = request.form.get("cf-turnstile-response")
    if not verify_turnstile(token, request.remote_addr):
        flash("CAPTCHA failed","error")
        return redirect(url_for('mailer'))

    fn = request.form.get('from_name','').strip()
    fe = request.form.get('from_email','').strip()
    te = request.form.get('to_email','').strip()
    subj = request.form.get('subject','').strip()
    msg = request.form.get('message','').strip()

    # Input validation
    if not (1 <= len(subj) <= 100):
        flash("Subject length must be 1-100 chars","error"); return redirect(url_for('mailer'))
    if not (1 <= len(msg) <= 2000):
        flash("Message length must be 1-2000 chars","error"); return redirect(url_for('mailer'))

    attachments = []
    for key in ('file1','file2'):
        f = request.files.get(key)
        if f and allowed_file(f.filename):
            attachments.append(('attachment',(f.filename,f.stream,f.mimetype)))

    free = 'free_trial' in request.form
    if free:
        ip = request.remote_addr
        h = hashlib.sha256(ip.encode()).hexdigest()
        key = f"free_trial_ip:{h}"
        if redis_client and redis_client.exists(key):
            flash("Free trial used","error"); return redirect(url_for('mailer'))
        if send_email_via_mailgun(te,subj,msg,fn,fe,attachments):
            if redis_client:
                redis_client.setex(key, timedelta(days=1),"used")
            return redirect(url_for('thankyou'))
        flash("Send failed","error"); return redirect(url_for('mailer'))

    if not STRIPE_SECRET_KEY:
        flash("Payment unavailable","error"); return redirect(url_for('mailer'))

    eid = str(uuid.uuid4())
    data_key = f"email:{eid}"
    payload = {"to_email":te,"subject":subj,"message":msg,"from_name":fn,"from_email":fe}
    if redis_client: redis_client.setex(data_key, timedelta(hours=36), json.dumps(payload))
    try:
        sess = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price_data':{'currency':'usd','product_data':{'name':subj},'unit_amount':100},'quantity':1}],
            mode='payment',
            success_url=url_for('thankyou',_external=True),
            cancel_url=url_for('mailer',_external=True),
            metadata={'redis_email_key':data_key}
        )
        return redirect(sess.url, code=303)
    except Exception as e:
        app.logger.error(f"Stripe session error: {e}", exc_info=True)
        if redis_client: redis_client.delete(data_key)
        flash("Payment error","error"); return redirect(url_for('mailer'))

# Webhook handler
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        app.logger.warning(f"Webhook verify failed: {e}")
        abort(400)
    if event['type']=="checkout.session.completed":
        sess = event['data']['object']
        key = sess.get('metadata',{}).get('redis_email_key')
        if key and redis_client:
            raw = redis_client.get(key)
            if raw:
                try:
                    payload = json.loads(raw)
                    send_email_via_mailgun(payload['to_email'],payload['subject'],payload['message'],payload['from_name'],payload['from_email'])
                    redis_client.delete(key)
                except Exception as e:
                    app.logger.error(f"Webhook handler error: {e}", exc_info=True)
                    abort(500)
    return ('',200)

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {e}", exc_info=True)
    flash("Internal error","error")
    return redirect(url_for('mailer')), 500

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

if __name__=='__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT',5000)), debug=os.getenv('FLASK_DEBUG','false')=='true')
