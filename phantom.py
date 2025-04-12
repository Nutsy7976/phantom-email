from flask_cors import CORS
from flask import Flask, request, redirect, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

# Configuration
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Stripe Setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route("/")
def index():
    return render_template("home_page.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/create-checkout-session", methods=["POST"])
@limiter.limit("5 per minute")
def create_checkout_session():
    data = request.form

    # Abuse protection: CAPTCHA + honeypot + rate limiter
    if not validate_captcha(data.get("cf-turnstile-response", ""), request.remote_addr):
        return "CAPTCHA verification failed", 403
    if data.get("website") != "":
        return "Bot detected", 403
    name = data.get("from_name")
    sender = data.get("from_email")
    recipient = data.get("to_email")
    message = data.get("message")

    files = [request.files.get("file1"), request.files.get("file2")]
    saved_files = []

    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)
            saved_files.append(path)

    # Free Trial Bypass
    if name.strip().lower() == "phantomfree":
        try:
            send_email(
                sender="send@phantommailer.net",
                recipient=recipient,
                subject="Anonymous Message (Free Trial)",
                body=message,
                attachments=saved_files,
                reply_to=sender
            )
            email_logs.append(f"Free trial used - delivered to {recipient}")
            return redirect("/thankyou")
        except Exception as e:
            return f"Bypass send failed: {str(e)}", 500

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 300,
                    "product_data": {"name": "Anonymous Email"}
                },
                "quantity": 1,
            }],
            mode="payment",
metadata={
                "from_name": name,
                "from_email": sender,
                "to_email": recipient,
                "message": message,
                "attachments": ",".join(saved_files)
            },
            success_url=request.host_url + "thankyou",
            cancel_url=request.host_url,
        )
        return redirect(session.url, code=303)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    import json
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError as e:
        print("❌ Invalid payload:", e)
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        print("❌ Invalid signature:", e)
        return "Invalid signature", 400
    except Exception as e:
        print("❌ Unknown error:", e)
        return "Webhook exception", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})
        sender = metadata.get("from_email", "anon@phantommailer.net")
        recipient = metadata.get("to_email")
        subject = f"Anonymous Message from {metadata.get('from_name', 'Anonymous')}"
        message = metadata.get("message", "")
        reply_to = metadata.get("from_email")

        attachments_raw = metadata.get("attachments", "[]")
        try:
            attachment_paths = json.loads(attachments_raw)
            if not isinstance(attachment_paths, list):
                attachment_paths = []
        except Exception as e:
            print("❌ Attachment parse error:", e)
            attachment_paths = []

        try:
            send_email(
                sender="send@phantommailer.net",
                recipient=recipient,
                subject=subject,
                body=message,
                attachments=attachment_paths,
                reply_to=reply_to
            )
            print("✅ Email delivered to", recipient)
            email_logs.append(f"Delivered to {recipient} via webhook.")
        except Exception as e:
            print("❌ Email send failed:", e)
            email_logs.append(f"Delivery failed: {str(e)}")

    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


email_logs = []

@app.route("/stealth")
def stealth_panel():
    token = request.args.get("token")
    if token != os.getenv("STEALTH_TOKEN"):
        abort(403)
    html = "<h2>Recent Message Logs</h2><ul>"
    for log in email_logs[-25:]:
        html += f"<li>{log}</li>"
    html += "</ul>"
    return html

import threading

def purge_old_files():
    import os, time, glob
    cutoff = time.time() - (36 * 3600)
    for f in glob.glob("uploads/*"):
        try:
            if os.path.isfile(f) and os.path.getmtime(f) < cutoff:
                os.remove(f)
        except:
            pass

# Run purge every hour
def start_purge_thread()

# Abuse Protection Setup
limiter = Limiter(get_remote_address, app=app)

TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
def validate_captcha(token, remote_ip):
    response = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
            "remoteip": remote_ip
        }
    )
    return response.json().get("success", False):
    def loop():
        while True:
            purge_old_files()
            time.sleep(3600)
    t = threading.Thread(target=loop, daemon=True)
    t.start()

start_purge_thread()

# Abuse Protection Setup
limiter = Limiter(get_remote_address, app=app)

TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
def validate_captcha(token, remote_ip):
    response = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
            "remoteip": remote_ip
        }
    )
    return response.json().get("success", False)

import secrets

# In-memory storage for incoming replies
inbox_store = {}

# Utility to generate a unique reply address and inbox key
def generate_reply_address():
    key = secrets.token_hex(8)
    address = f"reply-{key}@phantommailer.net"
    inbox_store[key] = {"created": time.time(), "message": None}
    return key, address

# Route to view replies
@app.route("/reply")
def view_reply():
    key = request.args.get("key")
    token = request.args.get("token")
    if not key or token != os.getenv("REPLY_SECRET_KEY"):
        abort(403)
    if key not in inbox_store or inbox_store[key]["message"] is None:
        return "No reply found or expired.", 404
    return f"<h2>Anonymous Reply</h2><p>{inbox_store[key]['message']}</p>"

@app.route("/mailer")
def mailer():
    return render_template("mailer_page.html"
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        return f"Webhook error: {str(e)}", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})
        sender = metadata.get("from_email", "anon@phantommailer.net")
        recipient = metadata.get("to_email")
        subject = "Anonymous Message via Phantom"
        message = metadata.get("message", "")
        reply_to = metadata.get("from_email")
        attachment_paths = metadata.get("attachments", "").split(",") if metadata.get("attachments") else []

        try:
            send_email(
                sender="send@phantommailer.net",
                recipient=recipient,
                subject=subject,
                body=message,
                attachments=attachment_paths,
                reply_to=reply_to
            )
            email_logs.append(f"Delivered to {recipient} via webhook.")
        except Exception as e:
            email_logs.append(f"Delivery failed: {str(e)}")
            print(f"Send failed: {e}")

    return "", 200
rs import CORS
from flask import Flask, request, redirect, render_template, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

# Configuration
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Stripe Setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route("/")
def index():
    return render_template("home_page.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/create-checkout-session", methods=["POST"])
@limiter.limit("5 per minute")
def create_checkout_session():
    data = request.form

    # Abuse protection: CAPTCHA + honeypot + rate limiter
    if not validate_captcha(data.get("cf-turnstile-response", ""), request.remote_addr):
        return "CAPTCHA verification failed", 403
    if data.get("website") != "":
        return "Bot detected", 403
    name = data.get("from_name")
    sender = data.get("from_email")
    recipient = data.get("to_email")
    message = data.get("message")

    files = [request.files.get("file1"), request.files.get("file2")]
    saved_files = []

    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)
            saved_files.append(path)

    # Free Trial Bypass
    if name.strip().lower() == "phantomfree":
        try:
            send_email(
                sender="send@phantommailer.net",
                recipient=recipient,
                subject="Anonymous Message (Free Trial)",
                body=message,
                attachments=saved_files,
                reply_to=sender
            )
            email_logs.append(f"Free trial used - delivered to {recipient}")
            return redirect("/thankyou")
        except Exception as e:
            return f"Bypass send failed: {str(e)}", 500

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 300,
                    "product_data": {"name": "Anonymous Email"}
                },
                "quantity": 1,
            }],
            mode="payment",
metadata={
                "from_name": name,
                "from_email": sender,
                "to_email": recipient,
                "message": message,
                "attachments": ",".join(saved_files)
            },
            success_url=request.host_url + "thankyou",
            cancel_url=request.host_url,
        )
        return redirect(session.url, code=303)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


email_logs = []

@app.route("/stealth")
def stealth_panel():
    token = request.args.get("token")
    if token != os.getenv("STEALTH_TOKEN"):
        abort(403)
    html = "<h2>Recent Message Logs</h2><ul>"
    for log in email_logs[-25:]:
        html += f"<li>{log}</li>"
    html += "</ul>"
    return html

import threading

def purge_old_files():
    import os, time, glob
    cutoff = time.time() - (36 * 3600)
    for f in glob.glob("uploads/*"):
        try:
            if os.path.isfile(f) and os.path.getmtime(f) < cutoff:
                os.remove(f)
        except:
            pass

# Run purge every hour
def start_purge_thread()

# Abuse Protection Setup
limiter = Limiter(get_remote_address, app=app)

TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
def validate_captcha(token, remote_ip):
    response = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
            "remoteip": remote_ip
        }
    )
    return response.json().get("success", False):
    def loop():
        while True:
            purge_old_files()
            time.sleep(3600)
    t = threading.Thread(target=loop, daemon=True)
    t.start()

start_purge_thread()

# Abuse Protection Setup
limiter = Limiter(get_remote_address, app=app)

TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
def validate_captcha(token, remote_ip):
    response = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
            "remoteip": remote_ip
        }
    )
    return response.json().get("success", False)

import secrets

# In-memory storage for incoming replies
inbox_store = {}

# Utility to generate a unique reply address and inbox key
def generate_reply_address():
    key = secrets.token_hex(8)
    address = f"reply-{key}@phantommailer.net"
    inbox_store[key] = {"created": time.time(), "message": None}
    return key, address

# Route to view replies
@app.route("/reply")
def view_reply():
    key = request.args.get("key")
    token = request.args.get("token")
    if not key or token != os.getenv("REPLY_SECRET_KEY"):
        abort(403)
    if key not in inbox_store or inbox_store[key]["message"] is None:
        return "No reply found or expired.", 404
    return f"<h2>Anonymous Reply</h2><p>{inbox_store[key]['message']}</p>"

@app.route("/mailer")
def mailer():
    return render_template("mailer_page.html")

@app.route("/favicon.ico")
def favicon():
    return app.send_static_file("favicon.ico")

@app.route("/sitemap.xml")
def sitemap():
    return app.send_static_file("sitemap.xml")

@app.route("/robots.txt")
def robots():
    return app.send_static_file("robots.txt")