from flask_cors import CORS
from flask import Flask, request, redirect, render_template, jsonify, abort
import os
import stripe
import time
import json
import threading
import secrets
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

used_ips = {}

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Configuration
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Stripe Setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")

@app.route("/qr")
def qr():
    return render_template("qr_flyer.html")

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    data = request.form
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
            success_url=request.host_url + "thankyou",
            cancel_url=request.host_url,
            metadata={
                "from_name": name,
                "from_email": sender,
                "to_email": recipient,
                "subject": "Anonymous Message",
                "message": message,
                "reply_to": data.get("reply_to"),
                "attachments": json.dumps(saved_files)
            }
        )
        return redirect(session.url, code=303)
    except Exception as e:
        return f"Error: {str(e)}", 500

def send_email(from_name, from_email, to_email, subject, message, reply_to=None, attachments=[]):
    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to

    for header in list(msg.keys()):
        if header.lower() in ["user-agent", "x-mailer", "x-originating-ip", "x-originating-host"]:
            del msg[header]

    msg.set_content(message)

    for path in attachments:
        with open(path, "rb") as f:
            file_data = f.read()
            file_name = os.path.basename(path)
            maintype, subtype = "application", "octet-stream"
            msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=file_name)

    with smtplib.SMTP_SSL(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT"))) as server:
        server.login(os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASS"))
        server.send_message(msg)

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get("stripe-signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except Exception as e:
        return f"Webhook error: {str(e)}", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})

        if metadata.get("from_name", "").lower() == "phantomfree":
            now = time.time()
            if ip in used_ips and now - used_ips[ip] < 86400:
                return "Free trial already used. Payment required.", 403
            used_ips[ip] = now

        send_email(
            from_name=metadata.get("from_name"),
            from_email=metadata.get("from_email"),
            to_email=metadata.get("to_email"),
            subject=metadata.get("subject"),
            message=metadata.get("message"),
            reply_to=metadata.get("reply_to"),
            attachments=json.loads(metadata.get("attachments", "[]"))
        )
    return jsonify(success=True), 200

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

def purge_old_files():
    import glob
    cutoff = time.time() - (36 * 3600)
    for f in glob.glob("uploads/*"):
        try:
            if os.path.isfile(f) and os.path.getmtime(f) < cutoff:
                os.remove(f)
        except:
            pass

def start_purge_thread():
    def loop():
        while True:
            purge_old_files()
            time.sleep(3600)
    t = threading.Thread(target=loop, daemon=True)
    t.start()

start_purge_thread()

# Reply system
inbox_store = {}

def generate_reply_address():
    key = secrets.token_hex(8)
    address = f"reply-{key}@phantommailer.net"
    inbox_store[key] = {"created": time.time(), "message": None}
    return key, address

@app.route("/reply")
def view_reply():
    key = request.args.get("key")
    token = request.args.get("token")
    if not key or token != os.getenv("REPLY_SECRET_KEY"):
        abort(403)
    if key not in inbox_store or inbox_store[key]["message"] is None:
        return "No reply found or expired.", 404
    return f"<h2>Anonymous Reply</h2><p>{inbox_store[key]['message']}</p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
