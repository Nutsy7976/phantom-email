from flask import Flask, request, redirect, render_template, jsonify, abort
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import json
import smtplib
from email.message import EmailMessage
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

limiter = Limiter(get_remote_address, app=app, default_limits=["10 per hour"])

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")

@app.route("/create-checkout-session", methods=["POST"])
@limiter.limit("5 per hour")
def create_checkout_session():
    data = request.form
    name = data.get("from_name", "Anonymous")
    sender = data.get("from_email")
    recipient = data.get("to_email")
    message = data.get("message")

    # OWNER BYPASS
    bypass_code = os.getenv("BYPASS_CODE", "phantomadmin")
    if name.strip().lower() == bypass_code.lower():
        send_email(name, sender, recipient, message, [])
        return redirect("/thankyou")

    files = [request.files.get("file1"), request.files.get("file2")]
    saved_files_info = []

    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)
            saved_files_info.append(filename)

    try:
        metadata = {
            "from_name": name,
            "from_email": sender,
            "to_email": recipient,
            "message": message,
            "attachments": json.dumps(saved_files_info)
        }
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
            success_url=request.host_url.rstrip('/') + "/thankyou",
            cancel_url=request.host_url.rstrip('/'),
            metadata=metadata
        )
        return redirect(session.url, code=303)
    except Exception as e:
        app.logger.error(f"Checkout error: {e}")
        return f"Error: {str(e)}", 500

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        app.logger.error(f"Webhook signature error: {e}")
        return "Signature verification failed", 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        metadata = session.get('metadata', {})
        try:
            send_email(
                metadata.get('from_name', 'Anonymous'),
                metadata.get('from_email'),
                metadata.get('to_email'),
                metadata.get('message'),
                json.loads(metadata.get('attachments', '[]'))
            )
        except Exception as e:
            app.logger.error(f"Email dispatch error: {e}")
            return "Email sending failed", 500
    return jsonify(success=True)

def send_email(from_name, from_email, to_email, message, attachments):
    email_user = os.getenv("SMTP_USERNAME")
    email_pass = os.getenv("SMTP_PASS")
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    from_address = os.getenv("From_Email")

    msg = EmailMessage()
    msg['Subject'] = f"Message from {from_name}"
    msg['From'] = from_address
    msg['To'] = to_email
    if from_email:
        msg['Reply-To'] = from_email
    msg.set_content(message)

    for filename in attachments:
        path = os.path.join("uploads", filename)
        try:
            with open(path, 'rb') as f:
                data = f.read()
                msg.add_attachment(data, maintype='application', subtype='octet-stream', filename=filename)
        except Exception as e:
            app.logger.warning(f"Attachment error: {e}")

    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(email_user, email_pass)
            server.send_message(msg)
            app.logger.info(f"✅ Email sent to {to_email}")
    except Exception as e:
        app.logger.error(f"❌ SMTP error: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
