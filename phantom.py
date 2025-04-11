from flask import Flask, request, redirect, render_template, jsonify
import os
import stripe
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("From_Email")

def send_anonymous_email(to_email, subject, message_html, spoofed_name, spoofed_email, reply_to=None, attachments=[]):
    try:
        msg = MIMEMultipart()
        msg["From"] = f"{spoofed_name} <{spoofed_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.attach(MIMEText(message_html, "html"))
        for filepath in attachments:
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    part = MIMEApplication(f.read(), Name=os.path.basename(filepath))
                    part['Content-Disposition'] = f'attachment; filename="{os.path.basename(filepath)}"'
                    msg.attach(part)
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        print("✅ Email sent")
        return True
    except Exception as e:
        print(f"❌ Email failed: {e}")
        return False

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/about.html")
def about():
    return render_template("about.html")

@app.route("/terms.html")
def terms():
    return render_template("terms.html")

@app.route("/contact.html", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        method = request.form.get("method")
        purpose = request.form.get("purpose")

        try:
            msg = MIMEMultipart()
            msg["From"] = FROM_EMAIL
            msg["To"] = FROM_EMAIL
            msg["Subject"] = f"Publisher Contact: {name}"
            msg.attach(MIMEText(
                f"<b>Contact Method:</b> {method}<br><b>Purpose:</b><br>{purpose}", "html"))
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                server.login(SMTP_USERNAME, SMTP_PASS)
                server.sendmail(FROM_EMAIL, FROM_EMAIL, msg.as_string())
            return render_template("contact.html", success=True)
        except Exception as e:
            print(f"❌ Contact form error: {e}")
            return render_template("contact.html", error=True)

    return render_template("contact.html")

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv("STRIPE_WEBHOOK_SECRET"))
    except Exception as e:
        print(f"❌ Webhook error: {e}")
        return jsonify(success=False), 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})
        to_email = metadata.get("to")
        subject = metadata.get("subject", "Anonymous Message")
        message_html = metadata.get("message", "")
        spoofed_email = metadata.get("spoofed_email", "anon@phantommailer.net")
        spoofed_name = metadata.get("spoofed_name", "Anonymous")
        reply_to = metadata.get("reply_to")
        attachments = []
        for i in range(1, 3):
            fname = metadata.get(f"file{i}")
            if fname:
                path = os.path.join("uploads", fname)
                if os.path.exists(path):
                    attachments.append(path)

        result = send_anonymous_email(
            to_email=to_email,
            subject=subject,
            message_html=message_html,
            spoofed_name=spoofed_name,
            spoofed_email=spoofed_email,
            reply_to=reply_to,
            attachments=attachments
        )

        print("✅ Email sent" if result else "❌ Email failed")

    return jsonify(success=True)

if __name__ == "__main__":
    app.run(debug=True)
