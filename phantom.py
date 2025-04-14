from flask import Flask, request, redirect, render_template
import os
import stripe
import json
import logging
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route("/")
def index():
    return render_template("home_page.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

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
                "message": message,
                "attachments": json.dumps(saved_files)
            }
        )
        return redirect(session.url, code=303)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")


def send_email(from_name, from_email, to_email, message, attachments):
    import smtplib
    from email.message import EmailMessage
    import mimetypes

    msg = EmailMessage()
    msg["Subject"] = "Anonymous Message via Phantom"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg.set_content(message)

    for file_path in attachments:
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
                maintype, subtype = mimetypes.guess_type(file_path)[0].split("/")
                msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=Path(file_path).name)
        except Exception as e:
            print(f"Attachment error: {e}")

    try:
        with smtplib.SMTP_SSL("smtp.zohocloud.ca", 465) as smtp:
            smtp.login(os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASS"))
            smtp.send_message(msg)
            print("✅ Email sent successfully")
    except Exception as e:
        print(f"❌ Email failed: {e}")
")
    print("From:", from_name, "<" + from_email + ">")
    print("To:", to_email)
    print("Message:", message)
    print("Attachments:", attachments)
    # Implement real email send here with SMTP2GO/Zoho.

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("stripe-signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})
        try:
            attachments = json.loads(metadata.get("attachments", "[]"))
        except Exception:
            attachments = []

        send_email(
            from_name=metadata.get("from_name", ""),
            from_email=metadata.get("from_email", ""),
            to_email=metadata.get("to_email", ""),
            message=metadata.get("message", ""),
            attachments=attachments
        )

        for path in attachments:
            try:
                os.remove(path)
            except Exception as e:
                logging.warning(f"Failed to delete file {path}: {e}")

    return "OK", 200

@app.route("/reprocess-failed-events", methods=["GET"])
def reprocess_failed_events():
    events = stripe.Event.list(
        types=["checkout.session.completed"],
        delivery_success=False
    )

    output = []
    for event in events.auto_paging_iter():
        payload = json.dumps(event)
        sig_header = ""
        endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

        try:
            reconstructed_event = stripe.Webhook.construct_event(
                payload=payload,
                sig_header=sig_header,
                secret=endpoint_secret
            )
        except Exception as e:
            output.append(f"❌ Skipping {event.id} due to error: {str(e)}")
            continue

        if reconstructed_event["type"] == "checkout.session.completed":
            session = reconstructed_event["data"]["object"]
            metadata = session.get("metadata", {})
            try:
                attachments = json.loads(metadata.get("attachments", "[]"))
            except Exception:
                attachments = []

            send_email(
                from_name=metadata.get("from_name", ""),
                from_email=metadata.get("from_email", ""),
                to_email=metadata.get("to_email", ""),
                message=metadata.get("message", ""),
                attachments=attachments
            )

            msg = (
                f"✅ Payment: {session.get('id')} | "
                f"👤 Email: {session.get('customer_email')} | "
                f"🧾 Metadata: {metadata}"
            )
            output.append(msg)

            for path in attachments:
                try:
                    os.remove(path)
                except Exception as e:
                    logging.warning(f"Failed to delete file {path}: {e}")

    return "<br>".join(output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


@app.route("/terms.html")
def terms():
    return render_template("terms.html")

@app.route("/privacy.html")
def privacy():
    return render_template("privacy.html")

@app.route("/contact.html", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        method = request.form.get("method")
        purpose = request.form.get("purpose")
        print("New contact message:", name, method, purpose)
        return render_template("contact_publisher.html", success=True)
    return render_template("contact_publisher.html")

@app.route("/about.html")
def about():
    return render_template("about.html")

@app.route("/terms.html")
def terms():
    return render_template("terms.html")

@app.route("/privacy.html")
def privacy():
    return render_template("privacy.html")

@app.route("/contact.html", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        method = request.form.get("method")
        purpose = request.form.get("purpose")
        print("New contact message:", name, method, purpose)
        return render_template("contact_publisher.html", success=True)
    return render_template("contact_publisher.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")
