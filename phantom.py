
from flask import Flask, request, redirect, render_template
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import smtplib
from email.message import EmailMessage

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

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
        )
        return redirect(session.url, code=303)
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")


# ✅ NEW CONTACT FORM ENDPOINT
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "Anonymous")
        contact_method = request.form.get("contact_method", "")
        purpose = request.form.get("purpose", "")

        msg = EmailMessage()
        msg["Subject"] = "New Phantom Contact Submission"
        msg["From"] = os.getenv("From_Email")
        msg["To"] = os.getenv("SMTP_USERNAME")

        msg.set_content(f"Name: {name}\nContact: {contact_method}\nPurpose: {purpose}")

        try:
            with smtplib.SMTP_SSL(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT"))) as server:
                server.login(os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASS"))
                server.send_message(msg)
            return redirect("/thankyou")
        except Exception as e:
            print("❌ Contact email failed:", e)
            return "Failed to send contact email", 500
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
