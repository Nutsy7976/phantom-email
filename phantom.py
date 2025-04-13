from flask import Flask, request, redirect, render_template
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

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
        print("💸 Payment succeeded!")
        print("Customer Email:", session.get("customer_email"))
        print("Metadata:", session.get("metadata"))

    return "OK", 200


@app.route("/reprocess-failed-events", methods=["GET"])
def reprocess_failed_events():
    stripe.api_key = "sk_live_..."  # Your actual secret key

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
            msg = (
                f"✅ Payment: {session.get('id')} | "
                f"👤 Email: {session.get('customer_email')} | "
                f"🧾 Metadata: {session.get('metadata')}"
            )
            output.append(msg)

    return "<br>".join(output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


import stripe
stripe.api_key = "sk_live_..."  # Use your real secret key here

events = stripe.Event.list(
    types=["checkout.session.completed"],
    delivery_success=False  # Only failed events
)

for event in events.auto_paging_iter():
    print(f"REPROCESSING: {event.id}")
    # Simulate webhook reprocessing by calling your handler logic
    payload = json.dumps(event)
    sig_header = ""  # Not used in manual case
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        reconstructed_event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=endpoint_secret
        )
    except Exception as e:
        print("Skipping due to error:", str(e))
        continue

    if reconstructed_event["type"] == "checkout.session.completed":
        session = reconstructed_event["data"]["object"]
        print("✅ Payment:", session.get("id"))
        print("👤 Email:", session.get("customer_email"))
        print("🧾 Metadata:", session.get("metadata"))
