
from flask import Flask, request, jsonify, abort
import json

app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    # Example: verify the signature (mocked for now)
    try:
        event = json.loads(payload)
    except Exception as e:
        app.logger.error(f"Webhook payload parse error: {e}")
        abort(400)

    if event.get("type") == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})
        attachments_raw = metadata.get("attachments", "[]")

        try:
            attachments = json.loads(attachments_raw)
            if not isinstance(attachments, list):
                raise ValueError("Attachments must be a list.")
        except Exception as e:
            app.logger.error(f"Attachment parse error: {e}")
            attachments = []

        # Safe access to metadata
        from_name = metadata.get("from_name", "Anonymous")
        from_email = metadata.get("from_email", "")
        to_email = metadata.get("to_email", "")
        message = metadata.get("message", "")

        app.logger.info("Webhook processed successfully.")
        app.logger.info(f"Sending email to {to_email} with {len(attachments)} attachments.")

    return jsonify(success=True)
