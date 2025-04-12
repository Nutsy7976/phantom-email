from flask_c@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    import json
    try:
        payload = request.get_data()
        sig_header = request.headers.get("Stripe-Signature")
        webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

        print("🔧 Raw payload received:")
        print(payload.decode("utf-8"))

        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        print("✅ Stripe event constructed:", event.get("type"))

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
                print("✅ Email sent to", recipient)
                email_logs.append(f"Delivered to {recipient} via webhook.")
            except Exception as e:
                print("❌ Email send failed:", e)
                email_logs.append(f"Delivery failed: {str(e)}")

    except Exception as final_e:
        print("🔥 Final webhook error:", final_e)

    return "Webhook received", 200