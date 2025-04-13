from flask_co


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    print("[Webhook] ✅ HIT")
    try:
        print("[Webhook] Headers:", dict(request.headers))
        print("[Webhook] Payload:", request.get_data(as_text=True))
    except Exception as e:
        print("[Webhook] ❌ Exception in logging:", e)
    return "OK", 200