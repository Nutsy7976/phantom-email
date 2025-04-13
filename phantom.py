from flask_co


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    print("[Webhook] Hit")
    sig_header = request.headers.get("Stripe-Signature", "❌ Missing")
    print("[Webhook] Stripe-Signature:", sig_header)
    try:
        raw = request.get_data(as_text=True)
        print("[Webhook] Raw payload:")
        print(raw)
    except Exception as e:
        print("[Webhook] Error reading payload:", e)
    return "OK", 200