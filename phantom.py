from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "✅ Flask is running", 200

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    print("[Webhook] ✅ HIT")
    try:
        print("[Webhook] Headers:", dict(request.headers))
        print("[Webhook] Payload:", request.get_data(as_text=True))
    except Exception as e:
        print("[Webhook] ❌ Logging error:", e)
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)