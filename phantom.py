from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per second"])

@app.route("/webhook", methods=["POST"])
@limiter.exempt
def stripe_webhook():
    print("[Webhook] ✅ HIT")
    try:
        print("[Webhook] Headers:", dict(request.headers))
        print("[Webhook] Payload:", request.get_data(as_text=True))
    except Exception as e:
        print("[Webhook] ❌ Logging error:", e)
    return "OK", 200

@app.route("/")
def home():
    return "🏠 Phantom Base is Running", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)