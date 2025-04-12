from flask_cors import CORS
from flask import Flask, request, redirect, render_template
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

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

@app.route("/qr")
def qr():
    return render_template("qr_flyer.html")

used_ips = {}

@app.route("/bypass-check", methods=["POST"])
def bypass_check():
    from_name = request.form.get("from_name", "").lower()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # Handle phantomfree bypass
    if from_name == "phantomfree":
        now = time.time()
        if ip in used_ips and now - used_ips[ip] < 86400:
            return "You already used the free Phantom trial. Please purchase to send more.", 403
        used_ips[ip] = now
        # You would normally trigger send_email() here
        return "Bypass granted. Message would be sent.", 200

    return "Invalid bypass or not allowed.", 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


email_logs = []

@app.route("/stealth")
def stealth_panel():
    token = request.args.get("token")
    if token != os.getenv("STEALTH_TOKEN"):
        abort(403)
    html = "<h2>Recent Message Logs</h2><ul>"
    for log in email_logs[-25:]:
        html += f"<li>{log}</li>"
    html += "</ul>"
    return html

import threading

def purge_old_files():
    import os, time, glob
    cutoff = time.time() - (36 * 3600)
    for f in glob.glob("uploads/*"):
        try:
            if os.path.isfile(f) and os.path.getmtime(f) < cutoff:
                os.remove(f)
        except:
            pass

# Run purge every hour
def start_purge_thread():
    def loop():
        while True:
            purge_old_files()
            time.sleep(3600)
    t = threading.Thread(target=loop, daemon=True)
    t.start()

start_purge_thread()

import secrets

# In-memory storage for incoming replies
inbox_store = {}

# Utility to generate a unique reply address and inbox key
def generate_reply_address():
    key = secrets.token_hex(8)
    address = f"reply-{key}@phantommailer.net"
    inbox_store[key] = {"created": time.time(), "message": None}
    return key, address

# Route to view replies
@app.route("/reply")
def view_reply():
    key = request.args.get("key")
    token = request.args.get("token")
    if not key or token != os.getenv("REPLY_SECRET_KEY"):
        abort(403)
    if key not in inbox_store or inbox_store[key]["message"] is None:
        return "No reply found or expired.", 404
    return f"<h2>Anonymous Reply</h2><p>{inbox_store[key]['message']}</p>"