# --- START OF FILE phantom.py (DIAGNOSTIC VERSION) ---

from flask import Flask, request, redirect, render_template, jsonify, abort
import os
import stripe
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import json
import traceback # Import traceback for detailed error logging

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# --- Stripe Configuration ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET") # Still load it, we might log if it's missing

# --- Basic Routes (Keep them as they are) ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")


# --- Checkout Session Creation (Keep as is) ---
@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    data = request.form
    name = data.get("from_name", "Anonymous") # Provide default
    sender = data.get("from_email")
    recipient = data.get("to_email")
    message = data.get("message")

    # --- File Handling ---
    files = [request.files.get("file1"), request.files.get("file2")]
    saved_files_info = [] # Store relative paths or identifiers

    for file in files:
        if file and file.filename:
            try:
                filename = secure_filename(file.filename)
                path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(path)
                saved_files_info.append(filename)
            except Exception as e:
                print(f"Error saving file {file.filename}: {e}")

    # --- Input Validation (Basic Example) ---
    if not recipient or not message:
         return "Missing required fields (recipient email, message)", 400
    if not sender: # Often needed for email sending
         return "Missing sender email", 400

    # --- Create Stripe Checkout Session ---
    try:
        metadata = {
            "from_name": name,
            "from_email": sender,
            "to_email": recipient,
            "message": message,
            "attachments": json.dumps(saved_files_info)
        }

        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 300, # $3.00
                    "product_data": {"name": "Anonymous Email Service"}
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=request.host_url.rstrip('/') + "/thankyou",
            cancel_url=request.host_url.rstrip('/'),
            metadata=metadata
        )
        return redirect(session.url, code=303)

    except stripe.error.StripeError as e:
        print(f"Stripe Error: {e}")
        return f"Stripe Error: {e.user_message or str(e)}", 500
    except Exception as e:
        print(f"Generic Error: {e}")
        return f"An unexpected error occurred: {str(e)}", 500


# --- DIAGNOSTIC Stripe Webhook Handler ---
@app.route('/webhook', methods=['POST'])
def webhook_diagnostic():
    print("\n" + "="*50)
    print("[WEBHOOK DIAGNOSTIC] Endpoint Hit")
    print("="*50)

    # 1. Log Headers
    print("\n--- Request Headers ---")
    try:
        # Use request.headers.items() for cleaner iteration
        for header, value in request.headers.items():
            print(f"{header}: {value}")
        sig_header = request.headers.get('Stripe-Signature')
        print(f"Stripe-Signature found: {'Yes' if sig_header else 'No'}")
    except Exception as e:
        print(f"[ERROR] Could not log headers: {e}")
        traceback.print_exc()
    print("--- End Headers ---")


    # 2. Log Raw Payload Body
    payload_raw = None
    print("\n--- Raw Request Body ---")
    try:
        payload_raw = request.data # Use request.data for raw bytes
        if payload_raw:
            print(f"Raw payload (bytes, first 500): {payload_raw[:500]}")
            # Attempt to decode for readability, but don't crash if it fails
            try:
                 payload_decoded = payload_raw.decode('utf-8')
                 print(f"\nAttempted UTF-8 Decode (first 500 chars):\n{payload_decoded[:500]}")
            except Exception as decode_err:
                 print(f"\n[WARNING] Could not decode payload as UTF-8: {decode_err}")
        else:
             print("Raw payload is empty.")

    except Exception as e:
        print(f"[ERROR] Could not read request.data: {e}")
        traceback.print_exc()
    print("--- End Raw Body ---")


    # 3. Log Webhook Secret Status
    print("\n--- Webhook Secret Check ---")
    if webhook_secret:
        print("STRIPE_WEBHOOK_SECRET is loaded.")
    else:
        print("[WARNING] STRIPE_WEBHOOK_SECRET is NOT set in environment!")
    print("--- End Secret Check ---")


    # 4. Attempt Event Construction (for logging purposes only in this version)
    event = None
    print("\n--- Attempting Event Construction (for logging only) ---")
    if payload_raw and sig_header and webhook_secret:
        try:
            event = stripe.Webhook.construct_event(
                payload_raw, sig_header, webhook_secret
            )
            print(f"[SUCCESS] Event constructed successfully!")
            print(f"Event ID: {event.get('id', 'N/A')}")
            print(f"Event Type: {event.get('type', 'N/A')}")
            # Optionally log more event data if needed
            # print(f"Event Data Object Keys: {event.get('data', {}).get('object', {}).keys()}")
        except ValueError as e:
            # Invalid payload
            print(f"[ERROR - ValueError] Event construction failed: Invalid payload - {e}")
            # traceback.print_exc() # Often less useful for ValueError
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            print(f"[ERROR - SignatureVerificationError] Event construction failed: Invalid signature - {e}")
            # traceback.print_exc() # Often less useful for SigVerifyError
        except Exception as e:
            # Other construction errors
            print(f"[ERROR - Unexpected] Event construction failed: {e}")
            traceback.print_exc() # Print full traceback for unexpected errors
    else:
        print("[INFO] Skipping event construction attempt due to missing payload, signature header, or webhook secret.")
    print("--- End Event Construction Attempt ---")


    # 5. ALWAYS Return 200 OK
    print("\n" + "="*50)
    print("[WEBHOOK DIAGNOSTIC] Processing complete. Returning 200 OK to Stripe.")
    print("="*50 + "\n")
    # Use jsonify for a standard Flask JSON response, status code defaults to 200
    return jsonify(status="received", diagnostic_mode=True), 200


# --- Main Execution ---
if __name__ == "__main__":
    if not webhook_secret:
        print("WARNING: STRIPE_WEBHOOK_SECRET environment variable not set.")
        print("         Webhook signature verification will fail if attempted.")

    # Use debug=True for development to see logs easily and get auto-reloads
    # Important: Set debug=False in production!
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)

# --- END OF FILE phantom.py (DIAGNOSTIC VERSION) ---