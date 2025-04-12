
import imaplib
import email
import os
import time
from email.header import decode_header
from phantom import inbox_store

def connect_and_check_replies():
    IMAP_HOST = os.getenv("ZOHO_IMAP_HOST", "imap.zoho.com")
    IMAP_USER = os.getenv("ZOHO_IMAP_USER")
    IMAP_PASS = os.getenv("ZOHO_IMAP_PASS")

    if not IMAP_USER or not IMAP_PASS:
        print("IMAP credentials missing.")
        return

    try:
        with imaplib.IMAP4_SSL(IMAP_HOST) as mail:
            mail.login(IMAP_USER, IMAP_PASS)
            mail.select("inbox")

            status, messages = mail.search(None, 'ALL')
            if status != "OK":
                return

            for num in messages[0].split():
                res, msg_data = mail.fetch(num, "(RFC822)")
                if res != "OK":
                    continue

                msg = email.message_from_bytes(msg_data[0][1])
                to_field = msg.get("To", "")
                if "reply-" in to_field:
                    key_part = to_field.split("@")[0].replace("reply-", "").strip()
                    if key_part in inbox_store:
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body = part.get_payload(decode=True).decode(errors="ignore")
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode(errors="ignore")

                        inbox_store[key_part]["message"] = body.strip()
                        print(f"Reply received and stored for key: {key_part}")
                # Delete message after processing
                mail.store(num, '+FLAGS', '\Deleted')

            mail.expunge()
    except Exception as e:
        print(f"IMAP error: {e}")

# Call this periodically from main thread or scheduler
if __name__ == "__main__":
    while True:
        connect_and_check_replies()
        time.sleep(60)
