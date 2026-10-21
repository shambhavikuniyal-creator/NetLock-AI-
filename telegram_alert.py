import os
import requests
from dotenv import load_dotenv

# Load secrets from hidden .env file
load_dotenv()

# Environment variables
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_threat_alert(ip: str, threat_score: int, packet_size: int) -> bool:
    """Formats a malicious network event and securely transmits a

    real-time cyber security threat alert to the configured Telegram chat.
    """
    if not BOT_TOKEN or not CHAT_ID:
        print(
            "[NetLock AI] Error: BOT_TOKEN or CHAT_ID missing in .env configuration."
        )
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    alert_message = (
        f"🚨 [NETLOCK AI SECURITY ALERT]\n"
        f"• Blocked IP: {ip}\n"
        f"• Threat Severity: {threat_score}%\n"
        f"• Packet Payload: {packet_size} Bytes\n"
        f"• Action Taken: Added to C Hash Table (Zero Delay Block)"
    )

    payload = {"chat_id": CHAT_ID, "text": alert_message}

    try:
        response = requests.post(url, json=payload, timeout=10)

        if response.status_code == 200:
            print(f"[NetLock AI] Alert successfully transmitted for IP: {ip}")
            return True
        else:
            print(
                f"[NetLock AI] API Transmission Failed. Server response code: {response.status_code}"
            )
            return False

    except requests.exceptions.RequestException as e:
        print(
            f"[NetLock AI] Critical network exception captured during execution: {e}"
        )
        return False


if __name__ == "__main__":
    print(
        "Initializing NetLock AI Automated Threat Alert Testing Mechanism..."
    )
    send_threat_alert(ip="185.220.101.5", threat_score=94, packet_size=1518)