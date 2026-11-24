#!/usr/bin/env python3
"""Create a test email and sign it with DKIM, writing the result to an .eml file."""
import argparse
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

import dkim

SIGNED_HEADERS = [b"from", b"to", b"subject", b"date", b"message-id"]


def build_message(sender: str, recipient: str, subject: str, body: str) -> EmailMessage:
    domain = sender.rpartition("@")[2]
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    msg.set_content(body)
    return msg


def sign_message(raw: bytes, domain: str, selector: str, private_key: bytes) -> bytes:
    signature = dkim.sign(
        raw,
        selector=selector.encode(),
        domain=domain.encode(),
        privkey=private_key,
        include_headers=SIGNED_HEADERS,
    )
    return signature + raw


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="sender", required=True, help="e.g. alice@example.com")
    parser.add_argument("--to", dest="recipient", required=True)
    parser.add_argument("--selector", required=True)
    parser.add_argument("--key", type=Path, required=True, help="private key PEM from generate_dkim.py")
    parser.add_argument("--subject", default="DKIM test message")
    parser.add_argument("--body", default="This is a DKIM-signed test message.")
    parser.add_argument("--out", type=Path, default=Path("signed.eml"))
    args = parser.parse_args()

    domain = args.sender.rpartition("@")[2]
    msg = build_message(args.sender, args.recipient, args.subject, args.body)
    signed = sign_message(msg.as_bytes(), domain, args.selector, args.key.read_bytes())
    args.out.write_bytes(signed)
    print(f"Signed message written to {args.out} (d={domain}, s={args.selector})")


if __name__ == "__main__":
    main()
