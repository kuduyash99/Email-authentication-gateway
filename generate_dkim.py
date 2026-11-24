#!/usr/bin/env python3
"""Generate a DKIM RSA key pair and print the DNS TXT record to publish."""
import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TXT_CHUNK = 255  # max length of a single string inside a DNS TXT record


def generate_private_key(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def dkim_record_value(private_key: rsa.RSAPrivateKey) -> str:
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


def chunk(value: str) -> str:
    """Split into quoted <=255 char strings, as required by most DNS zone files."""
    return " ".join(f'"{value[i:i + TXT_CHUNK]}"' for i in range(0, len(value), TXT_CHUNK))


def write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True, help="e.g. example.com")
    parser.add_argument("--selector", required=True, help="e.g. mail2026")
    parser.add_argument("--bits", type=int, default=2048, choices=[1024, 2048, 4096])
    parser.add_argument("--out-dir", type=Path, default=Path("keys"))
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    key_path = args.out_dir / f"{args.selector}.private.pem"

    key = generate_private_key(args.bits)
    write_private_key(key_path, key)  # fails if the file already exists

    print(f"Private key written to {key_path} (keep secret, never publish)\n")
    print("Publish this DNS TXT record:")
    print(f"  Name : {args.selector}._domainkey.{args.domain}")
    print(f"  Value: {chunk(dkim_record_value(key))}")


if __name__ == "__main__":
    main()
