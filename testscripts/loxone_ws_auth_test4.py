"""
Loxone Gen2 authentication test — PyLoxone-master 1:1 replica + diagnostiek.

OVER-DE-DRAAD-GEDRAG (identiek aan PyLoxone-master/connection.py):

  1. HTTP GET /jdev/cfg/apiKey       (BasicAuth)
  2. HTTP GET /jdev/sys/getPublicKey (BasicAuth)  ->  CERT-tags vervangen door
                                                     PUBLIC KEY-tags, dan RSA.importKey
  3. WS  ws://host/ws/rfc6455
       - subprotocol: configureerbaar (default 'remotecontrol' als safety;
         PyLoxone-master gebruikt geen subprotocol, maar Loxone-docs vermelden
         'remotecontrol'. Beide werken empirisch; we maken het knoppelbaar.)
       - GEEN Authorization header (PyLoxone doet dit ook niet)
  4. WS  jdev/sys/keyexchange/<rsa(b64(aeskey:iv))>     (PLAIN)
  5. WS  jdev/sys/getkey2/<user>                        (ENCRYPTED  -- r1228)
  6. hash-keten zoals _hash_credentials  (r404):
       pwd  = SHA(password + ":" + user_salt).hexdigest().upper()
       new  = HMAC(key_hex, username + ":" + pwd).hexdigest()
     user_salt = LETTERLIJK uit JSON; geen hex-decode (r1241).
  7. WS  jdev/sys/getjwt/<hash>/<user>/<perm>/<uuid>/<info>   (ENCRYPTED)

DIAGNOSTIEK (alleen lokaal gelogd, NIET extra over de draad):
  - Beide salt-varianten worden gehasht (raw & hex-decoded).
  - We versturen alleen de PyLoxone-versie (raw), en logen beide nieuwe hashes
    naast elkaar zodat je achteraf kunt vergelijken.
  - Eén poging, geen retry-loop, hard stop bij 401 (om IP-block te vermijden).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import urllib.parse
from datetime import datetime
from typing import Any

import aiohttp
import websockets as wslib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding


# ============================================================
# CONFIG
# ============================================================
# Fill in your miniserver details before running:
HOST = "192.168.1.10"             # LAN IP of your Loxone Miniserver
PORT = 80

USERNAME = "<your-loxone-user>"   # the miniserver user
PASSWORD = "<your-loxone-pass>"   # that user's password

# PyLoxone-master const.py: 2=web, 4=app
TOKEN_PERMISSION = 2

# PyLoxone-master connection.py r1266-r1268 (hardcoded, exact zo)
CLIENT_UUID = "edfc5f9a-df3f-4cad-9dddcdc42c732b82"
CLIENT_INFO = "pyloxone_api"

# WS-subprotocol: PyLoxone-master gebruikt 'None'. Loxone-docs noemen
# 'remotecontrol'. Voor extra robuustheid laten we het standaard aan;
# zet op None om exact PyLoxone-bytes-on-the-wire te hebben.
WS_SUBPROTOCOL: str | None = "remotecontrol"

# Constants uit PyLoxone-master const.py
IV_BYTES = 16
AES_KEY_SIZE = 32
SALT_BYTES = 16
MAX_WEBSOCKET_MESSAGE_SIZE = 5 * 1024 * 1024
TIMEOUT = 30

# Loxone command-strings
CMD_GET_API_KEY = "/jdev/cfg/apiKey"
CMD_GET_PUBLIC_KEY = "/jdev/sys/getPublicKey"
CMD_KEY_EXCHANGE = "jdev/sys/keyexchange/"
CMD_GET_KEY_AND_SALT = "jdev/sys/getkey2"
CMD_REQUEST_TOKEN = "jdev/sys/gettoken"             # MS < 10.2
CMD_REQUEST_TOKEN_JSON_WEB = "jdev/sys/getjwt"      # MS >= 10.2


# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s.%(msecs)03d] [%(levelname)-5s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("loxauth4")
logging.getLogger("websockets.client").setLevel(logging.INFO)
logging.getLogger("aiohttp.access").setLevel(logging.INFO)


def _short(s: Any, n: int = 200) -> str:
    if isinstance(s, (bytes, bytearray)):
        s = bytes(s).hex()
    s = str(s).replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[:n] + f"...(+{len(s)-n} chars)"


def _hexpreview(b: bytes, n: int = 32) -> str:
    if len(b) <= n:
        return b.hex()
    return b[:n].hex() + f"...(+{len(b)-n}B)"


def _redact(s: str, keep: int = 6) -> str:
    if len(s) <= keep * 2:
        return s
    return f"{s[:keep]}…{s[-keep:]} (len={len(s)})"


def _banner(title: str) -> None:
    bar = "═" * (len(title) + 4)
    log.info(bar)
    log.info(f"  {title}")
    log.info(bar)


# ============================================================
# HTTP fase
# ============================================================
async def http_phase(session: aiohttp.ClientSession) -> tuple[list[int], str, str]:
    """
    Voert /jdev/cfg/apiKey en /jdev/sys/getPublicKey uit (BasicAuth).
    Returns: (miniserver_version, public_key_pem, miniserver_serial)
    """
    _banner("HTTP fase: /jdev/cfg/apiKey + /jdev/sys/getPublicKey")
    base = f"http://{HOST}:{PORT}"
    auth = aiohttp.BasicAuth(USERNAME, PASSWORD)
    log.info(f"BasicAuth: user={USERNAME!r} pass.len={len(PASSWORD)}")

    # ---- /jdev/cfg/apiKey
    url = f"{base}{CMD_GET_API_KEY}"
    log.info(f"[HTTP] GET {url}")
    async with session.get(
        url, auth=auth, timeout=aiohttp.ClientTimeout(total=TIMEOUT)
    ) as resp:
        log.info(f"[HTTP] apiKey  status={resp.status}  ctype={resp.headers.get('Content-Type')!r}")
        if resp.status != 200:
            body = await resp.text()
            raise RuntimeError(f"apiKey: HTTP {resp.status}: {body!r}")
        api_text = await resp.text()
    log.debug(f"[HTTP] apiKey  body raw : {_short(api_text, 350)}")

    api_obj = json.loads(api_text)
    api_value_str = str(api_obj["LL"]["value"]).replace("'", '"')
    log.debug(f"[HTTP] apiKey  value-as-string (post-quote-fix): {_short(api_value_str, 350)}")
    api_value = json.loads(api_value_str)
    log.info(f"[HTTP] apiKey  parsed    : {api_value}")

    version_str = api_value.get("version", "")
    miniserver_version = (
        [int(x) for x in version_str.split(".")] if version_str else []
    )
    snr = api_value.get("snr", "")
    log.info(f"[HTTP] miniserver version={miniserver_version} snr={snr!r} local={api_value.get('local')}")

    # ---- /jdev/sys/getPublicKey
    url = f"{base}{CMD_GET_PUBLIC_KEY}"
    log.info(f"[HTTP] GET {url}")
    async with session.get(
        url, auth=auth, timeout=aiohttp.ClientTimeout(total=TIMEOUT)
    ) as resp:
        log.info(f"[HTTP] pubkey  status={resp.status}  ctype={resp.headers.get('Content-Type')!r}")
        if resp.status != 200:
            body = await resp.text()
            raise RuntimeError(f"getPublicKey: HTTP {resp.status}: {body!r}")
        pk_text = await resp.text()

    pk_obj = json.loads(pk_text)
    pk_value = str(pk_obj["LL"]["value"])
    log.debug(f"[HTTP] pubkey  raw value: {_short(pk_value, 350)}")

    # PyLoxone-master.open() r942-944: tag-vervang, dan RSA.importKey
    pem = (
        pk_value
        .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n")
        .replace("-----END CERTIFICATE-----", "\n-----END PUBLIC KEY-----\n")
    )
    log.info(f"[HTTP] pubkey  PEM gemaakt (len={len(pem)})")
    log.debug(f"[HTTP] pubkey  PEM:\n{pem}")

    # validatie: kan pycryptodome de PEM laden?
    rsa_validate = RSA.importKey(pem)
    log.info(f"[HTTP] pubkey  RSA OK: {rsa_validate.size_in_bits()} bits, e={rsa_validate.e}")

    return miniserver_version, pem, snr


# ============================================================
# Crypto
# ============================================================
def make_session_key(pubkey_pem: str) -> tuple[bytes, bytes, bytes]:
    """AES-256 key + 16-byte IV; versleutel '<key.hex>:<iv.hex>' met RSA-PKCS1v1_5."""
    aes_key = get_random_bytes(AES_KEY_SIZE)
    aes_iv = get_random_bytes(IV_BYTES)

    rsa_key = RSA.importKey(pubkey_pem)
    rsa_cipher = PKCS1_v1_5.new(rsa_key)

    plaintext = f"{aes_key.hex()}:{aes_iv.hex()}".encode("utf-8")
    log.debug(f"[CRYPTO] session-key plaintext = '{aes_key.hex()}:{aes_iv.hex()}' (len={len(plaintext)})")

    encrypted = rsa_cipher.encrypt(plaintext)
    if not encrypted:
        raise RuntimeError("RSA encryption returned empty result")
    sk_b64 = base64.b64encode(encrypted)

    log.info(f"[CRYPTO] aes_key  = {_hexpreview(aes_key)}")
    log.info(f"[CRYPTO] aes_iv   = {_hexpreview(aes_iv)}")
    log.info(f"[CRYPTO] rsa(out) = {len(encrypted)} bytes; b64.len={len(sk_b64)}")
    return aes_key, aes_iv, sk_b64


def encrypt_command(aes_key: bytes, aes_iv: bytes, salt_hex: str, command: str) -> str:
    """Bouwt 'jdev/sys/enc/<urlencode(b64(AES-CBC(salt/<salt>/<cmd>\\0)))>'."""
    plaintext = f"salt/{salt_hex}/{command}\x00".encode("utf-8")
    log.debug(f"[ENC] plaintext (pre-pad, len={len(plaintext)}) = {_short(plaintext.decode('utf-8', errors='replace'), 220)}")

    padded = Padding.pad(plaintext, 16)
    aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    cipher = aes.encrypt(padded)
    cipher_b64 = base64.b64encode(cipher).decode()
    enc_quoted = urllib.parse.quote(cipher_b64)
    out = f"jdev/sys/enc/{enc_quoted}"
    log.debug(f"[ENC] padded={len(padded)}B  cipher={len(cipher)}B  b64.len={len(cipher_b64)}  url.len={len(enc_quoted)}")
    return out


def compute_hash(
    password: str,
    username: str,
    user_salt: str,
    key_hex: str,
    hash_alg: str,
    label: str,
) -> str:
    """
    Exacte port van LoxoneBaseConnection._hash_credentials (connection.py r402-r426).

    LET OP: PyLoxone gebruikt user_salt LETTERLIJK uit JSON.
    Zie connection.py r1241 (self._user_salt = value_dict.get("salt", "")).
    """
    if hash_alg == "SHA1":
        m = hashlib.sha1()
        hash_module = SHA1
    elif hash_alg == "SHA256":
        m = hashlib.sha256()
        hash_module = SHA256
    else:
        raise ValueError(f"Onbekend hash-algoritme: {hash_alg!r}")

    pwd_hash_str = f"{password}:{user_salt}"
    m.update(pwd_hash_str.encode("utf-8"))
    pwd_hash = m.hexdigest().upper()

    hmac_input = f"{username}:{pwd_hash}"
    digester = HMAC.new(bytes.fromhex(key_hex), hmac_input.encode("utf-8"), hash_module)
    new_hash = digester.hexdigest()

    log.info(f"[HASH:{label}] alg={hash_alg}")
    log.info(f"[HASH:{label}]   pwd_hash_str = '{password}':{user_salt!r}  (len={len(pwd_hash_str)})")
    log.info(f"[HASH:{label}]   sha-upper    = {pwd_hash}")
    log.info(f"[HASH:{label}]   hmac_input   = '{username}:<pwd_hash>'  (len={len(hmac_input)})")
    log.info(f"[HASH:{label}]   key_hex[:8]  = {key_hex[:8]}  (key.len={len(key_hex)//2}B)")
    log.info(f"[HASH:{label}]   new_hash     = {new_hash}")
    return new_hash


def maybe_hex_decode_utf8(s: str) -> tuple[str | None, str]:
    """Probeer s als hex te lezen en utf-8 te decoderen.

    Returns (decoded_or_None, reason).
    """
    if not s:
        return None, "empty"
    if len(s) % 2 != 0:
        return None, "odd length"
    if not all(c in "0123456789abcdefABCDEF" for c in s):
        return None, "not all hex chars"
    try:
        decoded = binascii.unhexlify(s).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        return None, f"decode-error: {e}"
    return decoded, "ok"


# ============================================================
# WebSocket helpers
# ============================================================
async def ws_recv_ll(ws, label: str) -> dict[str, Any]:
    """Lees 8-byte binary header + payload, parse als LL JSON-object."""
    log.debug(f"[WS:{label}] wachten op header (8 bytes)…")
    header = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT)
    if not isinstance(header, (bytes, bytearray)):
        raise RuntimeError(
            f"[{label}] verwacht binary header, kreeg {type(header).__name__}: "
            f"{_short(header, 120)}"
        )
    if len(header) != 8:
        raise RuntimeError(
            f"[{label}] header heeft len={len(header)} (verwacht 8): "
            f"{_short(bytes(header))}"
        )
    if header[0] != 0x03:
        raise RuntimeError(
            f"[{label}] header startbyte 0x{header[0]:02x} != 0x03: {bytes(header).hex()}"
        )
    msg_type = header[1]
    info_byte = header[2]
    estimated = (info_byte >> 7) == 1
    payload_len = int.from_bytes(header[4:8], "little", signed=False)
    log.info(
        f"[WS:{label}] header   type=0x{msg_type:02x} info=0x{info_byte:02x} "
        f"estimated={estimated} payload_len={payload_len}"
    )

    log.debug(f"[WS:{label}] wachten op payload…")
    payload = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT)
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = bytes(payload).decode("utf-8")
        except UnicodeDecodeError:
            raise RuntimeError(
                f"[{label}] payload geen UTF-8; first32B={_hexpreview(bytes(payload))}"
            )
    log.debug(f"[WS:{label}] payload  raw : {_short(payload, 400)}")

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"[{label}] payload geen JSON: {e}; raw={_short(payload, 400)}")
    return data


def ll_code(data: dict) -> int | None:
    ll = data.get("LL", {})
    raw = ll.get("code", ll.get("Code"))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def ll_value(data: dict) -> Any:
    return data.get("LL", {}).get("value")


def ll_control(data: dict) -> str:
    return str(data.get("LL", {}).get("control", ""))


# ============================================================
# Main
# ============================================================
async def run() -> None:
    _banner("CONFIG")
    log.info(f"HOST            = {HOST}:{PORT}")
    log.info(f"USERNAME        = {USERNAME!r}")
    log.info(f"PASSWORD len    = {len(PASSWORD)}")
    log.info(f"TOKEN_PERMISSION= {TOKEN_PERMISSION}  (2=web, 4=app)")
    log.info(f"CLIENT_UUID     = {CLIENT_UUID}")
    log.info(f"CLIENT_INFO     = {CLIENT_INFO!r}")
    log.info(f"WS_SUBPROTOCOL  = {WS_SUBPROTOCOL!r}  (None = exact PyLoxone)")

    # ---- HTTP
    async with aiohttp.ClientSession() as session:
        miniserver_version, pubkey_pem, _snr = await http_phase(session)

    use_jwt = miniserver_version >= [10, 2]
    cmd_token = CMD_REQUEST_TOKEN_JSON_WEB if use_jwt else CMD_REQUEST_TOKEN
    log.info(f"[CFG] miniserver {miniserver_version} -> token-cmd={cmd_token}")

    # ---- Crypto
    _banner("Sessie-key voorbereiden (AES + RSA-encrypted)")
    aes_key, aes_iv, session_key_b64 = make_session_key(pubkey_pem)

    salt_hex = get_random_bytes(SALT_BYTES).hex()
    log.info(f"[CRYPTO] init salt = {salt_hex}  (len={len(salt_hex)} chars / {SALT_BYTES}B)")

    # ---- WebSocket
    ws_url = f"ws://{HOST}:{PORT}/ws/rfc6455"
    _banner(f"WebSocket connect → {ws_url}")
    log.info("Geen Authorization header (zoals PyLoxone-master).")
    log.info(f"Subprotocol = {WS_SUBPROTOCOL!r}")

    ws_kwargs: dict[str, Any] = dict(
        open_timeout=TIMEOUT,
        compression=None,
        max_size=MAX_WEBSOCKET_MESSAGE_SIZE,
    )
    if WS_SUBPROTOCOL:
        ws_kwargs["subprotocols"] = [WS_SUBPROTOCOL]

    async with wslib.connect(ws_url, **ws_kwargs) as ws:
        log.info(f"[WS] handshake OK; negotiated subprotocol = {ws.subprotocol!r}")

        # ----- 1) keyexchange (PLAIN)
        _banner("STAP 1: keyexchange (plain)")
        ke_cmd = f"{CMD_KEY_EXCHANGE}{session_key_b64.decode()}"
        log.info(f"[WS] -> keyexchange (cmd.len={len(ke_cmd)})")
        log.debug(f"[WS]    cmd = {_short(ke_cmd, 200)}")
        await ws.send(ke_cmd)
        ke_resp = await ws_recv_ll(ws, "keyexchange")
        log.info(f"[WS] <- keyexchange code={ll_code(ke_resp)} control={_short(ll_control(ke_resp), 100)}")
        if ll_code(ke_resp) != 200:
            raise RuntimeError(f"keyexchange faalde: {json.dumps(ke_resp)}")

        # ----- 2) getkey2 (ENCRYPTED, conform PyLoxone r1228)
        _banner("STAP 2: getkey2 (encrypted, zoals PyLoxone r1228)")
        gk_plain = f"{CMD_GET_KEY_AND_SALT}/{USERNAME}"
        log.info(f"[WS] -> getkey2 plain  = {gk_plain!r}")
        gk_enc = encrypt_command(aes_key, aes_iv, salt_hex, gk_plain)
        log.debug(f"[WS] -> getkey2 enc   = {_short(gk_enc, 220)}")
        await ws.send(gk_enc)
        gk_resp = await ws_recv_ll(ws, "getkey2")
        gk_code = ll_code(gk_resp)
        log.info(f"[WS] <- getkey2 code={gk_code} control={_short(ll_control(gk_resp), 100)}")
        if gk_code != 200:
            raise RuntimeError(f"getkey2 faalde: {json.dumps(gk_resp)}")

        v = ll_value(gk_resp) or {}
        if not isinstance(v, dict):
            raise RuntimeError(f"getkey2 value is geen dict: {v!r}")
        key_hex = str(v.get("key", ""))
        user_salt_raw = str(v.get("salt", ""))
        hash_alg = str(v.get("hashAlg", "SHA1"))
        log.info(f"[WS]    hashAlg     = {hash_alg}")
        log.info(f"[WS]    key (hex)   = {_redact(key_hex, 8)}")
        log.info(f"[WS]    salt (RAW)  = {user_salt_raw!r}  (len={len(user_salt_raw)})")

        decoded_salt, dec_reason = maybe_hex_decode_utf8(user_salt_raw)
        if decoded_salt is not None:
            log.info(f"[WS]    salt (HEX→UTF8 decoded) = {decoded_salt!r}  (len={len(decoded_salt)})")
        else:
            log.info(f"[WS]    salt is niet hex-decodeerbaar als UTF-8 ({dec_reason})")

        if not key_hex or not user_salt_raw:
            raise RuntimeError(f"getkey2 levert lege key/salt: {v!r}")

        # ----- 3) Hash-keten (PyLoxone-conform: RAW salt) + diagnostiek
        _banner("STAP 3: hash-keten (PyLoxone gebruikt RAW salt)")
        new_hash_raw = compute_hash(
            password=PASSWORD,
            username=USERNAME,
            user_salt=user_salt_raw,
            key_hex=key_hex,
            hash_alg=hash_alg,
            label="RAW (PyLoxone)",
        )

        if decoded_salt is not None:
            log.info("──── DIAGNOSTIEK: hash met decoded salt (NIET verzonden) ────")
            new_hash_decoded = compute_hash(
                password=PASSWORD,
                username=USERNAME,
                user_salt=decoded_salt,
                key_hex=key_hex,
                hash_alg=hash_alg,
                label="DECODED (info)",
            )
            log.info(f"[DIAG] new_hash RAW     = {new_hash_raw}")
            log.info(f"[DIAG] new_hash DECODED = {new_hash_decoded}")
            log.info("[DIAG] We versturen RAW (PyLoxone-master gedrag).")
        else:
            log.info("[DIAG] Geen decode-variant beschikbaar.")

        # ----- 4) getjwt / gettoken (ENCRYPTED)
        _banner(f"STAP 4: {cmd_token} (encrypted)")
        token_plain = (
            f"{cmd_token}/{new_hash_raw}/{USERNAME}/{TOKEN_PERMISSION}/"
            f"{CLIENT_UUID}/{CLIENT_INFO}"
        )
        log.info(f"[WS] -> {cmd_token} plain (len={len(token_plain)})")
        log.debug(f"[WS]    plain = {_short(token_plain, 240)}")
        token_enc = encrypt_command(aes_key, aes_iv, salt_hex, token_plain)
        log.debug(f"[WS]    enc   = {_short(token_enc, 240)}")
        await ws.send(token_enc)

        tok_resp = await ws_recv_ll(ws, cmd_token.split("/")[-1])
        code = ll_code(tok_resp)
        log.info(f"[WS] <- {cmd_token} code={code}")
        log.info(f"[WS]    control = {_short(ll_control(tok_resp), 200)}")
        log.info(f"[WS]    body    = {json.dumps(tok_resp, indent=2)}")

        if code != 200:
            log.error("=" * 60)
            log.error(f"AUTH FAALDE met code {code}.")
            log.error("Hard-stop om IP-block te voorkomen — geen retry.")
            if decoded_salt is not None:
                log.error("Vergelijk in de log RAW vs DECODED hashes hierboven om te zien")
                log.error("welke variant je miniserver verwacht.")
            log.error("=" * 60)
            raise RuntimeError(f"{cmd_token} faalde met code {code}")

        # ----- 5) Token uitlezen
        _banner("STAP 5: token verwerken")
        tv = ll_value(tok_resp) or {}
        if not isinstance(tv, dict):
            raise RuntimeError(f"token-respons value geen dict: {tv!r}")
        token = tv.get("token") or tv.get("jwt")
        valid_until = tv.get("validUntil")
        unsecure = tv.get("unsecurePass")
        token_key = tv.get("key")
        log.info(f"[OK] token verkregen len={len(token) if token else None}")
        log.info(f"[OK]   validUntil    = {valid_until}")
        log.info(f"[OK]   unsecurePass  = {unsecure}")
        log.info(f"[OK]   token.key     = {_redact(str(token_key), 6) if token_key else None}")
        if token:
            log.info(f"[OK]   token preview = {_redact(str(token), 16)}")


def main() -> None:
    started = datetime.now()
    log.info(f"=== loxone_ws_auth_test4 starten op {started.isoformat()} ===")
    try:
        asyncio.run(run())
        log.info("=== SUCCES ===")
    except wslib.exceptions.InvalidStatus as exc:
        log.error(
            "WS handshake afgewezen: HTTP %s %s",
            exc.response.status_code,
            exc.response.reason_phrase,
        )
        try:
            body = exc.response.body
            if body:
                log.error("WS body: %s", body.decode("utf-8", errors="replace"))
        except Exception:
            pass
    except Exception as exc:
        log.error(f"FOUT: {exc!r}")
        raise
    finally:
        log.info(f"=== klaar; duur={datetime.now() - started} ===")


if __name__ == "__main__":
    main()
