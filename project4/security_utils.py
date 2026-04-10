"""Client-side crypto helpers (strict MANV + MATKHAU mode)."""

from __future__ import annotations

import base64
import hashlib
from typing import Dict, Union

from Crypto.Cipher import ChaCha20, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def sha512_hex(plain_text: str) -> str:
    return hashlib.sha512(plain_text.encode("utf-8")).hexdigest().upper()


def get_deterministic_randfunc(password: str, manv: str):
    if not password:
        raise ValueError("password cannot be empty")
    if not manv:
        raise ValueError("manv cannot be empty")

    seed_material = f"{manv}|{password}"
    seed_bytes = hashlib.sha512(seed_material.encode("utf-8")).digest()
    key = seed_bytes[:32]
    nonce = seed_bytes[32:40]
    cipher = ChaCha20.new(key=key, nonce=nonce)

    def randfunc(n: int) -> bytes:
        return cipher.encrypt(b"\x00" * n)

    return randfunc


def generate_deterministic_rsa_keypair(password: str, manv: str, bits: int = 2048) -> RSA.RsaKey:
    return RSA.generate(bits, randfunc=get_deterministic_randfunc(password, manv))


def derive_rsa_keypair_from_password(password_plain: str, context: str, bits: int = 2048) -> tuple[str, str]:
    if not password_plain:
        raise ValueError("password_plain cannot be empty")
    if not context:
        raise ValueError("context(MANV) cannot be empty")

    key = generate_deterministic_rsa_keypair(password_plain, context, bits)
    private_pem = key.export_key().decode("utf-8")
    public_pem = key.publickey().export_key().decode("utf-8")
    return private_pem, public_pem


def derive_public_key_b64_from_password(password_plain: str, context: str, bits: int = 2048) -> str:
    _private_pem, public_pem = derive_rsa_keypair_from_password(password_plain, context, bits)
    return public_key_pem_to_b64(public_pem)


def public_key_pem_to_b64(public_pem: str) -> str:
    key = RSA.import_key(public_pem.encode("utf-8"))
    der = key.publickey().export_key(format="DER")
    return base64.b64encode(der).decode("ascii")


def public_key_b64_to_key(public_key_b64: str) -> RSA.RsaKey:
    der = base64.b64decode(public_key_b64)
    return RSA.import_key(der)


def _normalize_rsa_key(key_or_pem: Union[str, RSA.RsaKey]) -> RSA.RsaKey:
    if isinstance(key_or_pem, str):
        return RSA.import_key(key_or_pem.encode("utf-8"))
    return key_or_pem


def rsa_encrypt_text_to_b64(plain_text: str, rsa_key: Union[str, RSA.RsaKey]) -> str:
    key = _normalize_rsa_key(rsa_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    cipher_bytes = cipher.encrypt(plain_text.encode("utf-8"))
    return base64.b64encode(cipher_bytes).decode("ascii")


def rsa_decrypt_b64_to_text(cipher_text_b64: str, rsa_key: Union[str, RSA.RsaKey]) -> str:
    key = _normalize_rsa_key(rsa_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    plain_bytes = cipher.decrypt(base64.b64decode(cipher_text_b64))
    return plain_bytes.decode("utf-8")


def build_insert_nhanvien_payload(
    manv: str,
    hoten: str,
    email: str,
    luongcb: str,
    tendn: str,
    matkhau_plain: str,
    vaitro: str,
) -> Dict[str, str]:
    rsa_key = generate_deterministic_rsa_keypair(matkhau_plain, manv)
    public_pem = rsa_key.publickey().export_key().decode("utf-8")

    return {
        "MANV": manv,
        "HOTEN": hoten,
        "EMAIL": email,
        "LUONG": rsa_encrypt_text_to_b64(luongcb, rsa_key),
        "TENDN": tendn,
        "MK": sha512_hex(matkhau_plain),
        "PUB": public_key_pem_to_b64(public_pem),
        "VAITRO": vaitro,
    }


def build_change_password_payload(
    manv: str,
    old_password: str,
    new_password: str,
    encrypted_luong_b64_from_db: str,
) -> Dict[str, str]:
    old_key = generate_deterministic_rsa_keypair(old_password, manv)
    luong_plain = rsa_decrypt_b64_to_text(encrypted_luong_b64_from_db, old_key)

    new_key = generate_deterministic_rsa_keypair(new_password, manv)
    new_luong_b64 = rsa_encrypt_text_to_b64(luong_plain, new_key)
    new_pub_pem = new_key.publickey().export_key().decode("utf-8")

    return {
        "MANV": manv,
        "OLD_MK_HASH": sha512_hex(old_password),
        "NEW_MK_HASH": sha512_hex(new_password),
        "NEW_PUBKEY": public_key_pem_to_b64(new_pub_pem),
        "NEW_LUONG": new_luong_b64,
    }
