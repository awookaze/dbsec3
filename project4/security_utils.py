"""
security_utils.py
-----------------
- Hash password bằng SHA-512
- Tạo cặp khóa RSA 2048
- Export public key để lưu DB
- Encrypt / decrypt LUONG, DIEMTHI ở client
- Chuyển đổi bytes <-> string để gửi vào SQL Server

pip install pycryptodome
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Dict, Union

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def sha512_hex(plain_text: str) -> str:
    """Hash chuỗi bằng SHA-512 và trả về hex string viết hoa (128 ký tự)."""
    if plain_text is None:
        raise ValueError("plain_text cannot be None")
    return hashlib.sha512(plain_text.encode("utf-8")).hexdigest().upper()


def generate_rsa_keypair(bits: int = 2048) -> tuple[str, str]:
    """Tạo cặp khóa RSA và trả về (private_pem, public_pem)."""
    key = RSA.generate(bits)
    private_pem = key.export_key().decode("utf-8")
    public_pem = key.publickey().export_key().decode("utf-8")
    return private_pem, public_pem


def save_keypair(private_pem: str, public_pem: str, private_path: Union[str, Path], public_path: Union[str, Path]) -> None:
    Path(private_path).write_text(private_pem, encoding="utf-8")
    Path(public_path).write_text(public_pem, encoding="utf-8")


def load_private_key(private_path: Union[str, Path]) -> RSA.RsaKey:
    return RSA.import_key(Path(private_path).read_text(encoding="utf-8"))


def load_public_key(public_path: Union[str, Path]) -> RSA.RsaKey:
    return RSA.import_key(Path(public_path).read_text(encoding="utf-8"))


def public_key_pem_to_b64(public_pem: str) -> str:
    """
    Convert public key PEM -> Base64 DER/SPKI để lưu trong SQL Server.
    Đây là format nên lưu vào cột PUBKEY.
    """
    key = RSA.import_key(public_pem.encode("utf-8"))
    der = key.publickey().export_key(format="DER")
    return base64.b64encode(der).decode("ascii")


def public_key_b64_to_key(public_key_b64: str) -> RSA.RsaKey:
    """Convert Base64 DER/SPKI từ DB -> RSA public key object."""
    der = base64.b64decode(public_key_b64)
    return RSA.import_key(der)


def rsa_encrypt_text_to_b64(plain_text: str, public_key: Union[str, RSA.RsaKey]) -> str:
    """
    Mã hóa text bằng RSA-2048 OAEP-SHA256 rồi trả Base64 string.
    public_key có thể là:
    - PEM string
    - RSA key object
    """
    if isinstance(public_key, str):
        key = RSA.import_key(public_key.encode("utf-8"))
    else:
        key = public_key

    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    cipher_bytes = cipher.encrypt(plain_text.encode("utf-8"))
    return base64.b64encode(cipher_bytes).decode("ascii")


def rsa_decrypt_b64_to_text(cipher_text_b64: str, private_key: Union[str, RSA.RsaKey]) -> str:
    """
    Giải mã Base64 ciphertext bằng private key local.
    private_key có thể là:
    - PEM string
    - RSA key object
    """
    if isinstance(private_key, str):
        key = RSA.import_key(private_key.encode("utf-8"))
    else:
        key = private_key

    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    plain_bytes = cipher.decrypt(base64.b64decode(cipher_text_b64))
    return plain_bytes.decode("utf-8")


def build_insert_nhanvien_payload(
    manv: str,
    hoten: str,
    email: str,
    luongcb: Union[int, float, str],
    tendn: str,
    matkhau_plain: str,
    private_key_path: Union[str, Path],
    public_key_path: Union[str, Path],
) -> Dict[str, str]:
    """
    Chuẩn bị đúng 7 tham số để call SP_INS_PUBLIC_ENCRYPT_NHANVIEN:
    MANV, HOTEN, EMAIL, LUONG, TENDN, MK, PUB
    """
    public_key = load_public_key(public_key_path)
    public_pem = Path(public_key_path).read_text(encoding="utf-8")

    return {
        "MANV": manv,
        "HOTEN": hoten,
        "EMAIL": email,
        "LUONG": rsa_encrypt_text_to_b64(str(luongcb), public_key),
        "TENDN": tendn,
        "MK": sha512_hex(matkhau_plain),
        "PUB": public_key_pem_to_b64(public_pem),
    }


def decrypt_salary_from_db(cipher_text_b64: str, private_key_path: Union[str, Path]) -> str:
    """Nhận LUONG từ DB và giải mã bằng private key local."""
    private_key = load_private_key(private_key_path)
    return rsa_decrypt_b64_to_text(cipher_text_b64, private_key)


if __name__ == "__main__":
    # Demo local nhanh
    private_pem, public_pem = generate_rsa_keypair()
    sample_hash = sha512_hex("mkNV11")
    sample_pub_b64 = public_key_pem_to_b64(public_pem)
    sample_cipher = rsa_encrypt_text_to_b64("12000000", public_pem)
    sample_plain = rsa_decrypt_b64_to_text(sample_cipher, private_pem)

    print("SHA512:", sample_hash)
    print("PUBKEY_B64:", sample_pub_b64[:60] + "...")
    print("LUONG_B64:", sample_cipher[:60] + "...")
    print("DECRYPTED:", sample_plain)
