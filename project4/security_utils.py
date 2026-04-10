"""
security_utils.py
-----------------
- Mật khẩu + MANV tạo seed SHA-512 (MANV đóng vai trò như Salt).
- Seed chạy qua ChaCha20 tạo luồng random vô tận để feed vào RSA.generate.
- Export public key để lưu DB.
- Hỗ trợ Pipeline đổi mật khẩu.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Dict, Union

from Crypto.Cipher import ChaCha20, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def sha512_hex(plain_text: str) -> str:
    """Hash chuỗi bằng SHA-512 và trả về hex string viết hoa (128 ký tự)."""
    return hashlib.sha512(plain_text.encode("utf-8")).hexdigest().upper()

def get_deterministic_randfunc(password: str, manv: str):
    """
    Kết hợp Mật khẩu + MANV (Salt) -> SHA-512 tạo seed, 
    bơm vào ChaCha20 để tạo hàm pseudo-random cho thư viện RSA
    """
    # Nối password và manv lại với nhau để làm hạt giống
    combined_material = f"{password}{manv}"
    seed_bytes = hashlib.sha512(combined_material.encode("utf-8")).digest() # 64 bytes
    
    key = seed_bytes[:32]      # 256-bit key cho ChaCha20
    nonce = seed_bytes[32:40]  # 64-bit nonce cho ChaCha20

    # Khởi tạo bộ sinh luồng ChaCha20
    cipher = ChaCha20.new(key=key, nonce=nonce)

    def randfunc(n: int) -> bytes:
        # Mã hóa chuỗi byte rỗng để lấy keystream giả ngẫu nhiên liên tục
        return cipher.encrypt(b'\x00' * n)

    return randfunc

def generate_deterministic_rsa_keypair(password: str, manv: str, bits: int = 2048) -> RSA.RsaKey:
    """Tạo khóa RSA cố định (deterministic) dựa trên password và MANV."""
    randfunc = get_deterministic_randfunc(password, manv)
    # RSA.generate sẽ cắt tuần tự luồng byte từ randfunc để tìm p và q
    key = RSA.generate(bits, randfunc=randfunc)
    return key

def public_key_pem_to_b64(public_pem: str) -> str:
    key = RSA.import_key(public_pem.encode("utf-8"))
    der = key.publickey().export_key(format="DER")
    return base64.b64encode(der).decode("ascii")

def rsa_encrypt_text_to_b64(plain_text: str, rsa_key: RSA.RsaKey) -> str:
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    cipher_bytes = cipher.encrypt(plain_text.encode("utf-8"))
    return base64.b64encode(cipher_bytes).decode("ascii")

def rsa_decrypt_b64_to_text(cipher_text_b64: str, rsa_key: RSA.RsaKey) -> str:
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    plain_bytes = cipher.decrypt(base64.b64decode(cipher_text_b64))
    return plain_bytes.decode("utf-8")

def build_insert_nhanvien_payload(
    manv: str, hoten: str, email: str, luongcb: str, tendn: str, matkhau_plain: str, vaitro: str
) -> Dict[str, str]:
    """Tạo payload gọi SP_INS_PUBLIC_ENCRYPT_NHANVIEN"""
    # Truyền thêm manv vào hàm tạo key
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
        "VAITRO": vaitro
    }

def build_change_password_payload(
    manv: str, old_password: str, new_password: str, encrypted_luong_b64_from_db: str
) -> Dict[str, str]:
    """
    PIPELINE ĐỔI MẬT KHẨU: 
    1. Lấy khóa cũ -> Giải mã lương. 
    2. Tạo khóa mới -> Mã hóa lại lương.
    """
    # 1. Giải mã bằng Private Key cũ (Cần truyền manv)
    old_key = generate_deterministic_rsa_keypair(old_password, manv)
    luong_plain = rsa_decrypt_b64_to_text(encrypted_luong_b64_from_db, old_key)

    # 2. Tạo Private/Public Key mới (Cần truyền manv) và mã hóa lại lương
    new_key = generate_deterministic_rsa_keypair(new_password, manv)
    new_luong_b64 = rsa_encrypt_text_to_b64(luong_plain, new_key)
    new_pub_pem = new_key.publickey().export_key().decode("utf-8")

    return {
        "MANV": manv,
        "OLD_MK_HASH": sha512_hex(old_password),
        "NEW_MK_HASH": sha512_hex(new_password),
        "NEW_PUBKEY": public_key_pem_to_b64(new_pub_pem),
        "NEW_LUONG": new_luong_b64
    }

if __name__ == "__main__":
    # --- UTILITY: SINH MÃ SQL CHO FILE 04_seed_and_tests_lab04.sql ---
    # Chạy đoạn này để in ra các lệnh EXEC với PubKey và Luong chuẩn từ Hash Deterministic
    
    nhanviens = [
        ("NV11", "Nguyen Van An", "nv11@fit.vn", "15000000", "nvan", "DbSec@P@ss01", "ADMIN"),
        ("NV12", "Tran Thi Binh", "nv12@fit.vn", "12000000", "tbinh", "DbSec@P@ss02", "USER"),
        ("NV13", "Le Quang Huy", "nv13@fit.vn", "10000000", "lqhuy", "DbSec@P@ss03", "USER"),
    ]

    #print("/* PASTE NHỮNG LỆNH NÀY VÀO 04_seed_and_tests_lab04.sql */\n")
    for nv in nhanviens:
        p = build_insert_nhanvien_payload(nv[0], nv[1], nv[2], nv[3], nv[4], nv[5], nv[6])
        print(f"EXEC dbo.SP_INS_PUBLIC_ENCRYPT_NHANVIEN\n"
              f"    '{p['MANV']}',\n"
              f"    N'{p['HOTEN']}',\n"
              f"    '{p['EMAIL']}',\n"
              f"    '{p['LUONG']}',\n"
              f"    N'{p['TENDN']}',\n"
              f"    '{p['MK']}',\n"
              f"    '{p['PUB']}',\n"
              f"    '{p['VAITRO']}';\n")
