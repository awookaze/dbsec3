# Vinh - Lab 67-63

- **SHA-512** cho mật khẩu
- **RSA 2048** cho lương / điểm thi
- **Public key lưu trong database**
- **Private key không lưu trong database**, chỉ giữ local (zalo)

## File chính

1. `01_create_db_lab04.sql`
2. `02_create_tables_lab04.sql`
3. `03_create_procs_lab04.sql`
4. `04_seed_and_tests_lab04.sql`
5. `security_utils.py`

## Chạy theo thứ tự

1. Chạy `01_create_db_lab04.sql`
2. Chạy `02_create_tables_lab04.sql`
3. Chạy `03_create_procs_lab04.sql`
4. Chạy `04_seed_and_tests_lab04.sql`

## App layer

### Stored procedure insert
`SP_INS_PUBLIC_ENCRYPT_NHANVIEN`

Tham số:
- `@MANV` : mã nhân viên
- `@HOTEN` : họ tên
- `@EMAIL` : email
- `@LUONG` : ciphertext RSA-2048 Base64, mã hóa từ client
- `@TENDN` : tên đăng nhập
- `@MK` : SHA-512 hex string, hash từ client
- `@PUB` : public key RSA-2048 Base64 (DER/SPKI), tạo từ client

### Stored procedure select
`SP_SEL_PUBLIC_ENCRYPT_NHANVIEN`

Tham số:
- `@TENDN` : login bằng TENDN hoặc MANV
- `@MK` : SHA-512 hex string từ client

Kết quả trả về:
- `MANV`
- `HOTEN`
- `EMAIL`
- `LUONG` (vẫn là ciphertext Base64, client tự giải mã bằng private key local)
