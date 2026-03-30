# dbsec3

## 1) Thu tu chay script

Chay theo dung thu tu:

1. `01_create_db.sql`
2. `02_create_tables.sql`
3. `03_create_procs.sql`
4. `04_seed_and_tests.sql`

## 2) Cac bang va cot chinh

### `dbo.NHANVIEN`

| Cot | Kieu du lieu | Rang buoc / y nghia |
|---|---|---|
| `MANV` | `VARCHAR(20)` | PK |
| `HOTEN` | `NVARCHAR(100)` | NOT NULL |
| `EMAIL` | `VARCHAR(20)` | NULL |
| `LUONG` | `VARBINARY(MAX)` | Luong da ma hoa RSA_2048 |
| `TENDN` | `NVARCHAR(100)` | UNIQUE, NOT NULL |
| `MATKHAU` | `VARBINARY(32)` | `SHA2_256(MK)` |
| `PUBKEY` | `VARCHAR(20)` | UNIQUE, luon = `MANV` |

### `dbo.LOP`

| Cot | Kieu du lieu | Rang buoc / y nghia |
|---|---|---|
| `MALOP` | `VARCHAR(20)` | PK |
| `TENLOP` | `NVARCHAR(100)` | NOT NULL |
| `MANV` | `VARCHAR(20)` | FK -> `NHANVIEN(MANV)` |

### `dbo.HOCPHAN`

| Cot | Kieu du lieu | Rang buoc / y nghia |
|---|---|---|
| `MAHP` | `VARCHAR(20)` | PK |
| `TENHP` | `NVARCHAR(100)` | NOT NULL |
| `SOTC` | `INT` | CHECK > 0 |

### `dbo.SINHVIEN`

| Cot | Kieu du lieu | Rang buoc / y nghia |
|---|---|---|
| `MASV` | `VARCHAR(20)` | PK |
| `HOTEN` | `NVARCHAR(100)` | NOT NULL |
| `NGAYSINH` | `DATETIME` | NULL |
| `DIACHI` | `NVARCHAR(200)` | NULL |
| `MALOP` | `VARCHAR(20)` | FK -> `LOP(MALOP)` |
| `TENDN` | `NVARCHAR(100)` | UNIQUE, NOT NULL |
| `MATKHAU` | `VARBINARY(32)` | SHA2_256 |

### `dbo.BANGDIEM`

| Cot | Kieu du lieu | Rang buoc / y nghia |
|---|---|---|
| `MASV` | `VARCHAR(20)` | PK(1), FK -> `SINHVIEN(MASV)` |
| `MAHP` | `VARCHAR(20)` | PK(2), FK -> `HOCPHAN(MAHP)` |
| `DIEMTHI` | `VARBINARY(MAX)` | Diem da ma hoa |

## 3) Rule nhap lieu quan trong

- `NHANVIEN.MANV`, `HOTEN`, `TENDN`, `MK` khong duoc rong khi goi SP insert.
- `LUONGCB` phai `>= 0`.
- `TENDN` trong `NHANVIEN` la unique.
- `TENDN` trong `SINHVIEN` la unique.
- `PUBKEY` luon bang `MANV`.
- Chan xung dot `MANV/TENDN` de tranh truy van ngu.

## 4) Stored procedure contract

### `dbo.SP_INS_PUBLIC_NHANVIEN`

Input:

- `@MANV VARCHAR(20)`
- `@HOTEN NVARCHAR(100)`
- `@EMAIL VARCHAR(20)`
- `@LUONGCB BIGINT`
- `@TENDN NVARCHAR(100)`
- `@MK NVARCHAR(128)`

Xu ly:

- Tao asymmetric key ten = `MANV`, thuat toan `RSA_2048`, password = `MK`.
- `HASHBYTES('SHA2_256', MK)` -> `MATKHAU`.
- `ENCRYPTBYASYMKEY(public key cua MANV, LUONGCB)` -> `LUONG`.
- `PUBKEY = MANV`.

Output:

- Khong tra rowset. Thanh cong thi insert 1 dong vao `NHANVIEN`.

### `dbo.SP_SEL_PUBLIC_NHANVIEN`

Input:

- `@TENDN NVARCHAR(100)`
- `@MK NVARCHAR(128)`

Luu y:

- Du ten tham so la `@TENDN`, script hien ho tro truyen `TENDN` hoac `MANV`.
- Ly do: de bai mau thuan giua mo ta tham so va vi du `EXEC`.

Output rowset:

- `MANV`
- `HOTEN`
- `EMAIL`
- `LUONGCB` (da giai ma)

## 5) Tai khoan test

- `NV11 / nvan / mkNV11`
- `NV12 / tbinh / mkNV12`
- `NV13 / lqhuy / mkNV13`
- `NV14 / pmkhoa / mkNV14`
- `NV15 / vtlong / mkNV15`

## 6) Seed va test script

- Script `04_seed_and_tests.sql` cleanup toan bo du lieu cac bang theo thu tu phu thuoc FK, sau do seed lai du lieu mau.
- Mat khau `SINHVIEN` duoc bam bang `SHA2_256`.
- Du lieu `BANGDIEM.DIEMTHI` duoc ma hoa bang public key RSA_2048 cua nhan vien quan ly lop.
- Script giu lai cac check dem so dong va 1 lenh test giai ma qua SP.

## 7) Query test mau

```sql
-- Lay thong tin nhan vien theo username
EXEC dbo.SP_SEL_PUBLIC_NHANVIEN N'nvan', N'mkNV11';
GO

-- Lay thong tin nhan vien theo MANV (duoc ho tro)
EXEC dbo.SP_SEL_PUBLIC_NHANVIEN N'NV11', N'mkNV11';
GO

-- Xem lop do nhan vien quan ly
SELECT MALOP, TENLOP, MANV
FROM dbo.LOP
WHERE MANV = 'NV11';
GO

-- Xem danh sach sinh vien cua mot lop
SELECT MASV, HOTEN, NGAYSINH, DIACHI, MALOP, TENDN
FROM dbo.SINHVIEN
WHERE MALOP = 'L01';
GO

-- Xem bang diem dang ma hoa (raw)
SELECT MASV, MAHP, DIEMTHI
FROM dbo.BANGDIEM
WHERE MASV = 'SV01';
GO

-- Test loi sai mat khau giai ma
-- EXEC dbo.SP_SEL_PUBLIC_NHANVIEN N'nvan', N'saiMK';
GO
```

## 8) ADD(d) - Stored procedure cho man hinh quan ly

Da bo sung them trong `03_create_procs.sql` (co comment `ADD(d)`):

- `dbo.SP_LOGIN_NHANVIEN`: Dang nhap theo `MANV, MATKHAU`.
- `dbo.SP_LOP_LIST_BY_MANV`: Lay danh sach lop do nhan vien quan ly.
- `dbo.SP_LOP_INSERT_BY_MANV`: Them lop moi, lop do nhan vien dang nhap quan ly.
- `dbo.SP_LOP_UPDATE_BY_MANV`: Sua lop (chi lop thuoc nhan vien dang nhap).
- `dbo.SP_LOP_DELETE_BY_MANV`: Xoa lop (chi lop thuoc nhan vien dang nhap, va chua co sinh vien).
- `dbo.SP_SINHVIEN_LIST_BY_LOP_MANV`: Xem sinh vien cua lop thuoc nhan vien dang nhap.
- `dbo.SP_SINHVIEN_INSERT_BY_MANV`: Them sinh vien vao lop nhan vien dang nhap quan ly.
- `dbo.SP_SINHVIEN_UPDATE_BY_MANV`: Sua sinh vien trong pham vi lop nhan vien dang nhap quan ly.
- `dbo.SP_SINHVIEN_DELETE_BY_MANV`: Xoa sinh vien trong pham vi lop nhan vien dang nhap quan ly.
- `dbo.SP_BANGDIEM_UPSERT_BY_MANV`: Them/cap nhat diem thi, diem duoc ma hoa bang Public Key cua nhan vien dang nhap.
- `dbo.SP_BANGDIEM_LIST_BY_MANV`: Xem bang diem da giai ma (trong pham vi lop quan ly).

## 9) ADD(d) - Chuong trinh Python GUI

Thu muc moi: `python_app/`

- `python_app/app.py`: Man hinh dang nhap + quan ly lop + quan ly sinh vien theo lop + nhap bang diem.
- `python_app/requirements.txt`: Dependency Python.

### Cai dat

```bash
cd dbsec3/python_app
pip install -r requirements.txt
```

### Chay

```bash
python app.py
```

Luu y:

- Chinh sua bien `CONN_STR` trong `python_app/app.py` theo SQL Server tren may ban.
- App su dung cac SP trong `03_create_procs.sql`, can chay day du script SQL truoc.