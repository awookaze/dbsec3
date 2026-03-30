USE QLSVNhom;
GO

CREATE OR ALTER PROCEDURE dbo.SP_INS_PUBLIC_NHANVIEN
    @MANV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @EMAIL      VARCHAR(20),
    @LUONGCB    BIGINT,
    @TENDN      NVARCHAR(100),
    @MK         NVARCHAR(128)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF NULLIF(LTRIM(RTRIM(@MANV)), '') IS NULL
        THROW 50001, N'MANV không được rỗng.', 1;

    IF NULLIF(LTRIM(RTRIM(@HOTEN)), '') IS NULL
        THROW 50002, N'HOTEN không được rỗng.', 1;

    IF NULLIF(LTRIM(RTRIM(@TENDN)), '') IS NULL
        THROW 50003, N'TENDN không được rỗng.', 1;

    IF NULLIF(LTRIM(RTRIM(@MK)), '') IS NULL
        THROW 50004, N'MK không được rỗng.', 1;

    IF @LUONGCB IS NULL OR @LUONGCB < 0
        THROW 50005, N'LUONGCB phải >= 0.', 1;

    IF EXISTS (SELECT 1 FROM dbo.NHANVIEN WHERE MANV = @MANV OR TENDN = @MANV)
        THROW 50006, N'MANV đã tồn tại hoặc bị xung đột với TENDN hiện có.', 1;

    IF EXISTS (SELECT 1 FROM dbo.NHANVIEN WHERE TENDN = @TENDN OR MANV = @TENDN)
        THROW 50007, N'TENDN đã tồn tại hoặc bị xung đột với MANV hiện có.', 1;

    IF EXISTS (SELECT 1 FROM sys.asymmetric_keys WHERE name = @MANV)
        THROW 50008, N'Asymmetric key trùng tên MANV đã tồn tại.', 1;

    DECLARE @sql NVARCHAR(MAX);
    DECLARE @LuongMaHoa VARBINARY(MAX);

    BEGIN TRY
        BEGIN TRAN;

        /* RSA_2048 */
        SET @sql = N'
            CREATE ASYMMETRIC KEY ' + QUOTENAME(@MANV) + N'
            WITH ALGORITHM = RSA_2048
            ENCRYPTION BY PASSWORD = N''' + REPLACE(@MK, '''', '''''') + N''';';

        EXEC sys.sp_executesql @sql;

        SET @LuongMaHoa =
            ENCRYPTBYASYMKEY(ASYMKEY_ID(@MANV), CONVERT(VARBINARY(8), @LUONGCB));

        IF @LuongMaHoa IS NULL
            THROW 50009, N'Mã hóa lương thất bại.', 1;

        /* SHA2_256 */
        INSERT INTO dbo.NHANVIEN (MANV, HOTEN, EMAIL, LUONG, TENDN, MATKHAU, PUBKEY)
        VALUES
        (
            @MANV,
            @HOTEN,
            @EMAIL,
            @LuongMaHoa,
            @TENDN,
            HASHBYTES('SHA2_256', @MK),
            @MANV
        );

        COMMIT TRAN;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0
            ROLLBACK TRAN;

        IF EXISTS (SELECT 1 FROM sys.asymmetric_keys WHERE name = @MANV)
        BEGIN
            BEGIN TRY
                SET @sql = N'DROP ASYMMETRIC KEY ' + QUOTENAME(@MANV) + N';';
                EXEC sys.sp_executesql @sql;
            END TRY
            BEGIN CATCH

            END CATCH
        END;

        THROW;
    END CATCH
END
GO

CREATE OR ALTER PROCEDURE dbo.SP_SEL_PUBLIC_NHANVIEN
    @TENDN    NVARCHAR(100),
    @MK       NVARCHAR(128)
AS
BEGIN
    SET NOCOUNT ON;

    IF NULLIF(LTRIM(RTRIM(@TENDN)), '') IS NULL
        THROW 50010, N'Tham số định danh không được rỗng.', 1;

    IF NULLIF(LTRIM(RTRIM(@MK)), '') IS NULL
        THROW 50011, N'MK không được rỗng.', 1;

    DECLARE @Matched TABLE
    (
        MANV    VARCHAR(20),
        HOTEN   NVARCHAR(100),
        EMAIL   VARCHAR(20),
        PUBKEY  VARCHAR(20),
        LUONG   VARBINARY(MAX)
    );

    INSERT INTO @Matched (MANV, HOTEN, EMAIL, PUBKEY, LUONG)
    SELECT MANV, HOTEN, EMAIL, PUBKEY, LUONG
    FROM dbo.NHANVIEN
    WHERE TENDN = @TENDN OR MANV = @TENDN;

    DECLARE @RowCount INT;
    SELECT @RowCount = COUNT(*) FROM @Matched;

    IF @RowCount = 0
        THROW 50012, N'Không tìm thấy nhân viên theo TENDN/MANV.', 1;

    IF @RowCount > 1
        THROW 50013, N'Định danh bị mơ hồ. Dữ liệu đang có xung đột.', 1;

    DECLARE
        @MANV       VARCHAR(20),
        @HOTEN      NVARCHAR(100),
        @EMAIL      VARCHAR(20),
        @PUBKEY     VARCHAR(20),
        @LUONG      VARBINARY(MAX),
        @LUONG_GM   VARBINARY(8000);

    SELECT TOP (1)
        @MANV   = MANV,
        @HOTEN  = HOTEN,
        @EMAIL  = EMAIL,
        @PUBKEY = PUBKEY,
        @LUONG  = LUONG
    FROM @Matched;

    SET @LUONG_GM = DECRYPTBYASYMKEY(ASYMKEY_ID(@PUBKEY), @LUONG, @MK);

    IF @LUONG_GM IS NULL
        THROW 50014, N'Sai MK hoặc không giải mã được lương.', 1;

    SELECT
        @MANV AS MANV,
        @HOTEN AS HOTEN,
        @EMAIL AS EMAIL,
        CONVERT(BIGINT, @LUONG_GM) AS LUONGCB;
END
GO

/* ==============================
   ADD(d) - Login + Quan ly Lop/SinhVien/BangDiem
   ============================== */

/* ADD(d): Dang nhap nhan vien theo MANV + MATKHAU */
CREATE OR ALTER PROCEDURE dbo.SP_LOGIN_NHANVIEN
    @MANV   VARCHAR(20),
    @MK     NVARCHAR(128)
AS
BEGIN
    SET NOCOUNT ON;

    IF NULLIF(LTRIM(RTRIM(@MANV)), '') IS NULL
        THROW 51001, N'MANV khong duoc rong.', 1;

    IF NULLIF(LTRIM(RTRIM(@MK)), '') IS NULL
        THROW 51002, N'Mat khau khong duoc rong.', 1;

    SELECT TOP (1)
        MANV,
        HOTEN,
        EMAIL,
        TENDN,
        PUBKEY
    FROM dbo.NHANVIEN
    WHERE MANV = @MANV
      AND MATKHAU = HASHBYTES('SHA2_256', @MK);

    IF @@ROWCOUNT = 0
        THROW 51003, N'Dang nhap that bai. Sai MANV hoac MATKHAU.', 1;
END
GO

/* ADD(d): Danh sach lop do nhan vien quan ly */
CREATE OR ALTER PROCEDURE dbo.SP_LOP_LIST_BY_MANV
    @MANV VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MALOP, TENLOP, MANV
    FROM dbo.LOP
    WHERE MANV = @MANV
    ORDER BY MALOP;
END
GO

/* ADD(d): Them lop hoc, gan cho chinh nhan vien dang quan ly */
CREATE OR ALTER PROCEDURE dbo.SP_LOP_INSERT_BY_MANV
    @MANV   VARCHAR(20),
    @MALOP  VARCHAR(20),
    @TENLOP NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM dbo.NHANVIEN WHERE MANV = @MANV)
        THROW 51004, N'Nhan vien khong ton tai.', 1;

    IF EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP)
        THROW 51005, N'MALOP da ton tai.', 1;

    INSERT INTO dbo.LOP (MALOP, TENLOP, MANV)
    VALUES (@MALOP, @TENLOP, @MANV);
END
GO

/* ADD(d): Cap nhat lop hoc, chi nhan vien quan ly lop moi duoc sua */
CREATE OR ALTER PROCEDURE dbo.SP_LOP_UPDATE_BY_MANV
    @MANV   VARCHAR(20),
    @MALOP  VARCHAR(20),
    @TENLOP NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP)
        THROW 51006, N'Lop hoc khong ton tai.', 1;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP AND MANV = @MANV)
        THROW 51007, N'Ban khong duoc phep sua lop khong thuoc quan ly cua minh.', 1;

    UPDATE dbo.LOP
    SET TENLOP = @TENLOP
    WHERE MALOP = @MALOP
      AND MANV = @MANV;
END
GO

/* ADD(d): Xoa lop hoc, chi nhan vien quan ly lop moi duoc xoa */
CREATE OR ALTER PROCEDURE dbo.SP_LOP_DELETE_BY_MANV
    @MANV   VARCHAR(20),
    @MALOP  VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP AND MANV = @MANV)
        THROW 51008, N'Ban khong duoc phep xoa lop nay hoac lop khong ton tai.', 1;

    IF EXISTS (SELECT 1 FROM dbo.SINHVIEN WHERE MALOP = @MALOP)
        THROW 51009, N'Khong the xoa lop da co sinh vien.', 1;

    DELETE FROM dbo.LOP
    WHERE MALOP = @MALOP
      AND MANV = @MANV;
END
GO

/* ADD(d): Xem sinh vien cua 1 lop, chi lop thuoc nhan vien quan ly */
CREATE OR ALTER PROCEDURE dbo.SP_SINHVIEN_LIST_BY_LOP_MANV
    @MANV   VARCHAR(20),
    @MALOP  VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP AND MANV = @MANV)
        THROW 51010, N'Ban chi duoc xem sinh vien cua lop do minh quan ly.', 1;

    SELECT
        s.MASV,
        s.HOTEN,
        s.NGAYSINH,
        s.DIACHI,
        s.MALOP,
        s.TENDN
    FROM dbo.SINHVIEN s
    WHERE s.MALOP = @MALOP
    ORDER BY s.MASV;
END
GO

/* ADD(d): Them sinh vien vao lop thuoc nhan vien quan ly */
CREATE OR ALTER PROCEDURE dbo.SP_SINHVIEN_INSERT_BY_MANV
    @MANV      VARCHAR(20),
    @MASV      VARCHAR(20),
    @HOTEN     NVARCHAR(100),
    @NGAYSINH  DATETIME,
    @DIACHI    NVARCHAR(200),
    @MALOP     VARCHAR(20),
    @TENDN     NVARCHAR(100),
    @MK        NVARCHAR(128)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP AND MANV = @MANV)
        THROW 51011, N'Ban chi duoc them sinh vien vao lop minh quan ly.', 1;

    IF EXISTS (SELECT 1 FROM dbo.SINHVIEN WHERE MASV = @MASV)
        THROW 51012, N'MASV da ton tai.', 1;

    IF EXISTS (SELECT 1 FROM dbo.SINHVIEN WHERE TENDN = @TENDN)
        THROW 51013, N'TENDN sinh vien da ton tai.', 1;

    INSERT INTO dbo.SINHVIEN (MASV, HOTEN, NGAYSINH, DIACHI, MALOP, TENDN, MATKHAU)
    VALUES
    (
        @MASV,
        @HOTEN,
        @NGAYSINH,
        @DIACHI,
        @MALOP,
        @TENDN,
        HASHBYTES('SHA2_256', @MK)
    );
END
GO

/* ADD(d): Cap nhat sinh vien, chi sinh vien thuoc lop minh quan ly */
CREATE OR ALTER PROCEDURE dbo.SP_SINHVIEN_UPDATE_BY_MANV
    @MANV      VARCHAR(20),
    @MASV      VARCHAR(20),
    @HOTEN     NVARCHAR(100),
    @NGAYSINH  DATETIME,
    @DIACHI    NVARCHAR(200),
    @MALOP     VARCHAR(20),
    @TENDN     NVARCHAR(100),
    @MK        NVARCHAR(128) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS
    (
        SELECT 1
        FROM dbo.SINHVIEN s
        JOIN dbo.LOP l ON l.MALOP = s.MALOP
        WHERE s.MASV = @MASV
          AND l.MANV = @MANV
    )
        THROW 51014, N'Chi duoc sua sinh vien thuoc lop minh quan ly.', 1;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP AND MANV = @MANV)
        THROW 51015, N'Khong duoc chuyen sinh vien sang lop khong thuoc quan ly.', 1;

    IF EXISTS (SELECT 1 FROM dbo.SINHVIEN WHERE TENDN = @TENDN AND MASV <> @MASV)
        THROW 51016, N'TENDN sinh vien da ton tai.', 1;

    UPDATE dbo.SINHVIEN
    SET HOTEN = @HOTEN,
        NGAYSINH = @NGAYSINH,
        DIACHI = @DIACHI,
        MALOP = @MALOP,
        TENDN = @TENDN,
        MATKHAU = CASE
                    WHEN @MK IS NULL OR LTRIM(RTRIM(@MK)) = '' THEN MATKHAU
                    ELSE HASHBYTES('SHA2_256', @MK)
                  END
    WHERE MASV = @MASV;
END
GO

/* ADD(d): Xoa sinh vien, chi sinh vien thuoc lop minh quan ly */
CREATE OR ALTER PROCEDURE dbo.SP_SINHVIEN_DELETE_BY_MANV
    @MANV   VARCHAR(20),
    @MASV   VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS
    (
        SELECT 1
        FROM dbo.SINHVIEN s
        JOIN dbo.LOP l ON l.MALOP = s.MALOP
        WHERE s.MASV = @MASV
          AND l.MANV = @MANV
    )
        THROW 51017, N'Chi duoc xoa sinh vien thuoc lop minh quan ly.', 1;

    DELETE FROM dbo.BANGDIEM WHERE MASV = @MASV;
    DELETE FROM dbo.SINHVIEN WHERE MASV = @MASV;
END
GO

/* ADD(d): Nhap/cap nhat diem thi ma hoa bang Public Key cua nhan vien dang nhap */
CREATE OR ALTER PROCEDURE dbo.SP_BANGDIEM_UPSERT_BY_MANV
    @MANV      VARCHAR(20),
    @MASV      VARCHAR(20),
    @MAHP      VARCHAR(20),
    @DIEMTHI   DECIMAL(4,2)
AS
BEGIN
    SET NOCOUNT ON;

    IF @DIEMTHI < 0 OR @DIEMTHI > 10
        THROW 51018, N'Diem thi phai trong khoang 0..10.', 1;

    IF NOT EXISTS
    (
        SELECT 1
        FROM dbo.SINHVIEN s
        JOIN dbo.LOP l ON l.MALOP = s.MALOP
        WHERE s.MASV = @MASV
          AND l.MANV = @MANV
    )
        THROW 51019, N'Chi duoc nhap diem cho sinh vien thuoc lop minh quan ly.', 1;

    IF NOT EXISTS (SELECT 1 FROM dbo.HOCPHAN WHERE MAHP = @MAHP)
        THROW 51020, N'MAHP khong ton tai.', 1;

    IF ASYMKEY_ID(@MANV) IS NULL
        THROW 51021, N'Khong tim thay Public Key cua nhan vien dang nhap.', 1;

    DECLARE @DiemMaHoa VARBINARY(MAX);
    SET @DiemMaHoa = ENCRYPTBYASYMKEY(ASYMKEY_ID(@MANV), CONVERT(VARBINARY(16), @DIEMTHI));

    IF @DiemMaHoa IS NULL
        THROW 51022, N'Ma hoa diem thi that bai.', 1;

    IF EXISTS (SELECT 1 FROM dbo.BANGDIEM WHERE MASV = @MASV AND MAHP = @MAHP)
    BEGIN
        UPDATE dbo.BANGDIEM
        SET DIEMTHI = @DiemMaHoa
        WHERE MASV = @MASV
          AND MAHP = @MAHP;
    END
    ELSE
    BEGIN
        INSERT INTO dbo.BANGDIEM (MASV, MAHP, DIEMTHI)
        VALUES (@MASV, @MAHP, @DiemMaHoa);
    END
END
GO

/* ADD(d): Xem diem thi da giai ma (chi xem duoc sinh vien thuoc lop minh quan ly) */
CREATE OR ALTER PROCEDURE dbo.SP_BANGDIEM_LIST_BY_MANV
    @MANV      VARCHAR(20),
    @MK        NVARCHAR(128),
    @MALOP     VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (SELECT 1 FROM dbo.LOP WHERE MALOP = @MALOP AND MANV = @MANV)
        THROW 51023, N'Ban chi duoc xem diem cua lop minh quan ly.', 1;

    SELECT
        s.MASV,
        s.HOTEN,
        b.MAHP,
        CONVERT(DECIMAL(4,2), DECRYPTBYASYMKEY(ASYMKEY_ID(@MANV), b.DIEMTHI, @MK)) AS DIEMTHI
    FROM dbo.BANGDIEM b
    JOIN dbo.SINHVIEN s ON s.MASV = b.MASV
    WHERE s.MALOP = @MALOP
    ORDER BY s.MASV, b.MAHP;
END
GO