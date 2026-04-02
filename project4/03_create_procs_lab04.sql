USE QLSVNhom;
GO

/*
SP_INS_PUBLIC_ENCRYPT_NHANVIEN
- Không hash password trong SQL.
- Không mã hóa RSA trong SQL.
- Chỉ nhận dữ liệu ĐÃ xử lý từ client rồi lưu xuống DB.
- @MK là SHA-512 hex string do client gửi lên.
- @LUONG là ciphertext RSA-2048 Base64 do client gửi lên.
- @PUB là public key RSA-2048 Base64 (DER/SPKI) do client gửi lên.
*/

CREATE OR ALTER PROCEDURE dbo.SP_INS_PUBLIC_ENCRYPT_NHANVIEN
    @MANV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @EMAIL      VARCHAR(100),
    @LUONG      VARCHAR(500),
    @TENDN      NVARCHAR(100),
    @MK         VARCHAR(128),
    @PUB        VARCHAR(500)
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

    IF NULLIF(LTRIM(RTRIM(@LUONG)), '') IS NULL
        THROW 50005, N'LUONG không được rỗng.', 1;

    IF NULLIF(LTRIM(RTRIM(@PUB)), '') IS NULL
        THROW 50006, N'PUB không được rỗng.', 1;

    /*
    Chặn xung đột MANV / TENDN để proc select có thể hỗ trợ cả TENDN lẫn MANV
    mà không bị mơ hồ vì đề lab ví dụ truyền @MANV dù danh sách tham số ghi @TENDN.
    */
    IF EXISTS (SELECT 1 FROM dbo.NHANVIEN WHERE MANV = @MANV OR TENDN = @MANV)
        THROW 50007, N'MANV đã tồn tại hoặc bị xung đột với TENDN hiện có.', 1;

    IF EXISTS (SELECT 1 FROM dbo.NHANVIEN WHERE TENDN = @TENDN OR MANV = @TENDN)
        THROW 50008, N'TENDN đã tồn tại hoặc bị xung đột với MANV hiện có.', 1;

    DECLARE @MK_BIN VARBINARY(64) = TRY_CONVERT(VARBINARY(64), @MK, 2);

    IF @MK_BIN IS NULL OR DATALENGTH(@MK_BIN) <> 64
        THROW 50009, N'MK phải là SHA-512 hex string hợp lệ (128 ký tự hex).', 1;

    INSERT INTO dbo.NHANVIEN (MANV, HOTEN, EMAIL, LUONG, TENDN, MATKHAU, PUBKEY)
    VALUES (@MANV, @HOTEN, @EMAIL, @LUONG, @TENDN, @MK_BIN, @PUB);
END
GO

/*
SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
- Xác thực bằng TENDN/MANV + SHA-512 hash từ client.
- Trả LUONG vẫn ở dạng ciphertext Base64.
- Client tự dùng private key local để giải mã.
*/
CREATE OR ALTER PROCEDURE dbo.SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
    @TENDN    NVARCHAR(100),
    @MK       VARCHAR(128)
AS
BEGIN
    SET NOCOUNT ON;

    IF NULLIF(LTRIM(RTRIM(@TENDN)), '') IS NULL
        THROW 50010, N'TENDN/MANV không được rỗng.', 1;

    IF NULLIF(LTRIM(RTRIM(@MK)), '') IS NULL
        THROW 50011, N'MK không được rỗng.', 1;

    DECLARE @MK_BIN VARBINARY(64) = TRY_CONVERT(VARBINARY(64), @MK, 2);

    IF @MK_BIN IS NULL OR DATALENGTH(@MK_BIN) <> 64
        THROW 50012, N'MK phải là SHA-512 hex string hợp lệ (128 ký tự hex).', 1;

    DECLARE @Matched TABLE
    (
        MANV   VARCHAR(20),
        HOTEN  NVARCHAR(100),
        EMAIL  VARCHAR(100),
        LUONG  VARCHAR(500)
    );

    INSERT INTO @Matched (MANV, HOTEN, EMAIL, LUONG)
    SELECT MANV, HOTEN, EMAIL, LUONG
    FROM dbo.NHANVIEN
    WHERE (TENDN = @TENDN OR MANV = @TENDN)
      AND MATKHAU = @MK_BIN;

    DECLARE @RowCount INT;
    SELECT @RowCount = COUNT(*) FROM @Matched;

    IF @RowCount = 0
        THROW 50013, N'Sai thông tin đăng nhập hoặc không tìm thấy nhân viên.', 1;

    IF @RowCount > 1
        THROW 50014, N'Dữ liệu bị mơ hồ do xung đột MANV/TENDN.', 1;

    SELECT TOP (1)
        MANV,
        HOTEN,
        EMAIL,
        LUONG
    FROM @Matched;
END
GO
