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