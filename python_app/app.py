import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime
import pyodbc


# ADD(d): Chinh sua chuoi ket noi cho phu hop may cua ban.
CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=QLSVNhom;"
    "Trusted_Connection=yes;"
)


# ADD(UI): Theme xanh - trang cho toan bo ung dung.
COLORS = {
    "bg": "#f3f7ff",
    "card": "#ffffff",
    "primary": "#0a66cc",
    "primary_dark": "#084d9c",
    "accent": "#dbeafe",
    "text": "#113355",
    "muted": "#47607f",
    "table_header": "#eaf2ff",
}


def setup_styles(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")

    root.configure(bg=COLORS["bg"])

    style.configure("App.TFrame", background=COLORS["bg"])
    style.configure("Card.TFrame", background=COLORS["card"], relief="flat")

    style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 10))
    style.configure("Card.TLabel", background=COLORS["card"], foreground=COLORS["text"], font=("Segoe UI", 10))
    style.configure(
        "Title.TLabel",
        background=COLORS["card"],
        foreground=COLORS["primary_dark"],
        font=("Segoe UI", 17, "bold"),
    )
    style.configure("Subtitle.TLabel", background=COLORS["card"], foreground=COLORS["muted"], font=("Segoe UI", 10))

    style.configure(
        "Primary.TButton",
        background=COLORS["primary"],
        foreground="#ffffff",
        borderwidth=0,
        focusthickness=3,
        focuscolor=COLORS["accent"],
        padding=(12, 8),
        font=("Segoe UI", 10, "bold"),
    )
    style.map(
        "Primary.TButton",
        background=[("active", COLORS["primary_dark"]), ("pressed", COLORS["primary_dark"])],
        foreground=[("disabled", "#c9d3e2")],
    )

    style.configure(
        "Ghost.TButton",
        background=COLORS["card"],
        foreground=COLORS["primary_dark"],
        bordercolor=COLORS["accent"],
        padding=(10, 7),
        font=("Segoe UI", 10),
    )
    style.map("Ghost.TButton", background=[("active", COLORS["accent"])])

    style.configure(
        "TEntry",
        fieldbackground="#ffffff",
        foreground=COLORS["text"],
        bordercolor="#b9c9de",
        insertcolor=COLORS["primary_dark"],
        padding=(6, 5),
    )
    style.configure(
        "TCombobox",
        fieldbackground="#ffffff",
        foreground=COLORS["text"],
        bordercolor="#b9c9de",
        arrowsize=14,
        padding=(4, 4),
    )

    style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
    style.configure("TNotebook.Tab", background=COLORS["accent"], foreground=COLORS["primary_dark"], padding=(14, 8))
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLORS["card"]), ("active", "#cfe5ff")],
        foreground=[("selected", COLORS["primary_dark"])],
    )

    style.configure(
        "Treeview",
        background="#ffffff",
        fieldbackground="#ffffff",
        foreground=COLORS["text"],
        rowheight=28,
        bordercolor="#d7e3f6",
        lightcolor="#d7e3f6",
        darkcolor="#d7e3f6",
    )
    style.map("Treeview", background=[("selected", "#c9e1ff")], foreground=[("selected", COLORS["primary_dark"])])
    style.configure(
        "Treeview.Heading",
        background=COLORS["table_header"],
        foreground=COLORS["primary_dark"],
        relief="flat",
        font=("Segoe UI", 10, "bold"),
    )
    style.map("Treeview.Heading", background=[("active", "#dceaff")])


class DatabaseError(Exception):
    pass


class Database:
    def __init__(self, conn_str: str):
        self.conn_str = conn_str

    def _connect(self):
        return pyodbc.connect(self.conn_str)

    def execute_proc(self, proc_name: str, params: list, fetch: bool):
        placeholders = ", ".join(["?"] * len(params))
        sql = f"EXEC {proc_name} {placeholders}" if placeholders else f"EXEC {proc_name}"

        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(sql, params)

                rows = []
                if fetch and cur.description is not None:
                    cols = [c[0] for c in cur.description]
                    for row in cur.fetchall():
                        rows.append({cols[i]: row[i] for i in range(len(cols))})

                conn.commit()
                return rows
        except pyodbc.Error as ex:
            raise DatabaseError(str(ex)) from ex


class LoginFrame(ttk.Frame):
    def __init__(self, master, on_login_success, db: Database):
        super().__init__(master, padding=24, style="App.TFrame")
        self.on_login_success = on_login_success
        self.db = db
        self._build_ui()

    def _build_ui(self):
        # ADD(UI): Bo cuc login full-screen gom panel trai + card dang nhap ben phai.
        container = tk.Frame(self, bg=COLORS["bg"], bd=0, highlightthickness=0)
        container.pack(fill="both", expand=True)

        left = tk.Frame(container, bg=COLORS["primary"], bd=0, highlightthickness=0)
        left.pack(side="left", fill="both", expand=True)

        tk.Label(
            left,
            text="Quan Ly Sinh Vien",
            bg=COLORS["primary"],
            fg="#ffffff",
            font=("Segoe UI", 24, "bold"),
        ).pack(anchor="w", padx=42, pady=(88, 8))

        tk.Label(
            left,
            text="Dang nhap tai khoan nhan vien de quan ly\nlop hoc, sinh vien va bang diem.",
            justify="left",
            bg=COLORS["primary"],
            fg="#d9eaff",
            font=("Segoe UI", 12),
        ).pack(anchor="w", padx=42)

        right = tk.Frame(container, bg=COLORS["bg"], bd=0, highlightthickness=0)
        right.pack(side="right", fill="both", expand=True)

        card = ttk.Frame(right, style="Card.TFrame", padding=24)
        card.pack(expand=True, fill="x", padx=70, pady=90)

        ttk.Label(card, text="Dang nhap", style="Title.TLabel").grid(row=0, column=0, columnspan=2, pady=(0, 2), sticky="w")
        ttk.Label(card, text="Su dung MANV va MATKHAU", style="Subtitle.TLabel").grid(
            row=1, column=0, columnspan=2, pady=(0, 18), sticky="w"
        )

        ttk.Label(card, text="MANV", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        self.manv_var = tk.StringVar()
        ttk.Entry(card, textvariable=self.manv_var, width=30).grid(row=2, column=1, sticky="ew", pady=4)

        ttk.Label(card, text="MATKHAU", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=4)
        self.mk_var = tk.StringVar()
        ttk.Entry(card, textvariable=self.mk_var, width=30, show="*").grid(row=3, column=1, sticky="ew", pady=4)

        ttk.Button(card, text="Dang nhap", style="Primary.TButton", command=self._login).grid(
            row=4, column=0, columnspan=2, pady=(14, 0), sticky="ew"
        )

        card.columnconfigure(1, weight=1)

    def _login(self):
        manv = self.manv_var.get().strip()
        mk = self.mk_var.get().strip()

        if not manv or not mk:
            messagebox.showwarning("Thong bao", "Vui long nhap MANV va MATKHAU.")
            return

        try:
            rows = self.db.execute_proc("dbo.SP_LOGIN_NHANVIEN", [manv, mk], fetch=True)
            if not rows:
                messagebox.showerror("Dang nhap that bai", "Sai MANV hoac MATKHAU.")
                return

            self.on_login_success(rows[0], mk)
        except DatabaseError as ex:
            messagebox.showerror("Loi dang nhap", str(ex))


class MainFrame(ttk.Frame):
    def __init__(self, master, db: Database, employee: dict, login_password: str, on_logout):
        super().__init__(master, padding=12, style="App.TFrame")
        self.db = db
        self.employee = employee
        self.login_password = login_password
        self.on_logout = on_logout

        self.manv = str(employee["MANV"])

        self._managed_classes = []
        self._current_students = []

        self._build_ui()
        self.refresh_classes()

    def _build_ui(self):
        # ADD(UI): Header xanh dam giup nhan dien thong tin nhan vien dang nhap.
        header = tk.Frame(self, bg=COLORS["primary"], height=70, bd=0, highlightthickness=0)
        header.pack(fill="x", pady=(0, 12))
        header.pack_propagate(False)

        tk.Label(
            header,
            text="He thong Quan ly Sinh vien",
            bg=COLORS["primary"],
            fg="#ffffff",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=18, pady=(10, 0))

        title = f"Nhan vien: {self.employee['MANV']} - {self.employee['HOTEN']}"
        tk.Label(
            header,
            text=title,
            bg=COLORS["primary"],
            fg="#e8f1ff",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=18, pady=(2, 0))

        logout_btn = tk.Button(
            header,
            text="Dang xuat",
            command=self.handle_logout,
            bg="#ffffff",
            fg=COLORS["primary_dark"],
            activebackground="#eaf2ff",
            activeforeground=COLORS["primary_dark"],
            relief="flat",
            padx=12,
            pady=4,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
        )
        logout_btn.place(relx=1.0, x=-18, y=19, anchor="ne")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self.class_tab = ttk.Frame(self.notebook, padding=12, style="Card.TFrame")
        self.student_tab = ttk.Frame(self.notebook, padding=12, style="Card.TFrame")
        self.grade_tab = ttk.Frame(self.notebook, padding=12, style="Card.TFrame")

        self.notebook.add(self.class_tab, text="Quan ly lop")
        self.notebook.add(self.student_tab, text="Sinh vien theo lop")
        self.notebook.add(self.grade_tab, text="Nhap bang diem")

        self._build_class_tab()
        self._build_student_tab()
        self._build_grade_tab()

    # ADD(d): Tab Quan ly lop
    def _build_class_tab(self):
        form = ttk.Frame(self.class_tab, style="Card.TFrame")
        form.pack(fill="x")

        self.lop_malop_var = tk.StringVar()
        self.lop_tenlop_var = tk.StringVar()

        ttk.Label(form, text="MALOP", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.lop_malop_var, width=16).grid(row=0, column=1, sticky="w", pady=4)

        ttk.Label(form, text="TENLOP", style="Card.TLabel").grid(row=0, column=2, sticky="w", padx=(12, 8), pady=4)
        ttk.Entry(form, textvariable=self.lop_tenlop_var, width=28).grid(row=0, column=3, sticky="w", pady=4)

        btns = ttk.Frame(self.class_tab, style="Card.TFrame")
        btns.pack(fill="x", pady=(8, 8))
        ttk.Button(btns, text="Them", style="Primary.TButton", command=self.add_class).pack(side="left")
        ttk.Button(btns, text="Cap nhat", style="Ghost.TButton", command=self.update_class).pack(side="left", padx=6)
        ttk.Button(btns, text="Xoa", style="Ghost.TButton", command=self.delete_class).pack(side="left", padx=6)
        ttk.Button(btns, text="Tai lai", style="Ghost.TButton", command=self.refresh_classes).pack(side="left", padx=6)

        self.class_tree = ttk.Treeview(
            self.class_tab,
            columns=("MALOP", "TENLOP", "MANV"),
            show="headings",
            height=12,
        )
        for col, w in (("MALOP", 120), ("TENLOP", 260), ("MANV", 120)):
            self.class_tree.heading(col, text=col)
            self.class_tree.column(col, width=w, anchor="w")
        self.class_tree.pack(fill="both", expand=True)
        self.class_tree.bind("<<TreeviewSelect>>", self.on_class_select)

    # ADD(d): Tab Sinh vien theo lop
    def _build_student_tab(self):
        top = ttk.Frame(self.student_tab, style="Card.TFrame")
        top.pack(fill="x", pady=(0, 8))

        ttk.Label(top, text="Lop", style="Card.TLabel").pack(side="left")
        self.student_class_var = tk.StringVar()
        self.student_class_combo = ttk.Combobox(top, textvariable=self.student_class_var, width=18, state="readonly")
        self.student_class_combo.pack(side="left", padx=8)
        self.student_class_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_students())

        ttk.Button(top, text="Tai sinh vien", style="Ghost.TButton", command=self.refresh_students).pack(side="left")

        form = ttk.Frame(self.student_tab, style="Card.TFrame")
        form.pack(fill="x")

        self.sv_masv = tk.StringVar()
        self.sv_hoten = tk.StringVar()
        self.sv_ngaysinh = tk.StringVar()
        self.sv_diachi = tk.StringVar()
        self.sv_tendn = tk.StringVar()
        self.sv_mk = tk.StringVar()

        ttk.Label(form, text="MASV", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.sv_masv, width=16).grid(row=0, column=1, sticky="w", padx=(0, 10), pady=4)

        ttk.Label(form, text="HOTEN", style="Card.TLabel").grid(row=0, column=2, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.sv_hoten, width=24).grid(row=0, column=3, sticky="w", padx=(0, 10), pady=4)

        ttk.Label(form, text="NGAYSINH (YYYY-MM-DD)", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.sv_ngaysinh, width=16).grid(row=1, column=1, sticky="w", padx=(0, 10), pady=4)

        ttk.Label(form, text="DIACHI", style="Card.TLabel").grid(row=1, column=2, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.sv_diachi, width=24).grid(row=1, column=3, sticky="w", padx=(0, 10), pady=4)

        ttk.Label(form, text="TENDN", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.sv_tendn, width=16).grid(row=2, column=1, sticky="w", padx=(0, 10), pady=4)

        ttk.Label(form, text="MK moi (bo trong neu khong doi)", style="Card.TLabel").grid(row=2, column=2, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.sv_mk, width=24, show="*").grid(row=2, column=3, sticky="w", padx=(0, 10), pady=4)

        btns = ttk.Frame(self.student_tab, style="Card.TFrame")
        btns.pack(fill="x", pady=(8, 8))
        ttk.Button(btns, text="Them SV", style="Primary.TButton", command=self.add_student).pack(side="left")
        ttk.Button(btns, text="Cap nhat SV", style="Ghost.TButton", command=self.update_student).pack(side="left", padx=6)
        ttk.Button(btns, text="Xoa SV", style="Ghost.TButton", command=self.delete_student).pack(side="left", padx=6)

        self.student_tree = ttk.Treeview(
            self.student_tab,
            columns=("MASV", "HOTEN", "NGAYSINH", "DIACHI", "MALOP", "TENDN"),
            show="headings",
            height=10,
        )
        widths = {
            "MASV": 100,
            "HOTEN": 180,
            "NGAYSINH": 120,
            "DIACHI": 180,
            "MALOP": 100,
            "TENDN": 120,
        }
        for col in ("MASV", "HOTEN", "NGAYSINH", "DIACHI", "MALOP", "TENDN"):
            self.student_tree.heading(col, text=col)
            self.student_tree.column(col, width=widths[col], anchor="w")
        self.student_tree.pack(fill="both", expand=True)
        self.student_tree.bind("<<TreeviewSelect>>", self.on_student_select)

    # ADD(d): Tab Nhap bang diem (diem duoc ma hoa theo Public Key nhan vien dang nhap)
    def _build_grade_tab(self):
        top = ttk.Frame(self.grade_tab, style="Card.TFrame")
        top.pack(fill="x", pady=(0, 8))

        ttk.Label(top, text="Lop", style="Card.TLabel").pack(side="left")
        self.grade_class_var = tk.StringVar()
        self.grade_class_combo = ttk.Combobox(top, textvariable=self.grade_class_var, width=18, state="readonly")
        self.grade_class_combo.pack(side="left", padx=(8, 16))
        self.grade_class_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_grade_students())

        ttk.Label(top, text="Sinh vien", style="Card.TLabel").pack(side="left")
        self.grade_student_var = tk.StringVar()
        self.grade_student_combo = ttk.Combobox(top, textvariable=self.grade_student_var, width=20, state="readonly")
        self.grade_student_combo.pack(side="left", padx=(8, 16))

        ttk.Label(top, text="MAHP", style="Card.TLabel").pack(side="left")
        self.grade_mahp_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.grade_mahp_var, width=10).pack(side="left", padx=(8, 16))

        ttk.Label(top, text="DIEM (0..10)", style="Card.TLabel").pack(side="left")
        self.grade_diem_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.grade_diem_var, width=10).pack(side="left", padx=(8, 16))

        ttk.Button(top, text="Luu diem", style="Primary.TButton", command=self.upsert_grade).pack(side="left")
        ttk.Button(top, text="Tai bang diem", style="Ghost.TButton", command=self.refresh_grade_table).pack(side="left", padx=6)

        self.grade_tree = ttk.Treeview(
            self.grade_tab,
            columns=("MASV", "HOTEN", "MAHP", "DIEMTHI"),
            show="headings",
            height=12,
        )
        for col, w in (("MASV", 110), ("HOTEN", 200), ("MAHP", 110), ("DIEMTHI", 110)):
            self.grade_tree.heading(col, text=col)
            self.grade_tree.column(col, width=w, anchor="w")
        self.grade_tree.pack(fill="both", expand=True)

    def _clear_tree(self, tree: ttk.Treeview):
        for row in tree.get_children():
            tree.delete(row)

    def refresh_classes(self):
        try:
            rows = self.db.execute_proc("dbo.SP_LOP_LIST_BY_MANV", [self.manv], fetch=True)
            self._managed_classes = rows

            self._clear_tree(self.class_tree)
            for r in rows:
                self.class_tree.insert("", "end", values=(r["MALOP"], r["TENLOP"], r["MANV"]))

            class_ids = [r["MALOP"] for r in rows]
            self.student_class_combo["values"] = class_ids
            self.grade_class_combo["values"] = class_ids

            if class_ids:
                if self.student_class_var.get() not in class_ids:
                    self.student_class_var.set(class_ids[0])
                if self.grade_class_var.get() not in class_ids:
                    self.grade_class_var.set(class_ids[0])

                self.refresh_students()
                self.refresh_grade_students()
                self.refresh_grade_table()
            else:
                self.student_class_var.set("")
                self.grade_class_var.set("")
                self.grade_student_var.set("")
                self._clear_tree(self.student_tree)
                self._clear_tree(self.grade_tree)

        except DatabaseError as ex:
            messagebox.showerror("Loi tai lop", str(ex))

    def on_class_select(self, _event):
        selected = self.class_tree.selection()
        if not selected:
            return
        values = self.class_tree.item(selected[0], "values")
        self.lop_malop_var.set(values[0])
        self.lop_tenlop_var.set(values[1])

    def add_class(self):
        malop = self.lop_malop_var.get().strip()
        tenlop = self.lop_tenlop_var.get().strip()
        if not malop or not tenlop:
            messagebox.showwarning("Thieu du lieu", "Nhap MALOP va TENLOP.")
            return

        try:
            self.db.execute_proc("dbo.SP_LOP_INSERT_BY_MANV", [self.manv, malop, tenlop], fetch=False)
            self.refresh_classes()
            messagebox.showinfo("Thong bao", "Them lop thanh cong.")
        except DatabaseError as ex:
            messagebox.showerror("Loi them lop", str(ex))

    def update_class(self):
        malop = self.lop_malop_var.get().strip()
        tenlop = self.lop_tenlop_var.get().strip()
        if not malop or not tenlop:
            messagebox.showwarning("Thieu du lieu", "Nhap MALOP va TENLOP.")
            return

        try:
            self.db.execute_proc("dbo.SP_LOP_UPDATE_BY_MANV", [self.manv, malop, tenlop], fetch=False)
            self.refresh_classes()
            messagebox.showinfo("Thong bao", "Cap nhat lop thanh cong.")
        except DatabaseError as ex:
            messagebox.showerror("Loi cap nhat lop", str(ex))

    def delete_class(self):
        malop = self.lop_malop_var.get().strip()
        if not malop:
            messagebox.showwarning("Thieu du lieu", "Nhap MALOP can xoa.")
            return

        if not messagebox.askyesno("Xac nhan", f"Xoa lop {malop}?"):
            return

        try:
            self.db.execute_proc("dbo.SP_LOP_DELETE_BY_MANV", [self.manv, malop], fetch=False)
            self.refresh_classes()
            messagebox.showinfo("Thong bao", "Xoa lop thanh cong.")
        except DatabaseError as ex:
            messagebox.showerror("Loi xoa lop", str(ex))

    def _parse_date_or_none(self, raw: str):
        raw = raw.strip()
        if not raw:
            return None
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d")
            return dt
        except ValueError as ex:
            raise ValueError("Ngay sinh dung dinh dang YYYY-MM-DD") from ex

    def refresh_students(self):
        malop = self.student_class_var.get().strip()
        if not malop:
            self._clear_tree(self.student_tree)
            return

        try:
            rows = self.db.execute_proc("dbo.SP_SINHVIEN_LIST_BY_LOP_MANV", [self.manv, malop], fetch=True)
            self._current_students = rows
            self._clear_tree(self.student_tree)

            for r in rows:
                self.student_tree.insert(
                    "",
                    "end",
                    values=(
                        r["MASV"],
                        r["HOTEN"],
                        str(r["NGAYSINH"])[:10] if r["NGAYSINH"] else "",
                        r["DIACHI"] or "",
                        r["MALOP"],
                        r["TENDN"],
                    ),
                )
        except DatabaseError as ex:
            messagebox.showerror("Loi tai sinh vien", str(ex))

    def on_student_select(self, _event):
        selected = self.student_tree.selection()
        if not selected:
            return
        values = self.student_tree.item(selected[0], "values")
        self.sv_masv.set(values[0])
        self.sv_hoten.set(values[1])
        self.sv_ngaysinh.set(values[2])
        self.sv_diachi.set(values[3])
        self.sv_tendn.set(values[5])

    def add_student(self):
        malop = self.student_class_var.get().strip()
        masv = self.sv_masv.get().strip()
        hoten = self.sv_hoten.get().strip()
        ngaysinh_raw = self.sv_ngaysinh.get().strip()
        diachi = self.sv_diachi.get().strip()
        tendn = self.sv_tendn.get().strip()
        mk = self.sv_mk.get().strip()

        if not all([malop, masv, hoten, tendn, mk]):
            messagebox.showwarning("Thieu du lieu", "Can nhap MALOP, MASV, HOTEN, TENDN, MK.")
            return

        try:
            ngaysinh = self._parse_date_or_none(ngaysinh_raw)
            self.db.execute_proc(
                "dbo.SP_SINHVIEN_INSERT_BY_MANV",
                [self.manv, masv, hoten, ngaysinh, diachi, malop, tendn, mk],
                fetch=False,
            )
            self.refresh_students()
            self.refresh_grade_students()
            messagebox.showinfo("Thong bao", "Them sinh vien thanh cong.")
        except (DatabaseError, ValueError) as ex:
            messagebox.showerror("Loi them sinh vien", str(ex))

    def update_student(self):
        malop = self.student_class_var.get().strip()
        masv = self.sv_masv.get().strip()
        hoten = self.sv_hoten.get().strip()
        ngaysinh_raw = self.sv_ngaysinh.get().strip()
        diachi = self.sv_diachi.get().strip()
        tendn = self.sv_tendn.get().strip()
        mk = self.sv_mk.get().strip()

        if not all([malop, masv, hoten, tendn]):
            messagebox.showwarning("Thieu du lieu", "Can nhap MALOP, MASV, HOTEN, TENDN.")
            return

        try:
            ngaysinh = self._parse_date_or_none(ngaysinh_raw)
            mk_value = mk if mk else None
            self.db.execute_proc(
                "dbo.SP_SINHVIEN_UPDATE_BY_MANV",
                [self.manv, masv, hoten, ngaysinh, diachi, malop, tendn, mk_value],
                fetch=False,
            )
            self.refresh_students()
            self.refresh_grade_students()
            messagebox.showinfo("Thong bao", "Cap nhat sinh vien thanh cong.")
        except (DatabaseError, ValueError) as ex:
            messagebox.showerror("Loi cap nhat sinh vien", str(ex))

    def delete_student(self):
        masv = self.sv_masv.get().strip()
        if not masv:
            messagebox.showwarning("Thieu du lieu", "Nhap MASV can xoa.")
            return

        if not messagebox.askyesno("Xac nhan", f"Xoa sinh vien {masv}?"):
            return

        try:
            self.db.execute_proc("dbo.SP_SINHVIEN_DELETE_BY_MANV", [self.manv, masv], fetch=False)
            self.refresh_students()
            self.refresh_grade_students()
            self.refresh_grade_table()
            messagebox.showinfo("Thong bao", "Xoa sinh vien thanh cong.")
        except DatabaseError as ex:
            messagebox.showerror("Loi xoa sinh vien", str(ex))

    def refresh_grade_students(self):
        malop = self.grade_class_var.get().strip()
        if not malop:
            self.grade_student_combo["values"] = []
            self.grade_student_var.set("")
            return

        try:
            rows = self.db.execute_proc("dbo.SP_SINHVIEN_LIST_BY_LOP_MANV", [self.manv, malop], fetch=True)
            student_values = [f"{r['MASV']} - {r['HOTEN']}" for r in rows]
            self.grade_student_combo["values"] = student_values
            if student_values:
                self.grade_student_var.set(student_values[0])
            else:
                self.grade_student_var.set("")
        except DatabaseError as ex:
            messagebox.showerror("Loi tai sinh vien", str(ex))

    def upsert_grade(self):
        selected_student = self.grade_student_var.get().strip()
        mahp = self.grade_mahp_var.get().strip()
        diem_raw = self.grade_diem_var.get().strip()

        if not selected_student or not mahp or not diem_raw:
            messagebox.showwarning("Thieu du lieu", "Can chon sinh vien, nhap MAHP va DIEM.")
            return

        masv = selected_student.split(" - ")[0].strip()

        try:
            diem = float(diem_raw)
        except ValueError:
            messagebox.showwarning("Sai du lieu", "DIEM phai la so.")
            return

        try:
            self.db.execute_proc("dbo.SP_BANGDIEM_UPSERT_BY_MANV", [self.manv, masv, mahp, diem], fetch=False)
            self.refresh_grade_table()
            messagebox.showinfo("Thong bao", "Luu diem thanh cong (da ma hoa theo public key cua nhan vien dang nhap).")
        except DatabaseError as ex:
            messagebox.showerror("Loi luu diem", str(ex))

    def refresh_grade_table(self):
        malop = self.grade_class_var.get().strip()
        if not malop:
            self._clear_tree(self.grade_tree)
            return

        try:
            rows = self.db.execute_proc(
                "dbo.SP_BANGDIEM_LIST_BY_MANV",
                [self.manv, self.login_password, malop],
                fetch=True,
            )
            self._clear_tree(self.grade_tree)
            for r in rows:
                self.grade_tree.insert(
                    "",
                    "end",
                    values=(r["MASV"], r["HOTEN"], r["MAHP"], r["DIEMTHI"]),
                )
        except DatabaseError as ex:
            messagebox.showerror("Loi tai bang diem", str(ex))

    def handle_logout(self):
        if messagebox.askyesno("Xac nhan", "Ban muon dang xuat?"):
            self.on_logout()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("QLSVNhom - nhom 2")
        self.geometry("1100x720")
        self.minsize(980, 620)

        setup_styles(self)

        self.db = Database(CONN_STR)

        self.current_frame = None
        self._show_login()

    def _switch_frame(self, frame: ttk.Frame):
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = frame
        self.current_frame.pack(fill="both", expand=True)

    def _show_login(self):
        login_frame = LoginFrame(self, self._on_login_success, self.db)
        self._switch_frame(login_frame)

    def _on_login_success(self, employee: dict, login_password: str):
        main_frame = MainFrame(self, self.db, employee, login_password, self._show_login)
        self._switch_frame(main_frame)


if __name__ == "__main__":
    app = App()
    app.mainloop()
