import os, hashlib, random, string, time
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "your_secret_key"
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

USERS = {}        # username: {password: ..., email: ..., key: ...}
FILES = {}        # username: [{filename, hash, enc_filename}]
OTP = {}          # username: {"code": ..., "expires": ...}

# Tạo key cho mã hóa file
def get_user_key(username):
    if "key" not in USERS[username]:
        USERS[username]["key"] = Fernet.generate_key()
    return USERS[username]["key"]

# Hàm mã hóa file
def encrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    enc_filename = "enc_" + os.path.basename(filepath)
    enc_path = os.path.join(UPLOAD_FOLDER, enc_filename)
    with open(enc_path, "wb") as f:
        f.write(encrypted)
    return enc_filename

def decrypt_file(enc_path, key):
    with open(enc_path, "rb") as f:
        enc_data = f.read()
    fernet = Fernet(key)
    return fernet.decrypt(enc_data)

# Sinh mã OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@app.route("/", methods=["GET"])
def home():
    if "user" in session and session.get("verified"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        if username in USERS:
            flash("Username đã tồn tại!")
            return redirect(url_for("register"))
        USERS[username] = {"password": password, "email": email, "key": Fernet.generate_key()}
        FILES[username] = []
        flash("Đăng ký thành công! Đăng nhập để tiếp tục.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if USERS.get(username, {}).get("password") == password:
            otp_code = generate_otp()
            OTP[username] = {"code": otp_code, "expires": time.time() + 180}
            session["tmp_user"] = username
            # Demo: Hiện OTP luôn trên web (bản thực tế thì gửi email)
            flash(f"Nhập mã OTP: {otp_code} (demo, sẽ hết hạn sau 3 phút)")
            return redirect(url_for("otp_verify"))
        flash("Sai thông tin đăng nhập!")
    return render_template("login.html")

@app.route("/otp_verify", methods=["GET", "POST"])
def otp_verify():
    if "tmp_user" not in session:
        return redirect(url_for("login"))
    username = session["tmp_user"]
    if request.method == "POST":
        code = request.form["otp"]
        otp_info = OTP.get(username)
        if otp_info and otp_info["code"] == code and time.time() < otp_info["expires"]:
            session["user"] = username
            session["verified"] = True
            session.pop("tmp_user")
            flash("Đăng nhập thành công!")
            return redirect(url_for("dashboard"))
        flash("Mã OTP không đúng hoặc đã hết hạn.")
    return render_template("otp_verify.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("verified", None)
    session.pop("tmp_user", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session or not session.get("verified"):
        return redirect(url_for("login"))
    user = session["user"]
    user_files = FILES.get(user, [])
    return render_template("dashboard.html", files=user_files, username=user)

@app.route("/upload", methods=["POST"])
def upload():
    if "user" not in session or not session.get("verified"):
        return redirect(url_for("login"))
    if "file" not in request.files:
        flash("No file uploaded!")
        return redirect(url_for("dashboard"))
    file = request.files["file"]
    if file.filename == "":
        flash("No file selected!")
        return redirect(url_for("dashboard"))
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    file_hash = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
    user = session["user"]
    key = get_user_key(user)
    enc_filename = encrypt_file(filepath, key)
    FILES[user].append({"filename": filename, "hash": file_hash, "enc_filename": enc_filename})
    os.remove(filepath) # Xóa file gốc, chỉ lưu file mã hóa
    flash(f"Đã upload và mã hóa file, ký số SHA256: {file_hash[:10]}...")
    return redirect(url_for("dashboard"))

@app.route("/download/<enc_filename>")
def download(enc_filename):
    if "user" not in session or not session.get("verified"):
        return redirect(url_for("login"))
    user = session["user"]
    # Tìm file đúng user
    file_entry = next((f for f in FILES[user] if f["enc_filename"] == enc_filename), None)
    if not file_entry:
        flash("Không tìm thấy file.")
        return redirect(url_for("dashboard"))
    key = get_user_key(user)
    enc_path = os.path.join(UPLOAD_FOLDER, enc_filename)
    decrypted = decrypt_file(enc_path, key)
    response = app.response_class(decrypted, mimetype="application/octet-stream")
    response.headers.set("Content-Disposition", "attachment", filename=file_entry["filename"])
    return response

if __name__ == "__main__":
    app.run(debug=True)