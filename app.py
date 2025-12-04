from flask import Flask, request, render_template, send_file
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask_cors import CORS
import hashlib
import pyotp
import qrcode
import base64
from io import BytesIO

app = Flask(__name__)
CORS(app)  # simple CORS for local demo


# ---------- helpers ----------

def aes_encrypt(data: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(b'\x00' * 16),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(data: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(b'\x00' * 16),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()


# ---------- routes ----------

@app.route("/")
def index():
    # generate secret + QR for TOTP
    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret)
    otp_uri = totp.provisioning_uri(name='AES Demo',
                                    issuer_name='Furious Chargers')

    img = qrcode.make(otp_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template("index.html",
                           qr_image=qr_b64,
                           otp_secret=otp_secret)


@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    password = request.form.get("password", "")

    if not file or not password:
        return "Missing file or password", 400

    encrypted = aes_encrypt(file.read(), password)

    out = BytesIO(encrypted)
    out.seek(0)

    return send_file(
        out,
        as_attachment=True,
        download_name=file.filename + ".enc",
        mimetype="application/octet-stream"
    )


@app.route("/decrypt", methods=["POST"])
def decrypt():
    enc_file = request.files.get("encrypted_file")
    password = request.form.get("decryption_password", "")
    otp = request.form.get("otp", "")
    secret = request.headers.get("dp")  # 2FA secret from front-end

    if not enc_file or not password or not otp or not secret:
        return "Missing data", 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(otp):
        return "Invalid OTP", 400

    try:
        decrypted = aes_decrypt(enc_file.read(), password)
    except Exception:
        return "Decryption failed (wrong password or file)", 400

    out = BytesIO(decrypted)
    out.seek(0)

    return send_file(
        out,
        as_attachment=True,
        download_name="decrypted_file.txt",
        mimetype="text/plain"
    )


if __name__ == "__main__":
    app.run(debug=True)
