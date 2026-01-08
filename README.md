# 📄 File Authentication & AES Encryption/Decryption

A Python project for securely authenticating and encrypting files using AES encryption and file verification — ideal for cybersecurity applications and secure file storage.

## 🚀 Overview

This project allows you to:

✔ Authenticate files using secure checks
✔ Encrypt files using AES (Advanced Encryption Standard)
✔ Decrypt encrypted files with the correct key
✔ Prevent tampering with integrity checks

Built with **Python** and uses AES encryption (via `pycryptodome`/similar libraries) for strong, real-world file security.

---

## 🧠 Features

* 🔐 **AES Encryption** — Strong symmetric encryption
* 📂 **File Authentication** — Verifies file integrity
* 🪪 **Encrypt & Decrypt** — Easy CLI or programmatic interface
* 🛡️ **Secure Key Handling** — Use passphrases or keys safely
* ⚙️ Supports binary & text files

---

## 🛠️ Installation

1. **Clone the project**

```bash
git clone https://github.com/Ajay16code/File_Authentication.git
cd File_Authentication
```

2. **Create a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

---

## 🧰 Usage

### 🔑 Encrypt a File

```bash
python app.py encrypt --file myfile.txt --key "YourStrongPassphrase"
```

Outputs:
✔ Encrypted file (e.g., `myfile_encrypted.bin`)
✔ Authentication tag for integrity

---

### 🔓 Decrypt a File

```bash
python app.py decrypt --file myfile_encrypted.bin --key "YourStrongPassphrase"
```

Outputs:
✔ Decrypted file (restored original)

---

## 📁 Example

Use this project to:

| Operation       | Command                                                    |
| --------------- | ---------------------------------------------------------- |
| Encrypt file    | `python app.py encrypt --file secret.txt --key MyPass1234` |
| Decrypt file    | `python app.py decrypt --file secret.bin --key MyPass1234` |
| Check integrity | via returned authentication tag                            |

---

## 📦 File Structure

```
File_Authentication/
├── app.py
├── static/
├── templates/
├── encrypted_file.bin
├── requirements.txt
└── README.md
```

---

## 🧩 Dependencies

Install the following (example):

```
pycryptodome
flask (if included)
werkzeug
```

(Ensure your `requirements.txt` lists them)

---

## 🧪 Notes

✔ The AES implementation must use secure modes (e.g., CBC, GCM)
✔ Always protect encryption keys and don’t expose them publicly
✔ File authentication helps detect tampering

---

## 📄 License

This project is open-source and free to use.

---


[1]: https://github.com/Ajay16code/File_Authentication.git "GitHub - Ajay16code/File_Authentication"
