import os
import hashlib
import base64
from flask import Flask, request, jsonify, send_from_directory, url_for, render_template
from cryptography.fernet import Fernet

# Initialize Flask app
app = Flask(__name__, template_folder="templates")

# Define the upload folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Function to derive a secure key from user input
def derive_key(user_key):
    return base64.urlsafe_b64encode(hashlib.sha256(user_key.encode()).digest())

# 🏠 **Home Route**
@app.route("/")
def home():
    return render_template("index.html")

# 🔐 **Encrypt File**
@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files.get("file")
    user_key = request.form.get("key")

    if not file or not user_key:
        return jsonify({"success": False, "message": "File or key missing"})

    try:
        cipher = Fernet(derive_key(user_key))
        encrypted_data = cipher.encrypt(file.read())

        filename = f"encrypted_{file.filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        file_url = url_for("download_file", filename=filename, _external=True)
        return jsonify({"success": True, "file_url": file_url})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# 🔓 **Decrypt File**
@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files.get("file")
    user_key = request.form.get("key")

    if not file or not user_key:
        return jsonify({"success": False, "message": "File or key missing"})

    try:
        cipher = Fernet(derive_key(user_key))
        decrypted_data = cipher.decrypt(file.read())

        filename = f"decrypted_{file.filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        with open(filepath, "wb") as f:
            f.write(decrypted_data)

        file_url = url_for("download_file", filename=filename, _external=True)
        return jsonify({"success": True, "file_url": file_url})

    except Exception:
        return jsonify({"success": False, "message": "Wrong key entered or file corrupted"})

# 🔢 **Generate Hash (SHA-256)**
@app.route("/hash", methods=["POST"])
def generate_hash():
    file = request.files.get("file")
    hash_type = request.form.get("hashType")  # Get selected hash type

    if not file:
        return jsonify({"success": False, "message": "File missing"})

    try:
        file.seek(0)  # Reset file pointer before reading
        file_hash = hashlib.sha256(file.read()).hexdigest()
        
        return jsonify({"success": True, "hash": file_hash, "hashType": hash_type})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# 🔐 **Encrypt & Hash**
@app.route("/encrypt-hash", methods=["POST"])
def encrypt_and_hash():
    file = request.files.get("file")
    user_key = request.form.get("key")

    if not file or not user_key:
        return jsonify({"success": False, "message": "File or key missing"})

    try:
        cipher = Fernet(derive_key(user_key))
        encrypted_data = cipher.encrypt(file.read())

        # Compute hash of the encrypted file
        file_hash = hashlib.sha256(encrypted_data).hexdigest()

        filename = f"encrypted_hashed_{file.filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        file_url = url_for("download_file", filename=filename, _external=True)
        return jsonify({"success": True, "file_url": file_url, "hash": file_hash})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# 📂 **Download Files**
@app.route("/uploads/<filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
