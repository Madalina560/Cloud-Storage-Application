from io import BytesIO
from flask import Flask, render_template, request, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

# file uploading & downloading tutorial followed:
# https://www.geeksforgeeks.org/uploading-and-downloading-files-in-flask/

# encryption and decryption example used:
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-and-authenticate-data-in-one-step:~:text=.decode())-,Encrypt%20and%20authenticate%20data%20in%20one%20step,-%C2%B6

aesKey = get_random_bytes(16)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        upload = Upload(filename = file.filename, data = file.read())
        # setting up cipher & ciphertext 
        cipher = AES.new(aesKey, AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(upload.data)
        assert len(cipher.nonce) == 15

        # putting together encrypted data + uploading it
        encryptedData = tag + cipher.nonce + ciphertext
        encryptUpload = Upload(filename = file.filename + ".enc", data = encryptedData)

        db.session.add(encryptUpload)  # add encrypted file to db
        db.session.commit()
        return redirect('/')
    files = Upload.query.all()
    return render_template('index.html', files = files)

@app.route('/download/<upload_id>')
def download_file(upload_id):
    upload = Upload.query.filter_by(id = upload_id).first()

    binary = upload.data
    tag = binary[:16]
    nonce = binary[16:31]
    ciphertext = binary[31:]
    
    cipher = AES.new(aesKey, AES.MODE_OCB, nonce = nonce)

    try:
        decryptedData = cipher.decrypt_and_verify(ciphertext, tag)
        originalFile = upload.filename.replace('.enc', '')
        return send_file(BytesIO(decryptedData), download_name=originalFile, as_attachment=True)

    
    except ValueError:
        print("File Modified")
        return "Decryption failed, File may have been tampered with.", 400

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)