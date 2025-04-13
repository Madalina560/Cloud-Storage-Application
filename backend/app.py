from io import BytesIO
from flask import Flask, render_template, request, redirect, send_file, url_for, session
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# file uploading & downloading tutorial followed:
# https://www.geeksforgeeks.org/uploading-and-downloading-files-in-flask/

# encryption and decryption example used:
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-and-authenticate-data-in-one-step:~:text=.decode())-,Encrypt%20and%20authenticate%20data%20in%20one%20step,-%C2%B6


app = Flask(__name__)
app.secret_key = 'secretKeyforSession'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref = db.backref('uploads', lazy = True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), unique = True, nullable = False)
    password = db.Column(db.String(80), nullable = False)
    aesKey = db.Column(db.LargeBinary(16), nullable = False)
'''
def createUser(username):
    aesKey = get_random_bytes(16)
    user = User(username = username, aesKey = aesKey)
    db.session.add(user)
    db.session.commit()
    # potentially no longer need
'''

@app.route('/')
def loginPage():
    return render_template('index.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        file = request.files['file']
        #upload = Upload(filename = file.filename, data = file.read())

        userID = session.get('user_id')
        user = User.query.get(userID)
        if not user:
            return "User not logged in", 401
        plainData = file.read()

        # setting up cipher & ciphertext 
        cipher = AES.new(user.aesKey, AES.MODE_OCB)
        ciphertext, tag = cipher.encrypt_and_digest(plainData)
        assert len(cipher.nonce) == 15

        # putting together encrypted data + uploading it
        encryptedData = tag + cipher.nonce + ciphertext
        encryptUpload = Upload(filename = file.filename + ".enc", data = encryptedData, user = user)

        # add encrypted file to db
        db.session.add(encryptUpload)
        db.session.commit()
        return redirect('/home')
    files = Upload.query.all()
    # show frontend
    return render_template('home.html', files = files)

@app.route('/download/<upload_id>')
def download_file(upload_id):
    upload = Upload.query.filter_by(id = upload_id).first()
    user = upload.user

    binary = upload.data
    tag = binary[:16]
    nonce = binary[16:31]
    ciphertext = binary[31:]
    
    cipher = AES.new(user.aesKey, AES.MODE_OCB, nonce = nonce)

    try:
        decryptedData = cipher.decrypt_and_verify(ciphertext, tag)
        originalFile = upload.filename.replace('.enc', '')
        return send_file(BytesIO(decryptedData), download_name=originalFile, as_attachment=True)

    
    except ValueError:
        print("File Modified")
        return "Decryption failed, File may have been tampered with.", 400


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    alreadyExists = User.query.filter_by(username = username).first()
    if alreadyExists:
        return "User already exists", 400
    
    aesKey = get_random_bytes(16)
    user = User(username = username, password = password, aesKey = aesKey)
    db.session.add(user)
    db.session.commit()
    session['user_id'] = user.id
    return redirect(url_for('home'))

@app.route('/login', methods = ['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username = username, password = password).first()
    if user and password:
        session['user_id'] = user.id
        return redirect(url_for('home'))
    return "Invalid username or password", 401

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)