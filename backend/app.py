from io import BytesIO
from flask import Flask, render_template, request, redirect, send_file, url_for, session, g
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

# class to create File upload table
class Upload(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref = db.backref('uploads', lazy = True))

# class to create User table
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), unique = True, nullable = False)
    password = db.Column(db.String(80), nullable = False)
    aesKey = db.Column(db.LargeBinary(16), nullable = False)

# route to login & register page
@app.route('/')
def loginPage():
    return render_template('index.html')

# route to file uploading page
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        file = request.files['file']

        # prevents non logged in user from uploading
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
    if g.user is None:
        return redirect('/login') # go back to login if no user
    
    # find file user is trying to download in the database
    upload = Upload.query.filter_by(id = upload_id).first()
    if not upload or upload.userID != g.user.id:
        return "No permission to download, Not logged in to correct account", 403
    user = upload.user

    # read in files as binary, and extract tag, nonce and ciphertext
    binary = upload.data
    tag = binary[:16]
    nonce = binary[16:31]
    ciphertext = binary[31:]
    
    # create cipher with user's AES key
    cipher = AES.new(user.aesKey, AES.MODE_OCB, nonce = nonce)

    try:
        # decrypt and authenticate data
        decryptedData = cipher.decrypt_and_verify(ciphertext, tag)
        # replace .enc extention
        originalFile = upload.filename.replace('.enc', '')
        # download file to device
        return send_file(BytesIO(decryptedData), download_name=originalFile, as_attachment=True)

    # return error if file has been tampered with
    except ValueError:
        print("File Modified")
        return "Decryption failed, File may have been tampered with.", 400


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    # if user exists, forbid creation of that same user
    alreadyExists = User.query.filter_by(username = username).first()
    if alreadyExists:
        return "User already exists", 400
    
    # create user's AES key
    aesKey = get_random_bytes(16)
    user = User(username = username, password = password, aesKey = aesKey)
    # add user to User table
    db.session.add(user)
    db.session.commit()
    # collect user's ID during session
    session['user_id'] = user.id
    return redirect(url_for('home'))

@app.route('/login', methods = ['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # find user in the User table
    user = User.query.filter_by(username = username, password = password).first()
    # allow them to login if user and password exist
    if user and password:
        session['user_id'] = user.id
        return redirect(url_for('home'))
    return "Invalid username or password", 401

# login helper
@app.before_request
def loadUser():
    userID = session.get('user_id')
    if userID:
        g.user = User.query.get(userID)
    else:
        g.user = None

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)