import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# used pyCryptodome documentation to get started: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes

data = 'transmit secret data hehe'.encode()

# encrypt
aesKey = get_random_bytes(16)
hmacKey = get_random_bytes(16)

cipher = AES.new(aesKey, AES.MODE_CTR)
ciphertext = cipher.encrypt(data)

hmac = HMAC.new(hmacKey, digestmod=SHA256)
tag = hmac.update(cipher.nonce + ciphertext).digest()

with open("encrypted.bin", "wb") as f:
    f.write(tag)
    f.write(cipher.nonce)
    f.write(ciphertext)
    print("Message encoded")

# decrypt
with open("encrypted.bin", "rb") as f:
    tag = f.read(32)
    nonce = f.read(8)
    ciphertext = f.read()
    print("Message decoded")

try:
    hmac = HMAC.new(hmacKey, digestmod=SHA256)
    tag = hmac.update(nonce + ciphertext).verify(tag)
except ValueError:
    print("Message modified")
    sys.exit(1)

cipher = AES.new(aesKey, AES.MODE_CTR, nonce = nonce)
message = cipher.decrypt(ciphertext)
print("Message:, ", message.decode())