from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#simple_key = get_random_bytes(32)
#print(simple_key)
salt = b"\x9c\xddQghr\x06W)'\xe1\xeb0a=5\xaa\x17\xef\xc8\xf3\xb5\x1f\x1e\xb2\x85t\xf4a\x1e^\xe8"
password = "admin"

key = PBKDF2(password, salt, dkLen=32)

def encryption():
    with open('db.txt', 'rb') as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))

    with open('db.bin', 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphered_data)

def decryption():
    with open('db.bin', 'rb') as f:
        # initialization vector
        iv = f.read(16)
        decrypt_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original = unpad(cipher.decrypt(decrypt_data), AES.block_size)

    with open('db.txt', 'wb') as f:
        f.write(original)