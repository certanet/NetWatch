import base64
import os
from Crypto import Random
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2
from netwatch import app


def pad_data(data):
    # Allow data that is not of blocksize (multiples of 16) to be encrypted
    # The number is 16 as AES has a fixed block size of 128bit (16*8bits)
    if len(data) % 16 == 0:
        return data
    databytes = bytearray(data)
    padding_required = 15 - (len(databytes) % 16)
    databytes.extend(b'\x80')
    databytes.extend(b'\x00' * padding_required)
    return bytes(databytes)


def unpad_data(data):
    if not data:
        return data

    data = data.rstrip(b'\x00')
    if data[-1] == 128:  # b'\x80'[0]:
        return data[:-1]
    else:
        return data


def encrypt(pt, salt, password=app.config['SECRET_KEY']):
    password_enc = password.encode('utf-8')
    pt_enc = pad_data(pt.encode('utf-8'))

    # The key lengths avaialbe for AES are 128/192/256
    # So 32 here is AES256 (32*8bits)
    key = PBKDF2(password_enc, salt).read(32)  # 256-bit key
    iv = Random.new().read(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = iv + cipher.encrypt(pt_enc)

    ct_enc = base64.b64encode(ct)
    return ct_enc


def decrypt(ct, salt, password=app.config['SECRET_KEY']):
    password_enc = password.encode('utf-8')

    try:
        ct_dec = base64.b64decode(ct.decode())
    except:
        return "ERROR: CT looks invalid"

    key = PBKDF2(password_enc, salt).read(32)  # 256-bit key
    iv = ct_dec[:AES.block_size]

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
    except:
        return "ERROR: Decryption error, check CT"

    pt = cipher.decrypt(ct_dec[AES.block_size:])

    try:
        pt_dec = unpad_data(pt).decode('utf-8')
    except:
        return "ERROR: Decryption error, check password or salt"

    return pt_dec


def generate_salt():
    print("Generating Salt...")
    return str(os.urandom(8))  # 64-bit salt
