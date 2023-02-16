#!/usr/bin/env python3
import sys
import argparse
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad

parser = argparse.ArgumentParser(description = 'Decrypt an ansible-vault encrypted file')
parser.add_argument('-f', '--file', type=str, required=True)
parser.add_argument('-p', '--password', type=str, required=True)

args = parser.parse_args()

with open(args.file) as f:
    data = ''.join(f.read().splitlines()[1:])

salt, hmac, ct = bytes.fromhex(data).decode().splitlines()

def generateKeys(password, salt):
    keys = PBKDF2(password, salt, 32 + 32 + 16, count=10000, hmac_hash_module=SHA256)
    # drop middle key used by HMAC
    return keys[:32], keys[64:80]

key, iv = generateKeys(args.password.encode(), bytes.fromhex(salt))

cipher = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b'')
pt = cipher.decrypt(bytes.fromhex(ct))
print(unpad(pt, 16).decode())
