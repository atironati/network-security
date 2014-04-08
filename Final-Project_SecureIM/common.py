
BS    = 16
pad   = lambda s : s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

import base64

# crypto libraries
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random # Much stronger than standard python random module

# Encrypt a message using public-key crypto
def public_key_encrypt(msg, pub_key):
    nonce = Random.new().read( 32 )
    iv    = Random.new().read( 16 )

    # Encrypt plaintext using AES symmetric encryption
    plaintext   = pad(msg)
    cipher      = AES.new(nonce, AES.MODE_CBC, iv)
    ciphertext  = base64.b64encode(cipher.encrypt(plaintext))

    # encrypt response key with public key
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted_keys = base64.b64encode(cipher.encrypt(nonce + iv))

    data = [encrypted_keys, ciphertext]
    return data

# Decrypt a message that was encrypted with public-key crypto
def public_key_decrypt(encrypted_keys, ciphertext, priv_key):
    encrypted_keys = base64.b64decode( encrypted_keys )
    ciphertext     = base64.b64decode( ciphertext )

    cipher = PKCS1_OAEP.new(priv_key)
    msg = ""
    try:
        msg_key = cipher.decrypt( encrypted_keys )
    except ValueError:
        print "There was a key error in RSA decryption"
        return None

    # Retrieve AES key and initialization vector
    aes_key  = msg_key[:32]
    iv       = msg_key[32:]

    # Decrypt plaintext using AES
    cipher    = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    msg = plaintext.split(',')
    return msg

# Encrypt using AES
def aes_encrypt(msg, key, iv):
    plaintext   = pad(msg)
    cipher      = AES.new(key, AES.MODE_CBC, iv)
    encoded_msg = base64.b64encode(cipher.encrypt(plaintext))

    return encoded_msg

# Decrypt using AES
def aes_decrypt(msg, key, iv):
    cipher        = AES.new(key, AES.MODE_CBC, iv)
    decrypted_val = base64.b64decode(unpad(cipher.decrypt( msg )))

    return decrypted_val

# Encrypt a message using symmetric crypto
def shared_key_encrypt(msg, shared_key):
    iv    = Random.new().read( 16 )
    plaintext  = pad(msg)
    cipher     = AES.new(shared_key, AES.MODE_CBC, iv)
    ciphertext = base64.b64encode(iv + cipher.encrypt(plaintext))
    return ciphertext

# Decrypt a message using symmetric crypto
def shared_key_decrypt(msg, shared_key):
    ciphertext = base64.b64decode(msg)
    iv         = ciphertext[:16]
    cipher     = AES.new(shared_key, AES.MODE_CBC, iv)
    plaintext  = unpad(cipher.decrypt(ciphertext))
    return plaintext

# Sign a message with a private key
def sign(msg, priv_key):
    signer = PKCS1_v1_5.new(priv_key)
    signature = base64.b64encode( signer.sign(msg) )
    return signature

# Base 64 decode all items in an array
def decode_msg(msg):
    return map(base64.b64decode, msg)

# Increment the given key by 1
def increment_key(key, num=1):
    int_representation = int(key.encode('hex'), 16)
    int_representation += num
    return int_representation

# A helper for sending and receiving data
def send_and_receive(msg, address, socket, response_size, response_len):
    socket.sendto(msg, address)
    received = socket.recv(response_size)
    data = received.strip().split(',',response_len)
    return data

