#! /usr/bin/env python

import sys
import argparse
#import random
import base64

# crypto libraries
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

import random
def randomString(l):
    return ''.join(chr(random.randint(0, 0xFF)) for i in range(l))

key = RSA.generate(2048)
pubkey = key.publickey().exportKey("DER")
privkey = key.exportKey("DER")

print pubkey
print privkey

class EncryptAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        pub_key_file, priv_key_file, input_file, output_file = values

        pub_key  = RSA.importKey(open(pub_key_file, 'r').read().rstrip('\n'))
        priv_key = open(priv_key_file, 'r').read().rstrip('\n')
        raw      = open(input_file,    'r').read().rstrip('\n')
        output_f = open(output_file,   'w')

        session_key = Random.new().read( 32 )
        iv          = Random.new().read( 16 )

        rsa = PKCS1_OAEP.new(pub_key)
        encrypted_session_key = rsa.encrypt(session_key + iv)

        output_f.write(base64.b64encode(encrypted_session_key) + '\n')

        print base64.b64encode(session_key)
        print base64.b64encode(iv)

        raw = pad(raw)
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        ciphertext = base64.b64encode(cipher.encrypt(raw))

        output_f.write(ciphertext)

class DecryptAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        priv_key_file, pub_key_file, ciphertext_file, plaintext_file = values

        priv_key     = RSA.importKey(open(priv_key_file, 'r').read().rstrip('\n'))
        pub_key      = open(pub_key_file, 'r').read().rstrip('\n')
        ciphertext_f = open(ciphertext_file, 'r')
        output_f     = open(plaintext_file,  'w')


        # decode

        rsa = PKCS1_OAEP.new(priv_key)

        encrypted_msg_key = base64.b64decode( ciphertext_f.readline() )
        ciphertext        = base64.b64decode( ciphertext_f.readline() )

        msg_key = rsa.decrypt( encrypted_msg_key )
        print base64.b64encode(msg_key)

        aes_key = msg_key[:32]
        iv      = msg_key[32:]

        print base64.b64encode(aes_key)
        print base64.b64encode(iv)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        print unpad(cipher.decrypt(ciphertext))




        #encrypted_msg_key = base64.b64decode( ciphertext_f.readline() )
        #encrypted_msg     = base64.b64decode( ciphertext_f.readline() )

        #rsa = PKCS1_OAEP.new(privkey)

        #msg_key = rsa.decrypt( encrypted_msg_key )


        #aes_key = msg_key[16:]
        #iv      = msg_key[:16]


        #aes = AES.new(aes_key, AES.MODE_CBC, iv)
        #plaintext = unpad(aes.decrypt( encrypted_msg ))
        #output_f.write( plaintext )

        #enc = base64.b64decode(ciphertext)
        #iv = enc[:16]
        #cipher = AES.new('abcdefghiklmnopq', AES.MODE_CBC, iv)
        #output_f.write(unpad(cipher.decrypt(enc[16:])))

        #output_f.close()


parser = argparse.ArgumentParser()
parser.add_argument("-e", "--encrypt",
                    nargs=4,
                    action=EncryptAction,
                    metavar=('destination_public_key_filename',
                             'sender_private_key_filename',
                             'input_plaintext_file',
                             'output_cyphertext_file'),
                    help="encpt the given FILE")
parser.add_argument("-d", "--decrypt",
                    nargs=4,
                    action=DecryptAction,
                    metavar=('destination_private_key_filename',
                             'sender_public_key_filename',
                             'input_cyphertext_file',
                             'output_plaintext_file'),
                    help="decrypt the given FILE")

args = parser.parse_args()


#hash = SHA256.new()
#print hash
#print hash.update('message')
#print hash.digest()

