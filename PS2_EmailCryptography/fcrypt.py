#! /usr/bin/env python

import sys
import argparse
import base64

# crypto libraries
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random # Much stronger than standard python random module

BS    = 16
pad   = lambda s : s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class EncryptAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        pub_key_file, priv_key_file, input_file, output_file = values

        pub_key   = RSA.importKey(open(pub_key_file, 'r').read().rstrip('\n'))
        priv_key  = RSA.importKey(open(priv_key_file, 'r').read().rstrip('\n'))
        plaintext = open(input_file,    'r').read().rstrip('\n')
        output_f  = open(output_file,   'w')

        # Create a random session key and initialization vector
        session_key = Random.new().read( 32 )
        iv          = Random.new().read( 16 )

        # Encrypt session key using PKCS1 OEAP public key crypto
        cipher = PKCS1_OAEP.new(pub_key)
        encrypted_session_key = cipher.encrypt(session_key + iv)
        output_f.write(base64.b64encode(encrypted_session_key) + '\n')

        # Encrypt plaintext using AES symmetric encryption
        plaintext  = pad(plaintext)
        cipher     = AES.new(session_key, AES.MODE_CBC, iv)
        ciphertext = base64.b64encode(cipher.encrypt(plaintext))
        output_f.write(ciphertext + '\n')

        # Sign the message
        signature_msg = Random.new().read( 64 )
        signer = PKCS1_v1_5.new(priv_key)
        signature = signer.sign(SHA256.new(signature_msg))
        output_f.write(base64.b64encode(signature_msg) + '\n')
        output_f.write(base64.b64encode(signature))

        print "Message encrypted!"

class DecryptAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        priv_key_file, pub_key_file, ciphertext_file, plaintext_file = values

        priv_key     = RSA.importKey(open(priv_key_file, 'r').read().rstrip('\n'))
        pub_key      = RSA.importKey(open(pub_key_file, 'r').read().rstrip('\n'))
        ciphertext_f = open(ciphertext_file, 'r')
        output_f     = open(plaintext_file,  'w')

        line1 = ciphertext_f.readline()
        line2 = ciphertext_f.readline()
        line3 = ciphertext_f.readline()
        line4 = ciphertext_f.readline()

        if (len(line1) == 0 or len(line2) == 0 or
            len(line3) == 0 or len(line4) == 0):
            print "Incorrect encrypted file format"
            sys.exit()

        encrypted_msg_key = base64.b64decode( line1 )
        ciphertext        = base64.b64decode( line2 )
        signature_msg     = base64.b64decode( line3 )
        signature         = base64.b64decode( line4 )

        # Verify the signature
        h = SHA256.new(signature_msg)
        verifier = PKCS1_v1_5.new(pub_key)
        if verifier.verify(h, str(signature)):
            print "The signature is authentic"
        else:
            print "The signature is not authentic"
            sys.exit()

        # Decrypt session key using our private key with PKCS1 OEAP
        cipher  = PKCS1_OAEP.new(priv_key)
        msg_key = ""
        try:
            msg_key = cipher.decrypt( encrypted_msg_key )
        except ValueError:
            print "There was a key error in your decryption"
            sys.exit()

        # Retrieve AES key and initialization vector
        aes_key = msg_key[:32]
        iv      = msg_key[32:]

        # Decrypt plaintext using AES
        cipher    = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))
        output_f.write( plaintext )

        print "Decryption successful!"
        print plaintext

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


