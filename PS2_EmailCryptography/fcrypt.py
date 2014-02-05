#! /usr/bin/env python

import sys
import argparse
import random
import base64

# crypto libraries
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

class EncryptAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        pub_key_file, priv_key_file, input_file, output_file = values

        pub_key  = open(pub_key_file,  'r').read().rstrip('\n')
        priv_key = open(priv_key_file, 'r').read().rstrip('\n')
        raw      = open(input_file,    'r').read().rstrip('\n')
        output_f = open(output_file,   'w')

        raw = pad(raw)
        iv = Random.new().read( AES.block_size )

        cipher = AES.new('abcdefghiklmnopq', AES.MODE_CBC, iv)
        output_f.write(base64.b64encode( iv + cipher.encrypt( raw ) ))


class DecryptAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        priv_key_file, pub_key_file, ciphertext_file, plaintext_file = values

        priv_key   = open(priv_key_file,   'r').read().rstrip('\n')
        pub_key    = open(pub_key_file,    'r').read().rstrip('\n')
        ciphertext = open(ciphertext_file, 'r').read().rstrip('\n')
        output_f   = open(plaintext_file,  'w')

        enc = base64.b64decode(ciphertext)
        iv = enc[:16]
        cipher = AES.new('abcdefghiklmnopq', AES.MODE_CBC, iv)
        output_f.write(unpad(cipher.decrypt(enc[16:])))

        output_f.close()


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

