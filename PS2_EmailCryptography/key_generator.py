#! /usr/bin/env python

import sys
import base64
from Crypto.PublicKey import RSA

def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in DER format
    param: bits The key length in bits
    Return private key and public key
    '''
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("DER")
    private_key = new_key.exportKey("DER")

    public_key_f  = open(sys.argv[1],   'w')
    private_key_f = open(sys.argv[2],   'w')

    print base64.b64encode(public_key)

    public_key_f.write(public_key)
    private_key_f.write(private_key)

generate_RSA()
