#! /usr/bin/env python

import socket
import sys
import select
import termios
import tty
import diffie_hellman
import getpass
import base64
import common

# crypto libraries
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random # Much stronger than standard python random module

server_pub_key = RSA.importKey(open('server_pub_key.txt', 'r').read().rstrip('\n'))
pub_key        = RSA.importKey(open('alice_pub.txt', 'r').read().rstrip('\n'))
priv_key       = RSA.importKey(open('alice_priv.txt', 'r').read().rstrip('\n'))

BS    = 16
pad   = lambda s : s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

HOST = "localhost"
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
else:
    PORT = 9999

class Client():
    # SOCK_DGRAM is the socket type to use for UDP sockets
    sock = None

    def __init__(self):
        # set a timeout of 1 second so we can detect server inactivity
        socket.setdefaulttimeout(1)

        # SOCK_DGRAM is the socket type to use for UDP sockets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Prompt for login information
        sys.stdout.write('Please enter username: ')
        username = sys.stdin.readline().rstrip('\n')
        password = SHA256.new(getpass.getpass()).digest()

        # Initiate LOGIN protocol
        self.login_to_server(username, password)

    def login_to_server(self, username, password):
        try:
            self.sock.sendto("LOGIN", (HOST, PORT))
            received = self.sock.recv(1024)
            dos_cookie = received

            iv2 = Random.new().read( 16 )
            encoded_iv2 = base64.b64encode(iv2)

            # compute diffie hellman value and encrypt with password hash
            dh = diffie_hellman.DiffieHellman()
            dh_key = base64.b64encode(str(dh.genPublicKey()))
            encoded_dh = common.aes_encrypt(str(dh_key), password, iv2)

            # Sign the message
            signature_msg = SHA256.new(str(username) + str(iv2))
            signer = PKCS1_v1_5.new(priv_key)
            signature = base64.b64encode( signer.sign(signature_msg) )

            # Encrypt plaintext using AES symmetric encryption
            encrypt_msg = "%s,%s,%s,%s" % (username, encoded_iv2, signature, encoded_dh)
            encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, server_pub_key)

            final_msg = "LOGIN," + dos_cookie + "," + encrypted_keys + "," + ciphertext
            self.sock.sendto(final_msg, (HOST, PORT))
            data = self.sock.recv(8192).split(',', 2)

            if len(data) != 2 : return None

            msg = common.public_key_decrypt(data[0], data[1], priv_key)
            iv2       = base64.b64decode( msg[0] )
            signature = base64.b64decode( msg[1] )
            encrypted_server_dh_value = base64.b64decode( msg[2] )
            nonce1 = base64.b64decode( msg[3] )

            # Verify the signature
            h = SHA256.new(str(iv2))

            verifier = PKCS1_v1_5.new(server_pub_key)
            if verifier.verify(h, str(signature)):
                print "Signature Verified!"

                # Decrypt using AES
                server_dh_val = long(common.aes_decrypt(encrypted_server_dh_value, password, iv2))

                print 'server DH VAL'
                print server_dh_val

                # Generate shared key
                dh.genKey(server_dh_val)
                shared_key = dh.getKey()
                print "shared key"
                print base64.b64encode(shared_key)

        except socket.timeout as e:
            print "Server is not responding"
            sys.exit()

    def send_message(self, msg):
        self.send_helper("MESSAGE:", msg)

    # Print incoming messages to the terminal, has options for line breaks
    def print_message(self, msg, lb_before=False, lb_after=False):
        print '\n' + msg
        if "INCOMING:" in msg:
            if lb_before:
                print '\n' + msg[9:]
            elif lb_after:
                print msg[9:] + '\n'
            else:
                print msg[9:]

# User input prompt
def prompt():
    sys.stdout.write('-> ')
    sys.stdout.flush()

c = Client()

# Initial user prompt
prompt()

# Input and chat-printing/monitoring loop
while(1):
    try:
        # create a list of sources to monitor
        socket_list = [sys.stdin, c.sock]

        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            # Incoming message from remote server
            if sock == c.sock:
                data = sock.recv(1024)
                c.print_message(data, False, True)
                prompt()

            # User entered a message
            else:
                msg = sys.stdin.readline()
                c.send_message(msg)
                prompt()

    except KeyboardInterrupt as msg:
        print "disconnected"
        sys.exit()

