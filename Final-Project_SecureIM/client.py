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

server_pub_key = RSA.importKey(open('keys/server_pub_key.txt', 'r').read().rstrip('\n'))

BS    = 16
pad   = lambda s : s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

HOST = "localhost"
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
else:
    PORT = 9999

class Client():
    sock, server_address, username, shared_key, shared_iv, pub_key, priv_key = [None, None, None, None, None, None, None]

    def __init__(self):
        # Set server address
        self.server_address = (HOST, PORT)

        # set a timeout of 1 second so we can detect server inactivity
        socket.setdefaulttimeout(1)

        # SOCK_DGRAM is the socket type to use for UDP sockets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Prompt for login information
        sys.stdout.write('Please enter username: ')
        self.username = sys.stdin.readline().rstrip('\n')
        password      = SHA256.new(getpass.getpass()).digest()

        # Import user keys
        self.pub_key  = RSA.importKey(open('keys/' + self.username + '_pub.txt', 'r').read().rstrip('\n'))
        self.priv_key = RSA.importKey(open('keys/' + self.username + '_priv.txt', 'r').read().rstrip('\n'))

        # Initiate LOGIN protocol
        self.login_to_server(password)

    def login_to_server(self, password):
        try:
            self.sock.sendto("LOGIN", self.server_address)
            dos_cookie = self.sock.recv(1024)

            # compute diffie hellman value and encrypt with password hash
            iv1         = Random.new().read( 16 )
            dh          = diffie_hellman.DiffieHellman()
            dh_key      = str(dh.genPublicKey())
            dh_val      = common.aes_encrypt(dh_key, password, iv1)

            # Sign the message
            signature_msg = SHA256.new(str(self.username) + str(iv1))
            signature     = common.sign(signature_msg, self.priv_key)

            # Encrypt plaintext using AES symmetric encryption
            encrypt_msg = common.encode_msg([self.username, iv1, signature, dh_val])
            encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, server_pub_key)

            send_msg = "LOGIN," + dos_cookie + "," + encrypted_keys + "," + ciphertext
            self.sock.settimeout(3)
            data = common.send_and_receive(send_msg, self.server_address, self.sock, 8192, 2)
            if len(data) != 2 : return None

            rec_msg = common.public_key_decrypt(data[0], data[1], self.priv_key)
            decoded_msg = common.decode_msg(rec_msg)
            iv2                   = decoded_msg[0]
            signature             = decoded_msg[1]
            encrypted_serv_dh_val = decoded_msg[2]
            nonce1                = decoded_msg[3]

            # Verify the signature
            h = SHA256.new(str(iv2))
            verifier = PKCS1_v1_5.new(server_pub_key)

            if verifier.verify(h, str(signature)):
                # Decrypt server dh val
                server_dh_val = long(common.aes_decrypt(encrypted_serv_dh_val, password, iv2))

                # Generate shared key
                dh.genKey(server_dh_val)
                shared_key = dh.getKey()

                # Encrypt nonce1 with our shared key
                nonce2         = Random.new().read( 32 )
                iv3            = Random.new().read( 16 )
                encrypted_n1   = common.aes_encrypt(nonce1, shared_key, iv3)

                # Encrypt mesage with pub key of the server
                encrypt_msg = common.encode_msg([iv3, encrypted_n1, nonce2])
                encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, server_pub_key)

                # Send message
                send_msg = encrypted_keys + ',' + ciphertext
                data = common.send_and_receive(send_msg, self.server_address, self.sock, 4096, 2)
                if len(data) != 2 : return None

                rec_msg               = common.public_key_decrypt(data[0], data[1], self.priv_key)
                decoded_msg           = common.decode_msg(rec_msg)
                iv4                   = decoded_msg[0]
                encrypted_serv_nonce2 = decoded_msg[1]

                # Verify user nonce1 value matches the value we sent
                serv_nonce2 = common.aes_decrypt(encrypted_serv_nonce2, shared_key, iv4)

                if nonce2 == serv_nonce2:
                    self.shared_key = shared_key
                    self.shared_iv  = iv4
                    print "Successfully logged in!"
                else:
                    self.shared_key = None
                    print "Login unsuccessful"
                    sys.exit()
            else:
                print "Server could not be verified"
                sys.exit()

        except socket.timeout as e:
            print "Server is not responding"
            sys.exit()

    # Get a list of connected clients from the server
    def get_client_list(self):
        # Send the "LIST" server request
        self.sock.sendto("LIST", self.server_address)

        # Receive the dos cookie
        dos_cookie = self.sock.recv(1024)

        # Send the dos cookie back, along with the username
        msg = "LIST," + dos_cookie + "," + self.username
        self.sock.sendto(msg, (HOST, PORT))

        # Receive an encrypted nonce and decrypt it
        encrypted_nonce = self.sock.recv(1024)
        decoded_encrypted_nonce = base64.b64decode(encrypted_nonce)
        decrypted_nonce = common.aes_decrypt(decoded_encrypted_nonce, self.shared_key, self.shared_iv)

        # Create a new nonce and encrypt with the shared key + 1
        nonce2 = Random.new().read( 32 )
        incr_shared_key = SHA256.new(str( common.increment_key(self.shared_key) )).digest()
        encrypted_nonce2 = common.aes_encrypt(nonce2, incr_shared_key, self.shared_iv)

        # Send the decrypted nonce and encrypted second nonce to the server
        #send_msg = encoded_decrypted_nonce + "," + encrypted_nonce2
        send_msg = common.encode_msg([decrypted_nonce, encrypted_nonce2])
        data = common.send_and_receive(send_msg, self.server_address, self.sock, 8192, 2)

        # Check the nonce
        serv_nonce2 = base64.b64decode( data[0] )
        if serv_nonce2 != nonce2 : return
        encrypted_unames = base64.b64decode(data[1])

        # Decrypt and print names
        unames = common.aes_decrypt(encrypted_unames, self.shared_key, self.shared_iv)
        unames = unames.split(',')
        for name in unames:
            print name

    def send_message(self, user, msg):
        if authenticated_users[user] is None:
            self.get_ticket_from_server(user)

        print 'ppoop'

    def get_ticket_from_server(self, user):
        try:
            self.sock.sendto("TICKET", self.server_address)
            dos_cookie = self.sock.recv(1024)

            # compute something
            iv1         = Random.new().read( 16 )

            # Encrypt plaintext using AES symmetric encryption
            encrypt_msg = "%s,%s,%s,%s" % (self.username, encoded_iv1, signature, encoded_dh)
            encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, server_pub_key)

            # Create something
            nonce2 = Random.new().read( 32 )
            encoded_msg = base64.b64encode(user)
            encrypted_nonce2 = common.aes_encrypt(encoded_msg, self.shared_key, self.shared_iv)


            send_msg = "TICKET," + dos_cookie + "," + self.username + ',' + ciphertext
            data = common.send_and_receive(send_msg, self.server_address, self.sock, 8192, 2)
            if len(data) != 2 : return None

        except socket.timeout as e:
            print "Server is not responding"
            sys.exit()


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
                msg = sys.stdin.readline().rstrip('\n').split(' ', 2)

                if len(msg) > 0:
                    if msg[0] == "list":
                        c.get_client_list()

                    if len(msg) == 3:
                        if msg[0] == "send":
                            c.send_message(msg[1],msg[2])

                prompt()

    except KeyboardInterrupt as msg:
        print "disconnected"
        sys.exit()

