#! /usr/bin/env python

import diffie_hellman
import SocketServer
import sys
import sqlite3
import collections
import common

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

connected_clients      = collections.defaultdict(lambda: collections.defaultdict(str))
authenticating_clients = collections.defaultdict(lambda: collections.defaultdict(str))

server_pub_key  = RSA.importKey(open('server_pub_key.txt', 'r').read().rstrip('\n'))
server_priv_key = RSA.importKey(open('server_priv_key.txt', 'r').read().rstrip('\n'))

server_secret = Random.new().read( 32 )
iv            = Random.new().read( 16 )

conn = sqlite3.connect('server_db.db')
c = conn.cursor()

# c.execute("INSERT INTO users (ip, password_hash, pub_key, priv_key,name) VALUES ('129.10.9.112','alex','" + pub_key.exportKey() + "','" + priv_key.exportKey() + "','alex')")
conn.commit()

HOST = "localhost"
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
else:
    PORT = 9999

"""
A class used to handle UDP messages and act as a socket server.
self.request consists of a pair of data and client sockets. Because
there is no connection, the client address must be given explicitly
when sending data back via sendto()
"""
class UDPHandler(SocketServer.BaseRequestHandler):
    registered_clients = set()
    socket             = None

    def __init__(self, a, b, c):
        self.protocols = {"LOGIN" : self.login_protocol,
                          "LIST"  : self.verify_dos_cookie}
        SocketServer.BaseRequestHandler.__init__(self,a,b,c)

    # Handle an incoming request
    def handle(self):
        data        = self.request[0].strip().split(',')
        self.socket = self.request[1]

        # Every first request from an ip address requires a dos cookie check
        self.send_dos_cookie()
        received = self.socket.recv(8192)

        data     = received.strip().split(',', 8)
        data_len = len(data)

        if data_len > 2:
            protocol   = data[0]
            dos_cookie = data[1]

            # start the desired protocol if dos cookie is valid,
            # passing in the rest of the options
            if self.verify_dos_cookie(dos_cookie):
                try:
                    self.protocols[protocol](data[2:])
                except KeyError:
                    print "Protocol not found"

    def send_dos_cookie(self):
        print str(self.client_address)
        client_ip = str(self.client_address[0])

        plaintext  = pad(client_ip + "," + str(server_secret))
        cipher     = AES.new(server_secret, AES.MODE_CBC, iv)
        ciphertext = base64.b64encode(cipher.encrypt(plaintext))

        self.socket.sendto(ciphertext, self.client_address)

    def verify_dos_cookie(self, cookie):
        try:
            cipher    = AES.new(server_secret, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(base64.b64decode( cookie )))
            plaintext = plaintext.split(',')
            if len(plaintext) == 2:
                client_ip  = plaintext[0]
                our_secret = plaintext[1]
                if client_ip == self.client_address[0] and server_secret == our_secret:
                    return True
                else:
                    return False
            else:
                return False
        except TypeError:
            return False

    def login_protocol(self, data):
        if len(data) != 2 : return

        # Decrypt message with our private key and break out message
        msg = common.public_key_decrypt(data[0], data[1], server_priv_key)
        uname            = msg[0].rstrip('\n')
        iv1              = base64.b64decode( msg[1] )
        signature        = base64.b64decode( msg[2] )
        encrypted_dh_val = base64.b64decode( msg[3] )

        # Lookup public key of the user
        user_pub_key = self.get_user_pub_key(uname)

        # Verify the user's signature
        h = SHA256.new(str(uname) + str(iv1))
        verifier = PKCS1_v1_5.new(user_pub_key)

        if verifier.verify(h, str(signature)):
            print "Signature Verified!"
            pass_hash = base64.b64decode( self.get_password_hash(uname) )

            # Decrypt DH val
            diff_hell_val = long(common.aes_decrypt(encrypted_dh_val, pass_hash, iv1))

            # Create random values
            nonce1         = Random.new().read( 32 )
            encoded_nonce1 = base64.b64encode(nonce1)
            iv2            = Random.new().read( 16 )
            encoded_iv2    = base64.b64encode(iv2)

            # Compute our diffie hellman value and encrypt with password hash
            dh = diffie_hellman.DiffieHellman()
            serv_dh_key = base64.b64encode(str(dh.genPublicKey()))
            encoded_serv_dh = common.aes_encrypt(str(serv_dh_key), pass_hash, iv2)

            # Establish shared key
            dh.genKey(diff_hell_val)
            shared_key = dh.getKey()
            print 'shared_key'
            print base64.b64encode(shared_key)

            # Sign the message
            signature_msg = SHA256.new(str(iv2))
            signature     = common.sign(signature_msg, server_priv_key )

            # Encrypt with public key of user
            encrypt_msg = "%s,%s,%s,%s" % (encoded_iv2, signature, encoded_serv_dh, encoded_nonce1)
            encrypted_server_keys, ciphertext = common.public_key_encrypt(encrypt_msg, user_pub_key)

            msg = encrypted_server_keys + "," + ciphertext
            self.socket.sendto(msg, self.client_address)
            data = self.socket.recv(1024).split(',',2)
            if len(data) != 2 : return

            msg                   = common.public_key_decrypt(data[0], data[1], server_priv_key)
            iv3                   = base64.b64decode( msg[0] )
            encrypted_user_nonce1 = base64.b64decode( msg[1] )
            nonce2                = base64.b64decode( msg[2] )
            encoded_nonce2        = base64.b64encode( nonce2 )

            # Verify user nonce1 value matches the value we sent
            user_nonce1 = common.aes_decrypt(encrypted_user_nonce1, shared_key, iv3)

            if nonce1 == user_nonce1:
                print "YES!"

                # Keep track of shared key
                connected_clients[uname]['shared_key'] = shared_key
                connected_clients[uname]['ip']         = self.client_address[0]

                # Send last message so client can verify our identity/shared key
                iv4          = Random.new().read( 16 )
                encoded_iv4  = base64.b64encode( iv4 )
                encrypted_n2 = common.aes_encrypt(encoded_nonce2, shared_key, iv4)

                encrypt_msg = "%s,%s" % (encoded_iv4, encrypted_n2)
                encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, user_pub_key)

                msg = encrypted_keys + ',' + ciphertext
                self.socket.sendto(msg, self.client_address)

        else:
            print "The signature is not authentic"
            return

    def get_user_pub_key(self, uname):
        try:
            cmd = "SELECT pub_key FROM users WHERE name=?"
            c.execute( cmd, (uname,) )

            data = c.fetchone()
            key  = ''
            if data is not None:
                key = RSA.importKey(data[0])

            return key

        except sqlite3.Error, e:
            print "Error %s" % e.args[0]

    def get_password_hash(self, uname):
        try:
            cmd = "SELECT password_hash FROM users WHERE name=?"
            c.execute(cmd, (uname,))

            data = c.fetchone()
            pwd = ''
            if data is not None:
                pwd = data[0]

            return pwd

        except sqlite3.Error, e:
            print "Error %s" % e.args[0]


    # Registers a recognized client with the server
    def register_client(self, ca):
        self.registered_clients.add(ca)

    # Broadcast to all registered clients
    def broadcast_message(self, msg):
        client_ip   = self.client_address[0]
        client_port = self.client_address[1]

        for addr in self.registered_clients:
            outgoing_msg = "INCOMING:<From %s:%s> %s\n" % (client_ip, client_port, msg)
            self.socket.sendto(outgoing_msg, addr)

if __name__ == "__main__":
    try:
        server = SocketServer.UDPServer((HOST, PORT), UDPHandler)
        print "Server Initialized on port " + str(PORT)
        server.serve_forever()
    except KeyboardInterrupt:
        print "shutting down server"
        server.shutdown()
    except Exception as e:
        # Can't access SocketServer's socket, must use string matching instead
        if "Address already in use" in str(e):
            print "Port %s is already in use! Please run the server with a different port" % PORT

