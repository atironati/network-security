#! /usr/bin/env python

import SocketServer
import sys
import sqlite3
import collections

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

conn = sqlite3.connect('server_db.db')
c = conn.cursor()

pub_key   = RSA.importKey(open('cryptography/alice_pub.txt', 'r').read().rstrip('\n'))
priv_key  = RSA.importKey(open('cryptography/alice_priv.txt', 'r').read().rstrip('\n'))

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

    # Handle an incoming request
    def handle(self):
        data        = self.request[0].strip().split(',')
        data_len    = len(data)
        self.socket = self.request[1]

        if data_len > 0 and data[0] == "LOGIN":
            #self.register_client(self.client_address)
            #print "Client registered: " + str(self.client_address)
            if data_len == 1:
                send_dos_cookie()
            elif data_len == 3:
                if verify_dos_cookie(data[1]):
                    diff_hell_val = RSA_decrypt_login(data[2])
                    if diff_hell_val is not None:
                        authenticating_clients[str(self.client_address)]['user_diff_hell_val'] = diff_hell_val
                        #send client our diff hell val encoded with the password and whatever

            self.socket.sendto("INCOMING:You are connected to the chat server!",
                               self.client_address)

        elif data.startswith("MESSAGE:"):
            self.broadcast_message(data[8:])

    def send_dos_cookie(self):
        client_ip = str(self.client_address)
        iv        = Random.new().read( 16 )

        plaintext  = pad(client_ip)
        cipher     = AES.new(server_secret, AES.MODE_CBC, iv)
        ciphertext = base64.b64encode(cipher.encrypt(plaintext))

        self.socket.sendto(ciphertext)

    def RSA_decrypt_login(ciphertext):
        encrypted_msg_key = base64.b64decode( line1 )
        ciphertext        = base64.b64decode( line2 )

        cipher  = PKCS1_OAEP.new(server_priv_key)
        msg = ""
        try:
            msg = cipher.decrypt( ciphertext )
        except ValueError:
            print "There was a key error in RSA decryption"
            return None

        msg = msg.split(',')
        uname     = msg[0]
        nonce     = msg[1]
        signature = msg[2]
        encrypted_diff_hell_val = msg[3]

        user_pub_key = get_user_pub_key(uname)

        # Verify the signature
        h = SHA256.new(nonce)
        verifier = PKCS1_v1_5.new(user_pub_key)
        if verifier.verify(h, str(signature)):
            pass_hash = get_password_hash()
            pass_byte_str = str(bytearray( pass_hash.decode("hex") ))

            # Decrypt using AES
            cipher        = AES.new(pass_byte_str, AES.MODE_CBC, iv)
            diff_hell_val = unpad(cipher.decrypt( encrypted_diff_hell_val ))

            return diff_hell_val
        else:
            print "The signature is not authentic"
            return None


    def get_user_pub_key():
        try:
            cmd = "SELECT pub_key FROM users WHERE ip=%s"
            c.execute( cmd, self.client_address )

            data = c.fetchone()
            key  = ''
            if data is not None:
                key = RSA.importKey(data)

            return key

        except sqlite3.Error, e:
            print "Error %s" % e.args[0]

    def get_password_hash():
        try:
            cmd = "SELECT password_hash FROM users WHERE ip=%s"
            c.execute(cmd, self.client_address)

            data = c.fetchone()
            pwd = ''
            if data is not None:
                pwd = data

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

