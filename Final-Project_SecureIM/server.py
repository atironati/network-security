#! /usr/bin/env python

import diffie_hellman
import SocketServer
import sys
import sqlite3
import collections
import common
import datetime

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
fmt = '%Y-%m-%d %H:%M:%S'

connected_clients      = collections.defaultdict(lambda: collections.defaultdict(str))
authenticating_clients = collections.defaultdict(lambda: collections.defaultdict(str))

server_pub_key  = RSA.importKey(open('keys/server_pub_key.txt', 'r').read().rstrip('\n'))
server_priv_key = RSA.importKey(open('keys/server_priv_key.txt', 'r').read().rstrip('\n'))

server_secret = Random.new().read( 32 )
iv            = Random.new().read( 16 )

conn = sqlite3.connect('server_db.db')
c = conn.cursor()

#pub_key  = RSA.importKey(open('keys/bob_pub.txt', 'r').read())
#priv_key = RSA.importKey(open('keys/bob_priv.txt', 'r').read())
#c.execute("INSERT INTO users (ip, password_hash, pub_key, priv_key,name) VALUES ('129.10.9.112','bob','" + pub_key.exportKey() + "','" + priv_key.exportKey() + "','bob')")
#c.execute("UPDATE users set pub_key='" + pub_key.exportKey() + "', priv_key='" + priv_key.exportKey() + "' where name='mark')")
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
        self.protocols = {"LOGIN"  : self.login_protocol,
                          "LIST"   : self.list_protocol,
                          "TICKET" : self.ticket_protocol,
                          "LOGOUT" : self.logout_protocol,
                          "SYNC"   : self.clock_sync_protocol}
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
        msg              = common.public_key_decrypt(data[0], data[1], server_priv_key)
        decoded_msg      = common.decode_msg(msg)
        uname            = decoded_msg[0]
        iv1              = decoded_msg[1]
        signature        = decoded_msg[2]
        encrypted_dh_val = decoded_msg[3]

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
            iv2            = Random.new().read( 16 )

            # Compute our diffie hellman value and encrypt with password hash
            dh = diffie_hellman.DiffieHellman()
            serv_dh_key = str(dh.genPublicKey())
            serv_dh = common.aes_encrypt(serv_dh_key, pass_hash, iv2)

            # Establish shared key
            dh.genKey(diff_hell_val)
            shared_key = dh.getKey()

            # Sign the message
            signature_msg = SHA256.new(str(iv2))
            signature     = common.sign(signature_msg, server_priv_key )

            # Encrypt with public key of user
            encrypt_msg = common.encode_msg([iv2, signature, serv_dh, nonce1])
            encrypted_server_keys, ciphertext = common.public_key_encrypt(encrypt_msg, user_pub_key)

            # Send message
            send_msg = encrypted_server_keys + "," + ciphertext
            data = common.send_and_receive(send_msg, self.client_address, self.socket, 1024, 2)
            if len(data) != 2 : return

            rec_msg               = common.public_key_decrypt(data[0], data[1], server_priv_key)
            decoded_msg           = common.decode_msg(rec_msg)
            iv3                   = decoded_msg[0]
            encrypted_user_nonce1 = decoded_msg[1]
            nonce2                = decoded_msg[2]

            # Verify user encrypted nonce1 with the shared key
            user_nonce1 = common.aes_decrypt(encrypted_user_nonce1, shared_key, iv3)

            if nonce1 == user_nonce1:
                print "Login Sucess for user: " + uname

                # Send last message so client can verify our identity/shared key
                iv4          = Random.new().read( 16 )
                encrypted_n2 = common.aes_encrypt(nonce2, shared_key, iv4)

                encrypt_msg = common.encode_msg([iv4, encrypted_n2])
                encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, user_pub_key)

                msg = encrypted_keys + ',' + ciphertext
                self.socket.sendto(msg, self.client_address)

                # Keep track of shared key
                connected_clients[uname]['shared_key'] = shared_key
                connected_clients[uname]['shared_iv']  = iv4
                connected_clients[uname]['ip']         = self.client_address[0]
                connected_clients[uname]['port']       = self.client_address[1]
            else:
                print "Login Failure for user: " + uname
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

    def get_user_priv_key(self, uname):
        try:
            cmd = "SELECT priv_key FROM users WHERE name=?"
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

    # Lists all connected clients to user
    def list_protocol(self, data):
        if len(data) != 1 : return

        # Parse uname and use it to find the shared key
        uname = data[0]
        shared_key = connected_clients[uname]['shared_key']
        shared_iv  = connected_clients[uname]['shared_iv']

        # Create a nonce, encrypt it with the shared key, send it to the client
        nonce1 = Random.new().read( 32 )
        encrypted_nonce1 = common.aes_encrypt(nonce1, shared_key, shared_iv)

        encrypt_msg = common.encode_msg([encrypted_nonce1])
        data = common.send_and_receive(encrypt_msg, self.client_address, self.socket, 1024, 2)

        # Return if the nonce doesn't match
        user_nonce1 = base64.b64decode( data[0] )
        if nonce1 != user_nonce1 : return
        encrypted_n2 = base64.b64decode( data[1] )

        # Decrypt the client's nonce
        incr_shared_key = SHA256.new(str( common.increment_key(shared_key) )).digest()
        nonce2 = common.aes_decrypt(encrypted_n2, incr_shared_key, shared_iv)

        # Build the list of connected clients
        client_list = ''
        for key, value in connected_clients.iteritems():
            client_list += key + ','

        # Encrypt the list and send it to the client (along with the decrypted nonce)
        encrypted_client_list = common.aes_encrypt(client_list, shared_key, shared_iv)
        final_msg = common.encode_msg([nonce2, encrypted_client_list])
        self.socket.sendto(final_msg, self.client_address)

    # Issues a ticket to talk to a user
    def ticket_protocol(self, data):
        if len(data) != 2 : return

        # Parse uname and use it to find the shared key
        uname = data[0]
        if connected_clients.get(uname) is None : return
        shared_key = connected_clients[uname]['shared_key']
        shared_iv  = connected_clients[uname]['shared_iv']

        # Decrypt the requested user and timestamp
        msg = common.aes_decrypt(base64.b64decode(data[1]), shared_key, shared_iv).split(",",2)
        if len(msg) != 2 : return

        requested_user      = msg[0]
        requested_user_ip   = connected_clients[requested_user]['ip']
        requested_user_port = str(connected_clients[requested_user]['port'])
        user_timestamp_str  = ''
        user_timestamp      = ''
        try:
            user_timestamp_str = msg[1]
            user_timestamp     = datetime.datetime.strptime(msg[1], fmt)
        except ValueError:
            print "timestamp import issue"
            return

        # Verify timestamp is within acceptable range
        if common.verify_timestamp(user_timestamp, 5):
            # Lookup public key requested_user and create shared key
            requested_user_pub_key_str = self.get_user_pub_key(requested_user).exportKey()
            shared_user_key = self.create_shared_key()

            # Create ticket to requested_user
            encrypted_keys, ciphertext = self.create_ticket(requested_user, uname, shared_user_key)

            # Encrypt response with the shared key + 1
            encrypt_msg = user_timestamp_str + ',' + requested_user + ',' + shared_user_key + ',' + encrypted_keys + ',' + \
                          ciphertext + ',' + requested_user_pub_key_str + ',' + requested_user_ip + ',' + requested_user_port
            incr_shared_key = SHA256.new(str( common.increment_key(shared_key) )).digest()
            encrypted_msg   = common.aes_encrypt(encrypt_msg, incr_shared_key, shared_iv)

            # Encode the response (with ticket) and send it to the client
            final_msg = common.encode_msg([encrypted_msg])
            self.socket.sendto(final_msg, self.client_address)

        else:
            print "Timestamp not current enough"
            return

    def create_ticket(self, requested_user, requesting_user, shared_user_key):
        requesting_user_pub_key_str = self.get_user_pub_key(requesting_user).exportKey()
        requested_user_pub_key      = self.get_user_pub_key(requested_user)
        requested_user_pub_key_str  = requested_user_pub_key.exportKey()
        #requested_user_priv_key    = self.get_user_priv_key(requested_user).exportKey()
        now                         = datetime.datetime.now()
        expiration_datetime         = (now + datetime.timedelta(days=1)).strftime(fmt)

        # Create a signature
        iv            = Random.new().read( 16 )
        signature_msg = SHA256.new(str(iv))
        signature     = common.sign(signature_msg, server_priv_key)

        # Encrypt with public key of requested user
        encrypt_msg = common.encode_msg([iv, signature, shared_user_key, requesting_user, requesting_user_pub_key_str, expiration_datetime])
        encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, requested_user_pub_key)
        return [encrypted_keys, ciphertext]

    def create_shared_key(self):
        # Create shared key between users
        dh1 = diffie_hellman.DiffieHellman()
        dh2 = diffie_hellman.DiffieHellman()
        dh1.genPublicKey()
        dh2.genPublicKey()
        dh1.genKey(dh2.publicKey)
        shared_user_key = dh1.getKey()
        return shared_user_key

    # Logs out user
    def logout_protocol(self, data):
        if len(data) != 4 : return
        decoded_msg  = common.decode_msg(data)
        uname        = decoded_msg[0]
        iv           = decoded_msg[1]
        signature    = decoded_msg[2]
        encrypted_ts = decoded_msg[3]

        # Get user info
        if connected_clients.get(uname) is None : return
        shared_key = connected_clients[uname]['shared_key']
        shared_iv  = connected_clients[uname]['shared_iv']

        # Verify user signature
        user_pub_key = self.get_user_pub_key(uname)
        h = SHA256.new(str(iv))
        verifier = PKCS1_v1_5.new(user_pub_key)

        if verifier.verify(h, str(signature)):
            # Decrypt status
            user_timestamp_str = common.aes_decrypt(encrypted_ts, shared_key, shared_iv)

            user_timestamp = ''
            try:
                user_timestamp = datetime.datetime.strptime(user_timestamp_str, fmt)
            except ValueError:
                print "timestamp import issue"
                return

            # Verify timestamp is within acceptable range
            if common.verify_timestamp(user_timestamp, 5):
                # Encrypt response with the shared key
                encrypted_msg = common.aes_encrypt("LOGOUTSUCCESS", shared_key, shared_iv)

                # Create a signature
                iv2           = Random.new().read( 16 )
                signature_msg = SHA256.new(str(iv2))
                signature     = common.sign(signature_msg, server_priv_key)

                # Encode the response (with ticket) and send it to the client
                final_msg = common.encode_msg([iv2, signature, encrypted_msg])
                self.socket.sendto(final_msg, self.client_address)

                # Destroy user data
                connected_clients.pop(uname, None)
                print "User Logout: " + uname
            else:
                print "invalid timestamp"
        else:
            print "Invalid Signature"

        return

    def clock_sync_protocol(self, data):
        if len(data) != 1 : return

        # Parse uname and use it to find the shared key
        uname = data[0]
        shared_key = connected_clients[uname]['shared_key']
        shared_iv  = connected_clients[uname]['shared_iv']

        # Create a nonce, encrypt it with the shared key, send it to the client
        nonce1 = Random.new().read( 32 )
        encrypted_nonce1 = common.aes_encrypt(nonce1, shared_key, shared_iv)

        encrypt_msg = common.encode_msg([encrypted_nonce1])
        data = common.send_and_receive(encrypt_msg, self.client_address, self.socket, 1024, 2)

        # Return if nonce doesn't match
        user_nonce1 = base64.b64decode( data[0] )
        if nonce1 != user_nonce1 : return
        encrypted_n2 = base64.b64decode( data[1] )

        # Decrypt the client's nonce
        incr_shared_key = SHA256.new(str( common.increment_key(shared_key) )).digest()
        nonce2 = common.aes_decrypt(encrypted_n2, incr_shared_key, shared_iv)

        # Get the current server timestamp and encrypt it
        timestamp = datetime.datetime.now().strftime(fmt)
        encrypted_timestamp = common.aes_encrypt(timestamp, shared_key, shared_iv)
        final_msg = common.encode_msg([nonce2, encrypted_timestamp])
        self.socket.sendto(final_msg, self.client_address)


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

