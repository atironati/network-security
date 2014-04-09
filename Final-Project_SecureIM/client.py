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
import collections
import datetime
import hmac

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
fmt = '%Y-%m-%d %H:%M:%S'

HOST = "localhost"
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
else:
    PORT = 9999

class Client():
    sock, server_address, username, shared_key, shared_iv, pub_key, priv_key, authenticated_users = [None, None, None, None, None, None, None, None]

    def __init__(self):
        # Set server address
        self.server_address = (HOST, PORT)
        self.authenticated_users = collections.defaultdict(lambda: collections.defaultdict(str))

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

            # Encrypt plaintext using server public key
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
        if self.authenticated_users.get(user) is None:
            self.get_ticket_from_server(user)

        # create hmac key for message
        shared_key = self.authenticated_users[user]['shared_key']
        shared_iv  = self.authenticated_users[user]['shared_iv']
        user_addr  = self.authenticated_users[user]['address']
        self.authenticated_users[user]['sequence_n'] += 1
        sequence_n = self.authenticated_users[user]['sequence_n']
        hmac_key = hmac.new(shared_key, str(sequence_n) + ',' + msg).digest()

        msg = str(sequence_n) + ',' + msg
        encrypted_msg = common.aes_encrypt(msg, shared_key, shared_iv)

        send_msg = common.encode_msg([self.username, hmac_key, encrypted_msg])
        self.sock.sendto('MESSAGE' + ',' + send_msg, user_addr)

    def get_ticket_from_server(self, user):
        try:
            self.sock.sendto("TICKET", self.server_address)
            dos_cookie = self.sock.recv(1024)

            # Request to talk to given user, sending current timestamp
            timestamp             = datetime.datetime.now().strftime(fmt)
            msg                   = user + "," + timestamp
            encrypted_msg         = common.aes_encrypt(msg, self.shared_key, self.shared_iv)
            encoded_encrypted_msg = common.encode_msg([encrypted_msg])

            # Send request to server
            send_msg = "TICKET," + dos_cookie + ',' + self.username + ',' + encoded_encrypted_msg
            self.sock.settimeout(5)
            data = common.send_and_receive(send_msg, self.server_address, self.sock, 16384, 1)
            if len(data) != 1 : return

            # Decrypt the message with shared key + 1
            msg = base64.b64decode( data[0] )
            incr_shared_key = SHA256.new(str( common.increment_key(self.shared_key) )).digest()
            msg = common.aes_decrypt(msg, incr_shared_key, self.shared_iv).split(',', 8)
            if len(msg) != 8 : return

            serv_timestamp       = msg[0]
            serv_user_to_talk_to = msg[1]
            shared_key_ab        = msg[2]
            encr_ticket_key      = msg[3]
            encr_ticket_ciphert  = msg[4]
            user_pk              = msg[5]
            user_ip              = msg[6]
            user_port            = msg[7]

            if serv_timestamp == timestamp and serv_user_to_talk_to == user:
                nonce         = Random.new().read( 32 )
                iv2           = Random.new().read( 16 )
                signature_msg = SHA256.new(str(iv2))
                signature     = common.sign(signature_msg, self.priv_key)

                # Encrypt nonce with our shared key
                encrypted_nonce = common.aes_encrypt(nonce, shared_key_ab, iv2)

                # Encrypt mesage with pub key of the user
                user_pk = RSA.importKey(user_pk)
                encrypt_msg = common.encode_msg([self.username, encr_ticket_key, encr_ticket_ciphert, iv2, signature, encrypted_nonce])
                encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, user_pk)

                user_address = (user_ip,int(user_port))
                send_msg = "AUTH" + ',' + encrypted_keys + ',' + ciphertext
                data = common.send_and_receive(send_msg, user_address, self.sock, 2048, 2)
                if len(data) != 2 : return

                # Decrypt message with our private key and break out message
                msg                 = common.public_key_decrypt(data[0], data[1], self.priv_key)
                decoded_msg         = common.decode_msg(msg)
                iv3             = decoded_msg[0]
                signature       = decoded_msg[1]
                encrypted_nonce = decoded_msg[2]

                # Decrypt nonce with shared key + 1
                incr_shared_key = SHA256.new(str( common.increment_key(shared_key_ab) )).digest()
                connected_nonce = common.aes_decrypt(encrypted_nonce, incr_shared_key, iv3)

                # Verify nonce is correct
                if connected_nonce == nonce:
                    self.authenticated_users[serv_user_to_talk_to]['shared_key'] = shared_key_ab
                    self.authenticated_users[serv_user_to_talk_to]['shared_iv']  = iv3
                    self.authenticated_users[serv_user_to_talk_to]['sequence_n'] = int(iv3.encode('hex'), 16)
                    self.authenticated_users[serv_user_to_talk_to]['address']    = user_address

                return

        except socket.timeout as e:
            print "Server is not responding"
            sys.exit()

    def handle_request(self, data, addr):
        data = data.split(',', 4)

        if data[0] == 'AUTH':
            if len(data) != 3 : return
            # Decrypt message with our private key and break out message
            msg                 = common.public_key_decrypt(data[1], data[2], self.priv_key)
            decoded_msg         = common.decode_msg(msg)
            connected_uname     = decoded_msg[0]
            encr_ticket_key     = decoded_msg[1]
            encr_ticket_ciphert = decoded_msg[2]
            iv2                 = decoded_msg[3]
            signature           = decoded_msg[4]
            encrypted_nonce     = decoded_msg[5]

            # Decrypt ticket
            ticket = common.public_key_decrypt(encr_ticket_key, encr_ticket_ciphert, self.priv_key)
            ticket = common.decode_msg(ticket)
            if len(ticket) != 6 : return
            iv                          = ticket[0]
            serv_signature              = ticket[1]
            shared_user_key             = ticket[2]
            requesting_user             = ticket[3]
            requesting_user_pub_key_str = ticket[4]
            expiration_datetime_str     = ticket[5]

            # Verify ticket is not expired and username from ticket matches requesting username
            expiration_timestamp = ''
            try:
                expiration_timestamp = datetime.datetime.strptime(expiration_datetime_str, fmt)
            except ValueError:
                return
            if common.is_timestamp_current(expiration_timestamp) != True : return
            if requesting_user != connected_uname: return

            # Verify server's signature
            h = SHA256.new(str(iv))
            verifier = PKCS1_v1_5.new(server_pub_key)

            if verifier.verify(h, str(serv_signature)):
                # Now verify signature of initiating user
                requesting_user_pub_key = RSA.importKey(requesting_user_pub_key_str)
                h = SHA256.new(str(iv2))
                verifier = PKCS1_v1_5.new(requesting_user_pub_key)

                if verifier.verify(h, str(signature)):
                    # Create signature
                    iv3 = Random.new().read( 16 )
                    signature_msg = SHA256.new(str(iv3))
                    signature     = common.sign(signature_msg, self.priv_key)

                    # Add user to authenticated users
                    self.authenticated_users[requesting_user]['shared_key'] = shared_user_key
                    self.authenticated_users[requesting_user]['shared_iv']  = iv3
                    self.authenticated_users[requesting_user]['sequence_n'] = int(iv3.encode('hex'), 16)
                    self.authenticated_users[requesting_user]['address']  = addr

                    # Now decrypt nonce, and encrypt back with kab + 1
                    nonce = common.aes_decrypt(encrypted_nonce, shared_user_key, iv2)
                    incr_shared_key = SHA256.new(str( common.increment_key(shared_user_key) )).digest()
                    our_encrypted_nonce = common.aes_encrypt(nonce, incr_shared_key, iv3)

                    # Send final message back to initiating user, encrypted with their pub key
                    encrypt_msg = common.encode_msg([iv3, signature, our_encrypted_nonce])
                    encrypted_keys, ciphertext = common.public_key_encrypt(encrypt_msg, requesting_user_pub_key)
                    send_msg = encrypted_keys + "," + ciphertext
                    self.sock.sendto(send_msg, addr)

            else:
                return

            return
        if data[0] == 'MESSAGE':
            if len(data) != 4 : return
            decoded_msg   = common.decode_msg(data[1:])
            if len(decoded_msg) != 3 : return
            connected_uname = decoded_msg[0]
            user_hmac_key   = decoded_msg[1]
            encrypted_msg   = decoded_msg[2]

            # Retrieve session info for user
            if self.authenticated_users.get(connected_uname) == None : return
            shared_key = self.authenticated_users[connected_uname]['shared_key']
            shared_iv  = self.authenticated_users[connected_uname]['shared_iv']
            user_addr  = self.authenticated_users[connected_uname]['address']
            self.authenticated_users[connected_uname]['sequence_n'] += 1
            sequence_n = self.authenticated_users[connected_uname]['sequence_n']

            # Decrypt message
            msg = common.aes_decrypt(encrypted_msg, shared_key, shared_iv).split(',',1)
            if len(msg) != 2 : return
            user_seq_n = msg[0]
            user_msg   = msg[1]

            # Verify sequence number matches our sequence number
            if user_seq_n != str(sequence_n) : return

            # Verify hmac key
            hmac_key = hmac.new(shared_key, str(user_seq_n) + ',' + user_msg).digest()
            if user_hmac_key != hmac_key : return

            print connected_uname + ': ' + user_msg
            return

        else:
            return

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
            # Incoming message from remote server or user
            if sock == c.sock:
                data, addr = sock.recvfrom(16384)
                c.handle_request(data, addr)
                #c.print_message(data, False, True)
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

