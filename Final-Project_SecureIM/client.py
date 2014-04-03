#! /usr/bin/env python

import socket
import sys
import select
import termios
import tty

HOST = "localhost"
if len(sys.argv) > 1:
    PORT = int(sys.argv[1])
else:
    PORT = 9999

g = 2
p = """0xFFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
         29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
         EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
         E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
         EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
         C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
         83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
         670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
         E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
         DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
         15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"""
p = int(p.replace(" ",""),0)

class Client():
    # SOCK_DGRAM is the socket type to use for UDP sockets
    sock = None

    def __init__(self):
        # set a timeout of 1 second so we can detect server inactivity
        socket.setdefaulttimeout(1)

        # SOCK_DGRAM is the socket type to use for UDP sockets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.login_to_server()

    def login_to_server(self):
        self.send_helper("LOGIN", "")

    def send_message(self, msg):
        self.send_helper("MESSAGE:", msg)

    # used as a general way to send messages to the server
    # checks for socket timeouts to detect inactive server
    def send_helper(self, prefix, msg):
        try:

            self.sock.sendto(prefix + msg, (HOST, PORT))
            received = self.sock.recv(1024)
            self.print_message("HEYHEY: " + received)
            dos_cookie = received
            self.print_message("dos_cookie: " + dos_cookie)

            # compute diffie hellman value encrypted with password hash

            encrypted_response_1 = "what"

            self.sock.sendto("LOGIN," + dos_cookie + "," + encrypted_response_1, (HOST, PORT))
            received = self.sock.recv(1024)
            self.print_message(received)

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
                msg = sys.stdin.readline()
                c.send_message(msg)
                prompt()

    except KeyboardInterrupt as msg:
        print "disconnected"
        sys.exit()

