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

class Client():
    # SOCK_DGRAM is the socket type to use for UDP sockets
    sock = None

    def __init__(self):
        # set a timeout of 1 second so we can detect server inactivity
        socket.setdefaulttimeout(1)

        # SOCK_DGRAM is the socket type to use for UDP sockets
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.greet_server()

    def greet_server(self):
        self.send_helper("GREETING", "")

    def send_message(self, msg):
        self.send_helper("MESSAGE:", msg)

    # used as a general way to send messages to the server
    # checks for socket timeouts to detect inactive server
    def send_helper(self, prefix, msg):
        try:
            self.sock.sendto(prefix + msg, (HOST, PORT))
            received = self.sock.recv(1024)
            self.print_message(received)

        except socket.timeout as e:
            print "Server is not responding"
            sys.exit()

    # Print incoming messages to the terminal, has options for line breaks
    def print_message(self, msg, lb_before=False, lb_after=False):
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

