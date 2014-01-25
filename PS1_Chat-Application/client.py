#! /usr/bin/env python

import socket
import sys
import select
import termios
import tty

HOST, PORT = "localhost", int(sys.argv[1])

class Client():
    # SOCK_DGRAM is the socket type to use for UDP sockets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __init__(self):
        self.greet_server()

    def greet_server(self):
        self.sock.sendto("GREETING", (HOST, PORT))
        received = self.sock.recv(1024)
        if "INCOMING:" in received:
            print received[9:]

    def send_message(self, msg):
        self.sock.sendto("MESSAGE:" + msg, (HOST, PORT))
        received = self.sock.recv(1024)
        if "INCOMING:" in received:
            print received[9:]

def prompt():
    sys.stdout.write('-> ')
    sys.stdout.flush()

def get_cursor_pos():
    # Save stdin configuration
    fd = sys.stdin.fileno()
    settings = termios.tcgetattr(fd)

    # Set stdin to raw mode
    tty.setraw(fd)

    # Request cursor position
    sys.stdout.write("\033[6n")

    # Read response one char at a time until 'R'
    resp = char = ""

    try:
        while char != 'R':
            resp += char
            char = sys.stdin.read(1)
    finally:
        # Restore # previous # stdin # configuration
        termios.tcsetattr(fd, termios.TCSADRAIN, settings)

        # Split # answer # in # two # and # return # COL # and # ROW # as # tuple
        return tuple([int(i) for i in resp[2:].split(';')])

# 
def read_curr_word():
    # Save stdin configuration
    fd = sys.stdin.fileno()
    settings = termios.tcgetattr(fd)

    # Set stdin to raw mode
    tty.setraw(fd)

    # Read response one char at a time until 'R'
    resp = char = "a"

    try:
        resp = sys.stdin.read(4)
    finally:
        # Restore # previous # stdin # configuration
        termios.tcsetattr(fd, termios.TCSADRAIN, settings)

        # Split # answer # in # two # and # return # COL # and # ROW # as # tuple
        return resp

c = Client()

# Initial user prompt
prompt()

# Input and chat-printing loop
while(1):
    # create a list of sources to monitor
    socket_list = [sys.stdin, c.sock]

    # Get the list sockets which are readable
    read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

    for sock in read_sockets:
        #incoming message from remote server
        if sock == c.sock:
            data = sock.recv(4096)
            if not data:
                print '\nDisconnected from chat server'
                sys.exit()
            else:
                # p'\033[0;0H' + 
                #print '\033[6n'

                #cp = get_cursor_pos()
                #print cp
                #print cp[0]
                #print cp[1]
                #print str(cp[1] - 6)

                #move_pos = "\033[" + str(cp[0]) + ";" + str(0) + "H"

                #sys.stdout.flush()
                #msg = read_curr_word()

                #after_move_pos = "\033[" + str(cp[0]) + ";" + str(len(msg)) + "H"

                if "INCOMING:" in data:
                    sys.stdout.write(data[9:] + '\n')

                prompt()

        # user entered a message
        else:
            msg = sys.stdin.readline()
            c.send_message(msg)
            prompt()


