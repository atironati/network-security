#! /usr/bin/env python

import SocketServer
import sys

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
        data = self.request[0].strip()
        self.socket = self.request[1]

        if data == "GREETING":
            self.register_client(self.client_address)
            print "Client registered: " + str(self.client_address)

            self.socket.sendto("INCOMING:You are connected to the chat server!",
                               self.client_address)

        elif data.startswith("MESSAGE:"):
            self.broadcast_message(data[8:])

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

