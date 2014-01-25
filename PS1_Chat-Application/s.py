#! /usr/bin/env python

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

registered_clients = {}

# Here's a UDP version of the simplest possible protocol
class EchoUDP(DatagramProtocol):

    def startProtocol(self):
        self.transport.joinGroup("228.0.0.5")
        # Send to 228.0.0.5:8005 - all listeners on the
        # multicast address (including us) will receive this message.
        #self.transport.write('Client: Ping', ("228.0.0.5", 8005))

    def datagramReceived(self, datagram, address):
        print 'yay'
        print address

        if datagram == "GREETING":
            print "yay! " + str(address)
            self.transport.write("You are connected to the chat server!", address)
        else:
            print datagram
            #self.transport.write('Client: Ping' + datagram, ("228.0.0.5", 8000))


def main():
    reactor.listenMulticast(8000, EchoUDP(), listenMultiple=True)
    reactor.run()

if __name__ == '__main__':
    main()
