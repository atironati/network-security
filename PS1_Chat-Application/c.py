#! /usr/bin/env python

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import threading
from twisted.internet.task import LoopingCall
import socket, select

class EchoClientDatagramProtocol(DatagramProtocol):

    def __init__(self, host, port):
        self.loopObj = None
        self.host = host
        self.port = port

    def startProtocol(self):
        self.transport.setTTL(5)
        self.transport.joinGroup('228.0.0.5')

        self.send_greeting()
        self.loopObj = LoopingCall(self.wait_for_input)
        self.loopObj.start(2,now=False)

    def send_greeting(self):
        print 'butts'

        self.send_datagram("GREETING")
        #self.wait_for_input()

        #thread_out = threading.Thread(target=self.wait_for_input(), args=())
        #thread_out.start()

    def wait_for_input(self):
        socket_list = [sys.stdin, s]

        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
            #incoming message from
            remote server
            if sock == s:
                data = sock.recv(4096)
                if not data :
                    print '\nDisconnected from chat server'
                    sys.exit()
                else :
                    #print data
                    sys.stdout.write(data)
                    sys.stdout.flush()
                    prompt()

            #user entered a message
            else :
                msg = sys.stdin.readline()
                s.send(msg)
                prompt()

        msg = raw_input("-> ")
        self.send_datagram(msg)

    def send_datagram(self, datagram):
        self.transport.write(datagram, (self.host, self.port))

    def datagramReceived(self, datagram, host):
        print 'Datagram received: ', repr(datagram)

def main():
    protocol = EchoClientDatagramProtocol("228.0.0.5",8000)
    t = reactor.listenMulticast(8000, protocol, listenMultiple=True)
    reactor.run()

    #while(1):
        #msg = raw_input("-> ")
        #print msg
        #protocol.sendDatagram(msg)

if __name__ == '__main__':
   main()
