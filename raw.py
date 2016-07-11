#!/usr/bin/env python

import sys
import socket

def send_eth(src, dst, eth_type, payload, interface = "eth1"):
  """Send raw Ethernet packet on interface."""

  assert(len(src) == len(dst) == 6) # 48-bit ethernet addresses
  assert(len(eth_type) == 2) # 16-bit ethernet type

  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

  ## From the docs: "For raw packet sockets the address is a tuple:
  ## (ifname, proto [,pkttype [,hatype]])
  s.bind((interface, 0))
  s.send(src + dst + eth_type + payload)
  s.close()

def recv_eth(buff_size, interface = "eth1"):

    # create a raw socket and bind it to the public interface
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0x809B))

    # receive a package
    print(s.recvfrom(buff_size))

    s.close()

if __name__ == "__main__":
    if(sys.argv[1] == "client"):

        while(True):
            #send_eth("\x08\x00\x27\x08\xDE\x43", "\xA4\x5E\x60\xF4\x09\x1F", "\x00\x05", "hello")
            #send_eth("\x08\x00\x27\x08\xDE\x43", "\x08\x00\x27\x08\xDE\x43", "\x08\x00", "hello")
			send_eth("\x00\x02\xC9\x4D\x45\xC8", "\xF4\x52\x14\x94\x99\x60", "\x80\x9B", "hello")


    elif(sys.argv[1] == "server"):
        while(True):
            recv_eth(64)
    else:
        pass
