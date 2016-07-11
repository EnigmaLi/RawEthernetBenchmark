#!/usr/bin/env python

import sys
import socket

def send_eth(src, dst, eth_type, payload, interface = "enp0s3"):
  """Send raw Ethernet packet on interface."""

  assert(len(src) == len(dst) == 6) # 48-bit ethernet addresses
  assert(len(eth_type) == 2) # 16-bit ethernet type

  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

  # From the docs: "For raw packet
  # sockets the address is a tuple (ifname, proto [,pkttype [,hatype]])"
  s.bind((interface, 0))
  s.send((src + dst + eth_type + payload).encode("utf-8"))
  s.close()

def recv_eth(buff_size, interface = "enp0s3"):

    # create a raw socket and bind it to the public interface
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0x0800))

    # receive a package
    print(s.recvfrom(buff_size))

    s.close()

if __name__ == "__main__":
    if(sys.argv[1] == "client"):

        while(True):
            send_eth("\x08\x00\x27\x08\xDE\x43", "\xA4\x5E\x60\xF4\x09\x1F", "\x00\x05", "hello")
            #send_eth("\x08\x00\x27\x08\xDE\x43", "\x08\x00\x27\x08\xDE\x43", "\x08\x00", "hello")



    elif(sys.argv[1] == "server"):
        while(True):
            recv_eth(64)
    else:
        pass
