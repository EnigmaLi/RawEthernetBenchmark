#!/usr/bin/env python

import os
import sys
import socket
import time

class ether_benchmark(object):
	"""  """
	def __init__(self, is_server, local_mac, dest_mac, intf = "eth1"):
		self.__is_server = is_server
		## Raw Socket Init
		self.__skt_send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
		self.__skt_recv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
		self.__skt_send.bind((intf, 0))
		self.__skt_recv.bind((intf, 0x809B))	## ETHER_TYPE = ETHER_TALK
		
		## Order! Order! Order!
		self.__ether_header = dest_mac + local_mac + [0x80, 0x9B]
		
		self.__payload = [0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
						  0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						  0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
						  0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62]
		
	def __del__(self):
		self.__skt_send.close()
		self.__skt_recv.close()
	
	def __pack(self, byte_seq):
		## Convert List of Bytes to Byte String
		return b"".join(map(chr, byte_seq))
		
	def __send_eth(self, payload):
		data_pack = self.__pack(self.__ether_header + payload)
		self.__skt_send.send(data_pack)
		
	def __recv_eth(self, buff_size):
		return self.__skt_recv.recvfrom(buff_size)
		
	def run(self, rep):
		## Work as Server Mode
		if self.__is_server:
			for i in range(0, rep):
				packet = self.__recv_eth(64)
				print(">>> Receive Packet [" + str(i) +"]:")
				print("Packet Content: %s" % packet)
				
		## Work as Client Mode	
		else:
			for i in range(0, rep):
				t1 = time.time()
				self.__send_eth(self.__payload)
				t2 = time.time()
				print(("%.20f" % t2))
	
def str_to_mac(str_mac):
	pass

if __name__ == "__main__":
	if(sys.argv[1] == "client"):
		is_srv = False
	elif(sys.argv[1] == "server"):
		is_srv = True
	else:
		print(">>> Invalid arguments!")
		os.exit(-1)


	print("AAA")
	eth = ether_benchmark(is_srv, [0x00, 0x02, 0xC9, 0x4D, 0x45, 0xC8], [0xF4, 0x52, 0x14, 0x94, 0x99, 0x60])
	eth.run(100)
        
        
