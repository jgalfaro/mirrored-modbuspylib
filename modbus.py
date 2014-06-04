#! /usr/bin/env python
#

"""
Modbus/TCP Library for Scapy 0.2

	Tested with Scapy 2.2.0-dev

 Authors: - Arthur Gervais (creator)
          - Ken LE PRADO 
 
 Licence: Published under the GPL3 (https://www.gnu.org/licenses/gpl.txt)

 Supported Function Codes:
 	01 (0x01) Read Coils
	02 (0x02) Read Discrete Inputs
	03 (0x03) Read Holding Registers
	04 (0x04) Read Input Registers

	05 (0x05) Write Single Coil
	06 (0x06) Write Single Holding Register

	07 (0x07) Read Exception Status (Serial Line only)

	15 (0x0F) Write Multiple Coils
	16 (0x10) Write Multiple Holding Registers

	17 (0x11) Report Slave ID (Serial Line only)

	43 (0x2B) Read Device Identification (MEI Type 14)

 Unimplemented function (TCP)
 	20 (0x14) Read File Record
 	21 (0x15) Write File Record
 	22 (0x16) Mask Write Register
 	23 (0x17) Read/Write Multiple registers
 	24 (0x18) Read FIFO Queue

	Supported function codes:
   	Modsak supported: [1, 2, 3, 4, 5, 6, 7, 8, 11, 15, 16, 17, 22, 23]
   	Schneider Factory Cast supported: [1, 2, 3, 4, 5, 6, 15, 16, 22, 43, 90]

"""

import sys
sys.path.append('/home/user/projects/tools/scapy')
from scapy.all import *

_modbus_exceptions = {  1: "Illegal function",
						2: "Illegal data address",
						3: "Illegal data value",
						4: "Server device failure",
						5: "Acknowledge",
						6: "Server device busy",
						8: "Memory parity error",
						10: "Gateway path unavailable",
						11: "Gateway target device failed to respond"}

_read_device_id_codes = {  1: "Basic",
						2: "Regular",
						3: "Extended",
						4: "Specific"}


# 0x00 - Undefined Generic Function
class ModbusPDU00_Generic_Request(Packet):
	name = "Generic Request"
	fields_desc = [ XByteField("funcCode", 0x00),
							StrFixedLenField("payload", "", 255)]
	def extract_padding(self, s):
		return "", None

class ModbusPDU00_Generic_Response(Packet):
	name = "Generic Request"
	fields_desc = [ XByteField("funcCode", 0x00),
							StrFixedLenField("payload", "", 255)]
	def extract_padding(self, s):
		return "", None


# 0x80 - Undefined Generic Exception Function
class ModbusPDU00_Generic_Exception(Packet):
	name = "Generic Exception"
	fields_desc = [ XByteField("funcCode", 0x80),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]
	def extract_padding(self, s):
		return "", None

# 0x01 - Read Coils
class ModbusPDU01_Read_Coils_Request(Packet):
	name = "Read Coils Request"
	fields_desc = [ XByteField("funcCode", 0x01),
				# 0x0000 to 0xFFFF
			XShortField("startAddr", 0x0000),
			XShortField("quantity", 0x0001)]
	def extract_padding(self, s):
		return "", None

class ModbusPDU01_Read_Coils_Response(Packet):
	name = "Read Coils Response"
	fields_desc = [ XByteField("funcCode", 0x01),
			BitFieldLenField("byteCount", None, 8, count_of="coilStatus"),
			FieldListField("coilStatus", [0x00], ByteField("",0x00), count_from = lambda pkt: pkt.byteCount) ]
	def extract_padding(self, s):
		return "", None

class ModbusPDU01_Read_Coils_Exception(Packet):
	name = "Read Coils Exception"
	fields_desc = [ XByteField("funcCode", 0x81),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]
	def extract_padding(self, s):
		return "", None


# 0x02 - Read Discrete Inputs
class ModbusPDU02_Read_Discrete_Inputs_Request(Packet):
	name = "Read Discrete Inputs"
	fields_desc = [ XByteField("funcCode", 0x02),
			XShortField("startAddr", 0x0000),
			XShortField("quantity", 0x0001)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU02_Read_Discrete_Inputs_Response(Packet):
	name = "Read Discrete Inputs Response"
	fields_desc = [ XByteField("funcCode", 0x02),
			BitFieldLenField("byteCount", None, 8, count_of="inputStatus"),
			FieldListField("inputStatus", [0x00], ByteField("",0x00), count_from = lambda pkt: pkt.byteCount) ]
class ModbusPDU02_Read_Discrete_Inputs_Exception(Packet):
	name = "Read Discrete Inputs Exception"
	fields_desc = [ XByteField("funcCode", 0x82),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x03 - Read Holding Registers
class ModbusPDU03_Read_Holding_Registers_Request(Packet):
	name = "Read Holding Registers"
	fields_desc = [ XByteField("funcCode", 0x03),
			XShortField("startAddr", 0x0000),
			XShortField("quantity", 0x0001)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU03_Read_Holding_Registers_Response(Packet):
	name = "Read Holding Registers Response"
	fields_desc = [ XByteField("funcCode", 0x03),
			BitFieldLenField("byteCount", None, 8, count_of="registerVal"),
			FieldListField("registerVal", [0x00], ByteField("",0x00), count_from = lambda pkt: pkt.byteCount)]
class ModbusPDU03_Read_Holding_Registers_Exception(Packet):
	name = "Read Holding Registers Exception"
	fields_desc = [ XByteField("funcCode", 0x83),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x04 - Read Input Registers
class ModbusPDU04_Read_Input_Registers_Request(Packet):
	name = "Read Input Registers"
	fields_desc = [ XByteField("funcCode", 0x04),
			XShortField("startAddr", 0x0000),
			XShortField("quantity", 0x0001)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU04_Read_Input_Registers_Response(Packet):
	name = "Read Input Registers Response"
	fields_desc = [ XByteField("funcCode", 0x04),
			BitFieldLenField("byteCount", None, 8, count_of="registerVal"),
			FieldListField("registerVal", [0x00], ByteField("",0x00), count_from = lambda pkt: pkt.byteCount)]
class ModbusPDU04_Read_Input_Registers_Exception(Packet):
	name = "Read Input Registers Exception"
	fields_desc = [ XByteField("funcCode", 0x84),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x05 - Write Single Coil
class ModbusPDU05_Write_Single_Coil_Request(Packet):
	name = "Write Single Coil"
	fields_desc = [ XByteField("funcCode", 0x05),
			XShortField("outputAddr", 0x0000), # from 0x0000 to 0xFFFF
			XShortField("outputValue", 0x0000)]# 0x0000 == Off, 0xFF00 == On
class ModbusPDU05_Write_Single_Coil_Response(Packet): # The answer is the same as the request if successful
	name = "Write Single Coil"
	fields_desc = [ XByteField("funcCode", 0x05),
			XShortField("outputAddr", 0x0000), # from 0x0000 to 0xFFFF
			XShortField("outputValue", 0x0000)]# 0x0000 == Off, 0xFF00 == On
class ModbusPDU05_Write_Single_Coil_Exception(Packet):
	name = "Write Single Coil Exception"
	fields_desc = [ XByteField("funcCode", 0x85),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x06 - Write Single Register
class ModbusPDU06_Write_Single_Register_Request(Packet):
	name = "Write Single Register"
	fields_desc = [ XByteField("funcCode", 0x06),
			XShortField("registerAddr", 0x0000), 
			XShortField("registerValue", 0x0000)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU06_Write_Single_Register_Response(Packet):
	name = "Write Single Register Response"
	fields_desc = [ XByteField("funcCode", 0x06),
			XShortField("registerAddr", 0x0000), 
			XShortField("registerValue", 0x0000)]
class ModbusPDU06_Write_Single_Register_Exception(Packet):
	name = "Write Single Register Exception"
	fields_desc = [ XByteField("funcCode", 0x86),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x07 - Read Exception Status (Serial Line Only)
class ModbusPDU07_Read_Exception_Status_Request(Packet):
	name = "Read Exception Status"
	fields_desc = [ XByteField("funcCode", 0x07)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU07_Read_Exception_Status_Response(Packet):
	name = "Read Exception Status Response"
	fields_desc = [ XByteField("funcCode", 0x07),
			XByteField("startingAddr", 0x00)]
class ModbusPDU07_Read_Exception_Status_Exception(Packet):
	name = "Read Exception Status Exception"
	fields_desc = [ XByteField("funcCode", 0x87),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x0F - Write Multiple Coils
class ModbusPDU0F_Write_Multiple_Coils_Request(Packet):
	name = "Write Multiple Coils"
	fields_desc = [ XByteField("funcCode", 0x0F),
			XShortField("startingAddr", 0x0000),
			XShortField("quantityOutput", 0x0001),
			BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt,x:x),
			FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from = lambda pkt: pkt.byteCount)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU0F_Write_Multiple_Coils_Response(Packet):
	name = "Write Multiple Coils Response"
	fields_desc = [ XByteField("funcCode", 0x0F),
			XShortField("startingAddr", 0x0000),
			XShortField("quantityOutput", 0x0001)]
class ModbusPDU0F_Write_Multiple_Coils_Exception(Packet):
	name = "Write Multiple Coils Exception"
	fields_desc = [ XByteField("funcCode", 0x8F),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x10 - Write Multiple Registers
class ModbusPDU10_Write_Multiple_Registers_Request(Packet):
	name = "Write Multiple Registers"
	fields_desc = [ XByteField("funcCode", 0x10),
			XShortField("startingAddr", 0x0000),
			XShortField("quantityRegisters", 0x0001),
			BitFieldLenField("byteCount", None, 8, count_of="outputsValue", adjust=lambda pkt,x:x),
			FieldListField("outputsValue", [0x00], XByteField("", 0x00), count_from = lambda pkt: pkt.byteCount)]
	def extract_padding(self, s):
		return "", None
class ModbusPDU10_Write_Multiple_Registers_Response(Packet):
	name = "Write Multiple Registers Response"
	fields_desc = [ XByteField("funcCode", 0x10),
			XShortField("startingAddr", 0x0000),
			XShortField("quantityRegisters", 0x0001)]
class ModbusPDU10_Write_Multiple_Registers_Exception(Packet):
	name = "Write Multiple Registers Exception"
	fields_desc = [ XByteField("funcCode", 0x90),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x11 - Report Slave Id
class ModbusPDU11_Report_Slave_Id_Request(Packet):
	name = "Report Slave Id"
	fields_desc = [ XByteField("funcCode", 0x11)]
	def extract_padding(self, s):
		return "", None

class ModbusPDU11_Report_Slave_Id_Response(Packet):
	name = "Report Slave Id Response"
	fields_desc = [ XByteField("funcCode", 0x11),
			BitFieldLenField("byteCount", None, 8, length_of="slaveId"),
			ConditionalField(StrLenField("slaveId", "", length_from = lambda pkt: pkt.byteCount), lambda pkt: pkt.byteCount>0),
			ConditionalField(XByteField("runIdicatorStatus", 0x00), lambda pkt: pkt.byteCount>0)]
class ModbusPDU11_Report_Slave_Id_Exception(Packet):
	name = "Report Slave Id Exception"
	fields_desc = [ XByteField("funcCode", 0x91),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]

# 0x2B/0x0D - CANopen General Reference Request and Response PDU
#class ModbusPDU2B_Read Device Identification_Request(Packet):
#	name = "CANopen General Reference Request and Response PDU"
#	fields_desc = [ XByteField("funcCode", 0x2B),
#			XByteField("MEI_Type", 0x0D),       #0x0D (13=CANopen General Reference Request and Response PDU)
#			
#					]

# 0x2B/0x0E - Read Device Identification
class ModbusPDU2B_Read_Device_Identification_Request(Packet):
	name = "Read Device Identification"
	fields_desc = [ XByteField("funcCode", 0x2B),
			XByteField("MEIType", 0x0E),
			ByteEnumField("readCode", 1 , _read_device_id_codes),
			XByteField("objectId", 0x00)]

# 0x2B/0x0E - Read Device Identification
class ModbusPDU2B_Read_Device_Identification_Response(Packet):
	name = "Read Device Identification"
	fields_desc = [ XByteField("funcCode", 0x2B),
			XByteField("MEIType", 0x0E),
			ByteEnumField("readCode", 4 , _read_device_id_codes),
			XByteField("conformityLevel", 0x00),   #0x01, 0x02, 0x03, 0x04, 0x81, 0x82, 0x83, 0x84
			XByteField("more", 0x00),              #0x00 (no more)   0xFF (more objects)
			XByteField("nextObjId", 0x00),              
			ByteField("objCount", 0x00)
			]
	def guess_payload_class(self, payload):
		if self.objCount >0:		
			return ModBusPDU_ObjectId
		else:
			return Packet.guess_payload_class(self, payload)
		
class ModBusPDU_ObjectId(Packet):
	name = "Object"
	fields_desc = [ByteField("id", 0x00),            
			ByteField("length", 0x00),
	#TODO Bad thing here...		FieldLenField("length", None, length_of="value"),
			StrLenField("value", "", length_from = lambda pkt: pkt.length) #TODO : define my type because char are on 2 bytes
			]
	def guess_payload_class(self, payload):
		return ModBusPDU_ObjectId

class ModbusPDU2B_Read_Device_Identification_Exception(Packet):
	name = "Read Exception Status Exception"
	fields_desc = [ XByteField("funcCode", 0xAB),
			ByteEnumField("exceptCode", 1, _modbus_exceptions)]


class ModbusADU_Request(Packet):
	name = "ModbusADU"
	fields_desc = [ 
			XShortField("transId", 0x0001), # needs to be unique
			XShortField("protoId", 0x0000), # needs to be zero (Modbus)
			ShortField("len", None), 		# is calculated with payload
			XByteField("unitId", 0x00)] 	# 0xFF or 0x00 should be used for Modbus over TCP/IP
	# Dissects packets
	def guess_payload_class(self, payload):
		funcCode = int(payload[0].encode("hex"),16)
		MEIType = int(payload[1].encode("hex"),16)

		if funcCode == 0x01:
			return ModbusPDU01_Read_Coils_Request
		elif funcCode == 0x81:
			return ModbusPDU01_Read_Coils_Exception
			
		elif funcCode == 0x02:
			return ModbusPDU02_Read_Discrete_Inputs_Request
		elif funcCode == 0x82:
			return ModbusPDU02_Read_Discrete_Inputs_Exception

		elif funcCode == 0x03:
			return ModbusPDU03_Read_Holding_Registers_Request
		elif funcCode == 0x83:
			return ModbusPDU03_Read_Holding_Registers_Exception

		elif funcCode == 0x04:
			return ModbusPDU04_Read_Input_Registers_Request
		elif funcCode == 0x84:
			return ModbusPDU04_Read_Input_Registers_Exception

		elif funcCode == 0x05:
			return ModbusPDU05_Write_Single_Coil_Request
		elif funcCode == 0x85:
			return ModbusPDU05_Write_Single_Coil_Exception

		elif funcCode == 0x06:
			return ModbusPDU06_Write_Single_Register_Request
		elif funcCode == 0x86:
			return ModbusPDU06_Write_Single_Register_Exception

		elif funcCode == 0x07:
			return ModbusPDU07_Read_Exception_Status_Request
		elif funcCode == 0x87:
			return ModbusPDU07_Read_Exception_Status_Exception

		elif funcCode == 0x0F:
			return ModbusPDU0F_Write_Multiple_Coils_Request
		elif funcCode == 0x8F:
			return ModbusPDU0F_Write_Multiple_Coils_Exception

		elif funcCode == 0x10:
			return ModbusPDU10_Write_Multiple_Registers_Request
		elif funcCode == 0x90:
			return ModbusPDU10_Write_Multiple_Registers_Exception

		elif funcCode == 0x11:
			return ModbusPDU11_Report_Slave_Id_Request
		elif funcCode == 0x91:
			return ModbusPDU11_Report_Slave_Id_Exception

		elif funcCode == 0x2B and MEIType == 0x0E:
			return ModbusPDU2B_Read_Device_Identification_Request
		elif funcCode == 0xAB:
			return ModbusPDU2B_Read_Device_Identification_Exception

		else:
			return ModbusPDU00_Generic_Request
#			return Packet.guess_payload_class(self, payload)

	def post_build(self, p, pay):
		if self.len is None:
			l = len(pay)+1 #+len(p)
			p = p[:4]+struct.pack("!H", l)+p[6:]
		return p+pay
		
#	def extract_padding(self, s):
#		l = self.len
#		print "Length" + l
#		return s[:l], s[l:]

class ModbusADU_Response(Packet):
	name = "ModbusADU"
	fields_desc = [ 
			XShortField("transId", 0x0001), # needs to be unique
			XShortField("protoId", 0x0000), # needs to be zero (Modbus)
			ShortField("len", None), 		# is calculated with payload
			XByteField("unitId", 0x01)] 	# 0xFF or 0x00 should be used for Modbus over TCP/IP
	# Dissects packets
	def guess_payload_class(self, payload):
		funcCode = int(payload[0].encode("hex"),16)
		MEIType = int(payload[1].encode("hex"),16)

		if funcCode == 0x01:
			return ModbusPDU01_Read_Coils_Response
		elif funcCode == 0x81:
			return ModbusPDU01_Read_Coils_Exception

		elif funcCode == 0x02:
			return ModbusPDU02_Read_Discrete_Inputs_Response
		elif funcCode == 0x82:
			return ModbusPDU02_Read_Discrete_Inputs_Exception

		elif funcCode == 0x03:
			return ModbusPDU03_Read_Holding_Registers_Response
		elif funcCode == 0x83:
			return ModbusPDU03_Read_Holding_Registers_Exception

		elif funcCode == 0x04:
			return ModbusPDU04_Read_Input_Registers_Response
		elif funcCode == 0x84:
			return ModbusPDU04_Read_Input_Registers_Exception

		elif funcCode == 0x05:
			return ModbusPDU05_Write_Single_Coil_Response
		elif funcCode == 0x85:
			return ModbusPDU05_Write_Single_Coil_Exception

		elif funcCode == 0x06:
			return ModbusPDU06_Write_Single_Register_Response
		elif funcCode == 0x86:
			return ModbusPDU06_Write_Single_Register_Exception

		elif funcCode == 0x07:
			return ModbusPDU07_Read_Exception_Status_Response
		elif funcCode == 0x87:
			return ModbusPDU07_Read_Exception_Status_Exception

		elif funcCode == 0x0F:
			return ModbusPDU0F_Write_Multiple_Coils_Response
		elif funcCode == 0x8F:
			return ModbusPDU0F_Write_Multiple_Coils_Exception

		elif funcCode == 0x10:
			return ModbusPDU10_Write_Multiple_Registers_Response
		elif funcCode == 0x90:
			return ModbusPDU10_Write_Multiple_Registers_Exception

		elif funcCode == 0x11:
			return ModbusPDU11_Report_Slave_Id_Response
		elif funcCode == 0x91:
			return ModbusPDU11_Report_Slave_Id_Exception

		elif funcCode == 0x2B and MEIType == 0x0E:
			return ModbusPDU2B_Read_Device_Identification_Response
		elif funcCode == 0xAB:
			return ModbusPDU2B_Read_Device_Identification_Exception
			
		else:
			return ModbusPDU00_Generic_Exception
#			return Packet.guess_payload_class(self, payload)

#	def extract_padding(self, s):
#		l = self.len
#		print "Length" + l
#		return s[:l], s[l:]

# Binds TCP port 502 to Modbus/TCP
bind_layers( TCP, ModbusADU_Request, dport=502 )
bind_layers( TCP, ModbusADU_Response, sport=502 )

#if __name__ == "__main__":
#	os.system('clear');
#	interact(mydict=globals())
