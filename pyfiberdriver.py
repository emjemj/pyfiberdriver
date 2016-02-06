from pysnmp.hlapi import *
import argparse

class SNMP:
	hostname = None
	community = None
	
	def __init__(self, hostname, community):
		self.hostname = hostname
		self.community = community

	def walk(self, root):
		
		result = []
		for errorIndication, errorStatus, errorIndex, varBinds in self.next_cmd(root): 
										
			if errorIndication:
				print errorIndication
				break

			elif errorStatus:
				print "{0} at {1}".format(errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex)-1][0] or "?")
				break
			else:
				for varBind in varBinds:
					result.append({"oid": varBind[0].prettyPrint(), "value": varBind[1]})
		return result

	def next_cmd(self, root):
		return nextCmd(
			SnmpEngine(),
			CommunityData(self.community),
			UdpTransportTarget((self.hostname, 161)),
			ContextData(),
			ObjectType(ObjectIdentity(root)),
			lookupNames=False, lookupValues=False, lookupMib=False, lexicographicMode=False
		)

class MRVFiberDriver:
	snmp = None
	chassis = {}

	def __init__(self, hostname, community):
		self.snmp = SNMP(hostname, community)

		# Figure out slots
		for o in self.snmp.walk("1.3.6.1.4.1.629.200.7.1.1.2"):
			self.chassis[o["value"]] = {}

		# Initialize chassis data.
		self._init_slots()
		self._init_ports()
	
	def _init_slots(self):
		
		# slot model
		models = self.snmp.walk("1.3.6.1.4.1.629.200.7.1.1.4")

		# port count
		portcounts = self.snmp.walk("1.3.6.1.4.1.629.200.7.1.1.6")
		
		# hardware revisions
		hwrevs = self.snmp.walk("1.3.6.1.4.1.629.200.7.1.1.7")

		# card types
		cardtypes = self.snmp.walk("1.3.6.1.4.1.629.200.7.1.1.8")

		# serial numbers
		serials = self.snmp.walk("1.3.6.1.4.1.629.200.7.1.1.32")

		for slot in self.chassis:
			slot = int(slot)
			self.chassis[slot]["model"] = self._slot_value(slot, models)
			self.chassis[slot]["portcount"] = self._slot_value(slot, portcounts)
			self.chassis[slot]["hwrev"] = self._slot_value(slot, hwrevs)
			self.chassis[slot]["type"] = self._slot_value_type(slot, cardtypes)
			self.chassis[slot]["serial"] = self._slot_value(slot, serials)

	def _init_ports(self):

		# port types
		porttypes = { 28: "TP", 87: "Console", 125: "SFP" } 
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.4"):
			c, s, p = self._sp(i["oid"])

			self.chassis[s]["ports"][p]["type"] = porttypes[i["value"]] 

		# link status
		linkstatuses = { 1: "Other", 2: "NoSignal", 3: "SignalDetected", 4: "Link" }
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.6"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["link"] = linkstatuses[i["value"]] 

		# loopback
		loopbacks = { 1: "NotSupported", 2: "Off" } 
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.13"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["loopback"] = loopbacks[i["value"]]

		# enable
		enables = { 1: "NotSupported", 3: "Enabled" }
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.14"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["enabled"] = enables[i["value"]]

		# link integrity notification
		lins = { 1: "NotSupported", 3: "Enabled" }
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.16"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["lin"] = lins[int(i["value"])]

		# port names (descriptions)
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.21"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["name"] = i["value"]

		# optics serial
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.28"):
			c, s, p = self._sp(i["oid"])
			
			val = str(i["value"])
			if(val == "N/A"):
				val = None

			self.chassis[s]["ports"][p]["optics"]["serial"] = val

		# optics vendor info
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.29"):
			c, s, p = self._sp(i["oid"])

			val = str(i["value"])
			if(val == "N/A"):
				val = None

			self.chassis[s]["ports"][p]["optics"]["vendor"] = val

		# optics model
		for i in self.snmp.walk(".1.3.6.1.4.1.629.200.8.1.1.42"):
			c, s, p = self._sp(i["oid"])
			val = str(i["value"])

			if(val == "N/A"):
				val = None

			self.chassis[s]["ports"][p]["optics"]["model"] = val

		# optics temperature
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.30"):
			c, s, p = self._sp(i["oid"])

			val = i["value"]
			if(val < 0):
				val = None
			
			self.chassis[s]["ports"][p]["optics"]["temperature"] = val

		# optics txpower
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.31"):
			c, s, p = self._sp(i["oid"])

			val = float(i["value"]) / 1000

			self.chassis[s]["ports"][p]["optics"]["txpower"] = val
		
		# optics rxpower
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.32"):
			c, s, p = self._sp(i["oid"])

			val = float(i["value"]) / 1000

			self.chassis[s]["ports"][p]["optics"]["rxpower"] = val

		# optics bias amps
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.33"):
			c, s, p = self._sp(i["oid"])

			val = float(i["value"]) / 1000

			self.chassis[s]["ports"][p]["optics"]["bias"] = val

		# optics voltage 
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.34"):
			c, s, p = self._sp(i["oid"])

			val = float(i["value"]) / 1000

			self.chassis[s]["ports"][p]["optics"]["voltage"] = val

		# optics wavelength 
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.37"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["optics"]["wavelength"] = i["value"]

		# digital diagnostic status
		doms = { 1:  "NotSupported", 2: "DiagsOk" } 
		for i in self.snmp.walk("1.3.6.1.4.1.629.200.8.1.1.38"):
			c, s, p = self._sp(i["oid"])
			self.chassis[s]["ports"][p]["domstatus"] = i["value"]


	def _sp(self, oid):
		# Helper function to parse chassis, slot, port from oid
		pcs = oid.split(".")
		c = int(pcs[-3])
		s = int(pcs[-2])
		p = int(pcs[-1])

		if(s in self.chassis and not "ports" in self.chassis[s]):
			self.chassis[s]["ports"] = {}

		if(s in self.chassis and not p in self.chassis[s]["ports"]):
			self.chassis[s]["ports"][p] = {"optics": {}}

		return c, s, p


	def _slot_value(self, slot, data):
		# Helper function to store data for slot.
		for i in data:
			pcs = i["oid"].split(".")

			if(slot == int(pcs[-1])):
				if str(i["value"]) == "N/A":
					return None
				return str(i["value"]).strip()
		return None
	
	def _slot_value_type(self, slot, data):
		types = { 1: None,  2: "Management", 3: "Converter" }
		for i in data:
			pcs = i["oid"].split(".")

			if(slot == int(pcs[-1])):
				if i["value"] in types:
					return types[i["value"]]
				else:
					return None
				
	def get_chassis(self):
		return self.chassis
	
	def get_slot_count(self):
		return len(self.chassis)
	
	def get_slot_active_count(self):
		active = 0
		for slot in self.chassis:
			if self.chassis[slot]["model"] is not None:
				active +=1
		return active

def main():
	parser = argparse.ArgumentParser(description="List info from MRV Fiberdriver chassis")
	parser.add_argument("--host", "-H", help="Host for your fiberdriver chassis", required=True) 
	parser.add_argument("--community", "-c", help="SNMP Community", required=True)
	parser.add_argument("--list-slots", "-s", help="display a list of chassis slots", action="store_true")
	parser.add_argument("--list-ports", "-p", help="display a list of ports", action="store_true")
	parser.add_argument("--digital-diagnostics", "-d", help="display digital diagnostics information", action="store_true")
	parser.add_argument("--inventory", "-i", help="display inventory", action="store_true")

	opts = parser.parse_args()

	fd = MRVFiberDriver(opts.host, opts.community)

	if(opts.list_slots):
		print "{:4} {:20} {:20} {:20}".format("Slot", "Model", "Type", "Serial")
		for slot_id in fd.get_chassis():
			slot = fd.get_chassis()[slot_id]
			print "{:4} {:20} {:20} {:20}".format(slot_id, slot["model"], slot["type"], slot["serial"])
	if(opts.inventory):
		print "{:4} {:8} {:15} {:20} {:25} {:25}".format("Type", "Location", "Serial", "Vendor", "Model", "Revision")
		optics = []
		for slot_id in fd.get_chassis():
			slot = fd.get_chassis()[slot_id]
			if "ports" in slot and len(slot["ports"]) > 0:
				print "{:4} 1.{:6} {:15} {:20} {:25} {:25}".format("Slot", slot_id, slot["serial"], "MRV", slot["model"], slot["hwrev"])
				for port_id in slot["ports"]:
					port = slot["ports"][port_id]
					if port["optics"]["serial"] is None:
						continue

					optic = {
						"location": "{}.{}".format(slot_id, port_id),
						"type": port["type"],
						"vendor": port["optics"]["vendor"],
						"serial": port["optics"]["serial"],
						"model": port["optics"]["model"],
						"hwrev": "N/A"
					}
					optics.append(optic)
		for optic in optics:
				print "{:4} 1.{:6} {:15} {:20} {:25} {:25}".format(optic["type"], optic["location"], optic["serial"], optic["vendor"], optic["model"], optic["hwrev"])

	if(opts.list_ports):
		print "{:5} {:13} {:15} {:13} {:15} {:6} {:7} {:20}".format("Port", "Enabled", "Link", "Lin", "DOM", "WL(nm)", "Channel", "Name")
		for slot_id in fd.get_chassis():
			slot = fd.get_chassis()[slot_id]

			if "ports" in slot and  len(slot["ports"]) > 0:
				for port_id in slot["ports"]:
					port = slot["ports"][port_id]
					print "1.{}.{} {:13} {:15} {:13} {:15} {:6} {:7} {:20}".format(
									slot_id,
									port_id, 
									port["enabled"],
									port["link"],
									port["lin"],
									port["domstatus"],
									port["optics"]["wavelength"],
									"Channel", 
									port["name"])
	if(opts.digital_diagnostics):
		print "{:5} {:10} {:10} {:10} {:10} {:10} {:10}".format("Port", "DDiags", "Temp(C)", "Supply(V)", "TxPower(dBm)", "RxPower(dBm)", "Bias(mA)")
		for slot_id in fd.get_chassis():
			slot = fd.get_chassis()[slot_id]
			if "ports" in slot and len(slot["ports"]) > 0:
				for port_id in slot["ports"]:
					port = slot["ports"][port_id]
					optic = port["optics"]

					if port["domstatus"] == 1:
						# Don't list ports where dom is not available
						continue

					def dom_status(x):
						return {
							2: "Ok"
						}.get(x, "N/A")


					print "1.{}.{} {:10} {:10} {:10} {:10} {:10} {:10}".format(
								slot_id,
								port_id,
								dom_status(port["domstatus"]),
								optic["temperature"],
								optic["voltage"],
								optic["txpower"],
								optic["rxpower"],
								optic["bias"]
								)
if __name__ == "__main__":
	main()
