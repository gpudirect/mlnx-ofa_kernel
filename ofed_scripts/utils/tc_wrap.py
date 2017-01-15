#!/usr/bin/python

import sys
import os
import re
from subprocess import Popen, PIPE
from collections import defaultdict
from optparse import OptionParser

tctool = 'tc'
port_num = 1
max_tc_num = "8"
skprio2tos = { 0 : 0, 2 : 8, 4 : 24, 6 : 16 }

class skprio2up:
	def __init__(self, path, intf):
		self.path = path
		self.map = []
		self.intf = intf
		self.up2skprio = defaultdict(list)
		if (options.skprio_up is not None):
			self.parse_args(options.skprio_up.split(","))


	def get_tagged(self):
	        output = Popen('grep -H "EGRESS" /proc/net/vlan/' + self.intf +
	                        "* 2> /dev/null", shell=True, bufsize=4096,
	                        stdout=PIPE).stdout
	        for line in output:
	                param, val=line.strip().split(":", 1)
	                vlan = param.split('.')[-1]
	                for item in val.split(":", 1)[1].split():
	                        skprio, up = item.split(':')
	                        skprio = int(skprio)
	                        str = "%d (vlan %s" % (skprio, vlan)
	                        if skprio2tos.get(skprio):
	                           str += " tos: %d" % (skprio2tos[skprio])
	                        str += ")"
	                        self.up2skprio[int(up)].append(str)

	def refresh(self):
	        skprio = 0
	        for up in self.map:
	                s = str(skprio)
	                if skprio2tos.get(skprio):
	                        s += " (tos: %s)" % (str(skprio2tos[skprio]))
	                self.up2skprio[int(up)].append(s)
	                skprio += 1
	        self.get_tagged()

	def parse_args(self, new):
		for i, up in enumerate(new):
			_up = int(up)
			if (_up > 8 or _up < 0):
				print "Bad user prio: %s - should be in the range: 0-7" % up
				sys.exit(1)

			self.map.append(up)

	def set(self, new):
		self.parse_args(new)
		self.refresh()
		f = open(self.path, "w")
		f.write(" ".join(self.map).strip())
		f.close()

	def get(self):
		f = open(self.path, "r")
		self.map = f.read().split()
		f.close()

class tcnum:
	def __init__(self, intf):
		self.map = []
		self.intf = intf
		self.tc_num = str(8)

	def set(self, dummy):
		raise NotImplementedError("Setting skprio<=>up mapping is not implemented yet")

class tcnum_sysfs(tcnum):
	def __init__(self, path, intf):
		tcnum.__init__(self, intf)
		self.path = path


	def set(self, new):
		f = open(self.path, "w")
		f.write(new)
		f.close()

	def get(self):
		f = open(self.path, "r")
		self.tc_num = f.read()
		f.close()


class tcnum_mqprio(tcnum):
	def __init__(self, intf):
		tcnum.__init__(self, intf)


	def set(self, new):
		try:
			output = Popen("%s qdisc del dev %s root" % (tctool, self.intf),
					shell=True,
					bufsize=4096, stdout=PIPE, stderr=PIPE).stdout

			output = Popen("%s qdisc add dev %s root mqprio num_tc %s" % (tctool,
					self.intf, new),
					shell=True,
					bufsize=4096, stdout=PIPE).stdout

		except:
			print "QoS is not supported via mqprio"
			sys.exit(1)

	def get(self):
		empty = True
		output = Popen(tctool + " qdisc show dev " + self.intf, shell=True,
				bufsize=4096, stdout=PIPE).stdout

		for line in output:
			empty=False
			m = re.search(r'tc (\d)', line)
			if m:
				self.tc_num = m.group(1)

		if (empty):
			raise IOError("tc tool returned empty output")



if __name__ == "__main__":
	parser = OptionParser(usage="%prog -i <interface> [options]", version="%prog 1.0")

	parser.add_option("-i", "--interface", dest="intf",
			  help="Interface name")

	parser.add_option("-u", "--skprio_up", dest="skprio_up",
			help="maps sk_prio to priority for RoCE. LIST is <=16 comma seperated priority. " +
			"index of element is sk_prio.")


	(options, args) = parser.parse_args()

	if (options.intf == None):
		print "Interface name is required"
		parser.print_usage()

		sys.exit(1)


	empty = True
	output = Popen("ibdev2netdev", shell=True,
			bufsize=4096, stdout=PIPE).stdout

	for line in output:
		m = re.search(r'port (\d+) ==> (\w+)', line)
		if m:
			if (m.group(2) == options.intf):
				empty=False
				port_num = m.group(1)
	if (empty):
		print "Could not find interface " + options.intf + " in ibdev2netdev output"
		sys.exit(1)


# try using sysfs - if not exist fallback to tc tool
	tc_num_path = "/sys/class/net/" + options.intf + "/qos/tc_num"
	skprio2up_path = "/sys/class/infiniband/mlx4_0/ports/" + str(port_num)+"/skprio2up"

	try:
		if (os.path.exists(tc_num_path)):
			tcnum = tcnum_sysfs(tc_num_path, options.intf)
		else:
			tcnum = tcnum_mqprio(options.intf)

	except Exception, e:
		print e
		sys.exit(1)


	tcnum.set(max_tc_num)

	try:
		skprio2up = skprio2up(skprio2up_path, options.intf)

		if (os.path.exists(skprio2up_path) and options.skprio_up is not None):
			skprio2up.set(options.skprio_up.split(","))
		else:
			if (options.skprio_up is not None):
				print "skprio2up is availabe only for RoCE in kernels that don't support set_egress_map"

	except Exception, e:
		print e
		sys.exit(1)


	tcnum.get()
	print "Tarrfic classes are set to " + tcnum.tc_num

	skprio2up.refresh()

	for up in range(8):
		print "UP ", up
		for skprio in skprio2up.up2skprio[int(up)]:
			print "\tskprio: " + skprio