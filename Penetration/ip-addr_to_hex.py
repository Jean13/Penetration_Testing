#!/usr/bin/python

import sys


def toLittleEndian(string):
	little_endian = '0x' + "".join(reversed([string[i:i+2] 
		for i in range(0, len(string), 2)]))
	return little_endian


def main():
	if len(sys.argv[1:]) != 4:
		print "ip-addr_to_hex.py: Convert an IPv4 address to hex."
		print "Example: ./ip-addr_to_hex.py 10 11 0 128\n"
		sys.exit(0)

	# Original input
	i1 = int(sys.argv[1])
	i2 = int(sys.argv[2])
	i3 = int(sys.argv[3])
	i4 = int(sys.argv[4])

	ip4 = i4 * (256 ** 0)
	ip3 = i3 * (256 ** 1)
	ip2 = i2 * (256 ** 2)
	ip1 = i1 * (256 ** 3)

	# Decimal representation
	ip_dec = ip4 + ip3 + ip2 + ip1

	in_hex = hex(ip_dec)
	little_endian = toLittleEndian(in_hex)
	print 'Hex:', in_hex
	print 'Little-endian:', little_endian[:-2]

main()

