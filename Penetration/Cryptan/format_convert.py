#!/usr/bin/python

# Converts to hex, ascii, decimal, octal, binary, or little-endian.

import sys
from binascii import unhexlify, b2a_base64


def ascToHex(string):
	in_hex = string.encode('hex')
	return in_hex


def toLittleEndian(string):
	little_endian = '0x' + "".join(reversed([string[i:i+2] 
		for i in range(0, len(string), 2)]))
	return little_endian


def toDecimal(string):
	in_dec = int(string, 16)
	return in_dec


def toAscii(string):
	in_ascii = string.decode('hex')
	return in_ascii


def toOctal(string):
	in_oct = ""
	c = 0
	for char in string:
		c = ord(char)
		octa = oct(c)
		in_oct += ' ' + str(octa)
	return in_oct


def hexToBin(string):
	in_hex = int(string, 16)
	in_bin = bin(in_hex)[2:]
	return in_bin


def binToHex(string):
	in_hex = hex(int(string, 2))
	return in_hex


def decToHex(number):
	in_hex = hex(int(number))
	return in_hex


def hexToB64(string):
	raw = unhexlify(string)
	in_b64 = b2a_base64(raw)
	return in_b64

