#!/usr/bin/python

'''
Caesar Cipher encryption and decryption.

'''

import sys

def getOption():
	do = raw_input("Do you wish to encrypt or decrypt a message?\n").lower()
	if do in "encrypt e decrypt d".split():
		return do

	elif do in "No no Quit quit exit Exit".split():
		sys.exit(0)

	else:
		print "Enter either 'encrypt' or 'e' or 'decrypt' or 'd'."


def getMessage():
	print "Enter your message:"
	return raw_input()


def getKey():
	MAX_KEY_SIZE = 26

	key = 0

	print "Enter the key number (1-{})".format(MAX_KEY_SIZE)
	key = int(raw_input())
	if key >= 1 and key <= MAX_KEY_SIZE:
		return key


def getConvertedMessage(do, message, key):
	if do[0] == 'd':
		key = -key
	converted = ""

	for symbol in message:
		if symbol.isalpha():
			num = ord(symbol)
			num += key

			if symbol.isupper():
				if num > ord('Z'):
					num -= 26
				elif num < ord('A'):
					num += 26
			elif symbol.islower():
				if num > ord('z'):
					num -= 26
				elif num < ord('a'):
					num += 26

			converted += chr(num)
		else:
			converted += symbol
	return converted

do = getOption()
message = getMessage()
key = getKey()

print "Your converted text is:"
print getConvertedMessage(do, message, key)

