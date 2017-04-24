#!/usr/bin/python

'''
Caesar Cipher brute-force decryption.

'''

import string


def getMessage():
	print "Enter the message you want to decrypt:"
	return raw_input()


def caesar_bruteforce(message):
	alphabet = string.ascii_lowercase + string.ascii_uppercase
	for key in range(27):
		converted = ""

		for symbol in message:
			if symbol in alphabet:
				num = alphabet.find(symbol)
				num = num - key

				if num < 0:
					num = num + 26

				converted = converted + alphabet[num]

			else:
				converted = converted + symbol

		print "Key #{}: {}".format(key, converted)
	

message = getMessage()

print "\nYour converted text is:"
print caesar_bruteforce(message)
