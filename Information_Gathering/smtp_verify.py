#!/usr/bin/python

import socket
import sys
	
# Sends VRFY queries to SMTP to verify if a user exists

def smtp_verify(ip, user):
	# Create a socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Connect to the server
	connect = s.connect((ip, 25))
	# Receive the banner
	banner = s.recv(1024)
	print banner

	# VRFY a user
	s.send('VRFY ' + user + '\r\n')
	print "[*] Attempting to verify existance of user:", user
	result = s.recv(1024)
	print result

	# Close the socket
	s.close()


def main():
	if len(sys.argv) != 3:
		print "Usage: ./smtp_verify.py <IP address> <users file> \n"
		sys.exit(0)

	ip = sys.argv[1]
	user = sys.argv[2]
	with open(user, 'r') as f:
		for line in f:
			user = line
			smtp_verify(ip, user)

main()

