'''
Netcat replacement in Python.

Suggestions:
* Run as Python script or as executable to suit your needs.
'''

import sys
import socket
import getopt
import threading
import subprocess


# Define global variables
listen			= False
command 		= False
upload 			= False
execute			= ""
target 			= ""
upload_destination 	= ""
port			= ""


def usage():
	print '''
<PyNet>\n
Usage: pynet.py -t <target_IP> -p <port>\n
Options: 
-l --listen 			: listen on <host>:<port> for incoming connections
-e --execute=<file to run>	: execute the given file upon receiving a connection
-c --command			: initialize a command shell
-u --upload=<destination>	: upon receiving a connection, upload a file and write to <destination>

Examples: 
pynet.py -t 192.168.0.1 -p 5555 -l -c
pynet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe
pynet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"
echo 'ABCDEFGHI' | ./pynet.py -t 192.168.11.12 -p 135
	'''
	sys.exit(0)


def client_sender(buffer):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		client.connect((target, port))
		
		if len(buffer):
			client.send(buffer)

		while True:
			# Wait for data
			recv_len = 1
			response = ""

			while recv_len:
				data = client.recv(4096)
				recv_len = len(data)
				response += data

				if recv_len < 4096:
					break

			print response

			# Wait for more input
			buffer = raw_input("")
			buffer += "\n"

			# Send the input
			client.send(buffer)

	except:
		print "[!] Error! Exiting..."
		client.close()


def server_loop():
	global target

	# If no target is defined, we listen on all interfaces
	if not len(target):
		target = "0.0.0.0"

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((target, port))
	server.listen(5)

	while True:
		client_socket, addr = server.accept()
		print "[+] Received connection from: {}".format(addr)

		# Spin off a thread to handle our new client
		client_thread = threading.Thread(target=client_handler,
		args=(client_socket,))
		client_thread.start()


def run_command(command):
	# Trim the newline
	command = command.rstrip()

	# Run the command and get the output back
	try:
		output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
	except:
		output = "[!] Failed to execute command.\r\n"

	# Send the output back to the client
	return output


def client_handler(client_socket):
	global upload
	global execute
	global command

	# Check for upload
	if len(upload_destination):
		# Read in all of the bytes and write to our destination
		file_buffer = ""

		# Keep reading data until none is available
		while True:
			data = client_socket.recv(1024)

			if not data:
				break
			else:
				file_buffer += data

		# Take the bytes and try to write them out
		try:
			file_descriptor = open(upload_destination, "wb")
			file_descriptor.write(file_buffer)
			file_descriptor.close()

			# Acknowledge that we wrote the file out
			client_socket.send("[+] Successfully saved file to: {}\r\n".format(upload_destination))

		except:
			client_socket.send("[!] Failed to save file to: {}\r\n".format(upload_destination))

	# Check for command execution
	if len(execute):
		# Run the command
		output = run_command(execute)
		client_socket.send(output)

	# Go into another loop if a command shell was requested
	if command:
		while True:
			# Show a simple prompt
			client_socket.send("<PyNet:#> ")

			# Receive until we see a linefeed <enter key>
			cmd_buffer = ""
			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)

			# Send back the command output
			response = run_command(cmd_buffer)

			# Send back the response
			client_socket.send(response)


def main():
	global listen
	global port
	global execute
	global command
	global upload_destination
	global target

	if not len(sys.argv[1:]):
		usage()

	# Read the command line options
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu", ["help", "listen", "execute", "target", "port", "command", "upload"])
	
	except:
		print str(err)
		usage()

	for o, a in opts:
		if o in ("-h", "--help"):
			usage()
		elif o in ("-l", "--listen"):
			listen = True
		elif o in ("-e", "--execute"):
			execute = a
		elif o in ("-c", "--commandshell"):
			command = True
		elif o in ("-u", "--upload"):
			upload_destination = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			port = int(a)
		else:
			assert False, "Unhandled Option"

	# Are we going to listen or just send data from stdin?
	if not listen and len(target) and port > 0:
		'''		
		Read in the buffer from the commandline this will block, 
		so send CTRL-D if not sending input to stdin
		'''
		print "[*] Press CTRL-D to enter an interactive shell."
		buffer = sys.stdin.read()

		# Send data
		client_sender(buffer)

	'''
	We are going to listen and potentially upload things, execute
	commands, and drop a shell back depending on our command line
	options
	'''
	if listen:
		server_loop()

main()

