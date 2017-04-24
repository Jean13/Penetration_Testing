'''
Win race conditions!
Inject code before a file gets executed and then deleted.

Suggestion:
* Run the script for 24 hours or longer.
Interesting bugs and information disclosures on top of potential privilege escalations will likely be reported.

Ideas:
* Can save the output to a file.
* Can send the output to a remote server.

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

