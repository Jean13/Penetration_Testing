'''
Notes:
In order to capture information about high-privilege processes created by SYSTEM, we need to run the monitoring script as Administrator.

Interesting Privileges:
* SeBackupPrivilege	- Enables the user process to back up files and directories;
			  Grants READ access to files no matter what their ACL defines.
* SeDebugPrivilege	- Enables the user process to debug other processes.
			  Includes obtaining process handles to inject DLLs or code into 
			  running processes.
* SeLoadDriver		- Enables a user process to load or unload drivers.

If loading the Windows API is not possible, the following can be translated into native calls by using the ctypes library.

Ideas:
* Find interesting file paths to monitor, such as software updates.

'''

import win32con
import win32api
import win32security

import wmi
import sys
import os


def get_process_privileges(pid):
	try:
		# Obtain a handle to the target process
		t_proc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)	

		# Open the main process token
		t_tok = win32security.OpenProcessToken(t_proc, win32con.TOKEN_QUERY)

		# Retrieve the list of enabled privileges
		privs = win32security.GetTokenInformation(t_tok, win32security.TokenPrivileges)

		# Iterate over privileges and output the ones that are enabled
		priv_list = ""
		for p in privs:
			# Check if the privilege is enabled
			if p[1] == 3:
				priv_list += "{} | ".format(win32security.LookupPrivilegeName(None, p[0]))

	except:
		priv_list = "N/A"

	return priv_list


def log_to_file(message):
	fd = open("process_monitor_log.csv", "ab")
	fd.write("{}\r\n".format(message))
	fd.close()

	return

def monitor_process():
	# Create a log file header
	log_to_file("Time, User, Executable, CommandLine, PID, Parent PID, Privileges")

	# Instantiate the WMI interface
	c = wmi.WMI()

	# Create the process monitor
	process_watcher = c.Win32_Process.watch_for("creation")

	while True:
		try:
			new_process = process_watcher()

			proc_owner = new_process.GetOwner()
			proc_owner = "{}\\{}".format(proc_owner[0], proc_owner[2])
			create_date = new_process.CreationDate
			executable = new_process.ExecutablePath
			cmdline = new_process.CommandLine
			pid = new_process.ProcessId
			parent_pid = new_process.ParentProcessId

			privileges = get_process_privileges(pid)

			process_log_message = "{}, {}, {}, {}, {}, {}, {}\r\n".format(create_date, proc_owner, executable, cmdline, pid, parent_pid, privileges)

			print process_log_message

			log_to_file(process_log_message)

		except:
			pass

monitor_process()

