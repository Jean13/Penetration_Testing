
'''
Suggestion:
Use py2exe to turn this script into a Windows executable.
Example: python setup.py py2exe

Run as administrator to store file under current path.
Change pathname if administrator level privilege is not possible.
'''

import win32gui
import win32ui
import win32con
import win32api

def win_screenshot_taker():
	# Grab a handle to the main desktop window
	fg_window = win32gui.GetDesktopWindow()

	# Determine the size of all monitors in pixels
	width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
	height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
	left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
	top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

	# Create a device context
	desktop_dc = win32gui.GetWindowDC(fg_window)
	img_dc = win32ui.CreateDCFromHandle(desktop_dc)

	# Create a memory-based device context
	mem_dc = img_dc.CreateCompatibleDC()

	# Create a bitmap object
	screenshot = win32ui.CreateBitmap()
	screenshot.CreateCompatibleBitmap(img_dc, width, height)
	mem_dc.SelectObject(screenshot)

	# Copy the screen into our memory device context
	mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)

	# Save the bitmap to a file
	screenshot.SaveBitmapFile(mem_dc, "c:\\WINDOWS\\Temp\\screenshot.bmp")

	# Free our objects
	mem_dc.DeleteDC()
	win32gui.DeleteObject(screenshot.GetHandle())

win_screenshot_taker()

