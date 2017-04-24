#!/usr/bin/python


import re
import pyperclip


print("[!] Before running the script, make sure to edit the top-level domain.")
print("[*] The current default is: .mil")
file_name = raw_input("\nEnter the filename you would like the output to save as: ")


web_regex = re.compile(r'''(
        [a-zA-Z0-9.-]+          # Domain name
        (\.mil)			# .mil
        )''', re.VERBOSE)


# Find matches in clipboard text
text = str(pyperclip.paste())
matches = []


for groups in web_regex.findall(text):
    matches.append(groups[0])


# Copy results to the clipboard
if len(matches) > 0:
	# Join since pyperclip.copy() takes only a single string, not a list of strings
	pyperclip.copy('\n'.join(matches))
	#print('Copied to clipboard:')
	#print('\n'.join(matches))
	with open(file_name, 'a+') as f:
		f.write('\n'.join(matches))
	f.close()

else:
	print('No websites found.')
