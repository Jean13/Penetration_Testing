'''
Screenshot grabber. 
Suggestions:
Add functionality to send images to a remote server.
'''


import time
import sys
import itertools
from os import system 


def mac_screenshot_taker():
    while True:
        try:
            for i in itertools.count():
                # -x option to mute the screenshot-taking sound
                system("screencapture -x /tmp/s{}.png".format(i))
                time.sleep(3)
        except KeyboardInterrupt:
            sys.exit(0)
            
mac_screenshot_taker()
