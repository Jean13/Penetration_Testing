#!/bin/bash

if ["$1" == ""]
then
	echo "Usage: ./snmpwalk_automate.sh <target IP address>"

else

	# Enumerating the entire MIB tree
	echo "[*] Enumerating the entire MIB tree:"
	snmpwalk -c public -v1 $1
	# Enumerating Windows users
	echo -e "\n[*] Enumerating Windows users:"
	snmpwalk -c public -v1 $1 1.3.6.1.4.1.77.1.2.25
	# Enumerating running Windows processes
	echo -e "\n[*] Enumerating running Windows processes:"
	snmpwalk -c public -v1 $1 1.3.6.1.2.1.25.4.2.1.2
	# Enumerating open TCP ports
	echo -e "\n[*] Enumerating open TCP ports:"
	snmpwalk -c public -v1 $1 1.3.6.1.2.1.6.13.1.3
	# Enumerating installed software
	echo -e "\n[*] Enumerating installed software:"
	snmpwalk -c public -v1 $1 1.3.6.1.2.1.25.6.3.1.2
	echo -e "\n[*] Finished enumeration of IP address $1"
fi
