#!/bin/bash

if ["$1" == ""]
then
	echo "Usage: ./snmp-check_automate.sh <file with IP list>"

else

	while read line; do
		snmp-check $line
	done < $1
fi

