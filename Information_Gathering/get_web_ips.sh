#!/bin/bash

if ["$1" == ""]
then
	echo "Usage: ./get_web_ips.sh <file with websites>"

else

	while read line; do
		host $line
		printf "\n"
	done < $1
fi
