#!/bin/bash

if ["$1" == ""]
then
	echo "Usage: ./enum4linux_scan-range.sh <file with IP list>"

else

	while read line; do
		enum4linux -a $line
	done < $1
fi
