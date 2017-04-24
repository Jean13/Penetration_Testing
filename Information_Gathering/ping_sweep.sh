#!/bin/bash

if [ "$1" == "" ]
then
	echo "Usage: ./ping_sweep.sh [network]"
	echo "example: ./ping_sweep.sh 10.11.1"

else

	for ip in $(seq 1 254); do
		ping -c 1 $1.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
	done
fi
