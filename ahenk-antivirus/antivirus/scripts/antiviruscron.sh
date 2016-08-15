#!/bin/bash

while read -r line 
do 
	clamscan -irv $line --log=/var/log/usbscanlog
done < "/etc/ahenk/antivirusscanfolder"
