#!/bin/bash

while read -r line 
do 
	clamscan -irv $line --log=/var/log/clamavscanlog
done < "/opt/ahenk/plugins/antivirus/antivirusscanfolder"
