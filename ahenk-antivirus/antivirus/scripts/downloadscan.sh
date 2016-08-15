#!/bin/bash

echo "$2 Scan Started" >> /var/log/usbscanlog
clamscan -riav --bell $1 --log=/var/log/usbscanlog
echo "$1 Scan Finished" 
