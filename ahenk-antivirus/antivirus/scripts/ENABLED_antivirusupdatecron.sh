#!/bin/bash

line="*/$1 * * * * /opt/ahenk/plugins/antivirus/scripts/antivirusupdatecron.sh"
(crontab -u root -l; echo "$line" ) | crontab -u root -
