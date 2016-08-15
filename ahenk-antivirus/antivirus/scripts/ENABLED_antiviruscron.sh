#!/bin/bash

line="0 */$1 * * * /opt/ahenk/plugins/antivirus/scripts/antiviruscron.sh"
(crontab -u root -l; echo "$line" ) | crontab -u root -
