#!/bin/bash
if [[ $EUID -eq 0 ]]; then
echo "This script must not be run as root.." 1>&2
exit 1
fi
#sudo echo 1 > /proc/sys/net/ipv4/ip_forward
#clear
if [ ! -d /pentest ] ; then
sudo mkdir /pentest
sudo chown -R $USER /pentest && chgrp -R $USER /pentest
fi
[ ! -d /pentest/temp ] && mkdir /pentest/temp
[ ! -d /pentest/wireless ] && mkdir /pentest/wireless
[ ! -d /pentest/exploits ] && mkdir /pentest/exploits
[ ! -d /pentest/exploits/exploitdb ] && mkdir /pentest/exploits/exploitdb
[ ! -d /pentest/web ] && mkdir /pentest/web
[ ! -d /pentest/scanners ] && mkdir /pentest/scanners
[ ! -d /pentest/misc ] && mkdir /pentest/misc
[ ! -d /pentest/enumeration ] && mkdir /pentest/enumeration
[ ! -d /pentest/voip ] && mkdir /pentest/voip
[ ! -d /pentest/database ] && mkdir /pentest/database
[ ! -d /pentest/passwords ] && mkdir /pentest/passwords
[ ! -d /pentest/fuzzers ] && mkdir /pentest/fuzzers
[ ! -d /pentest/spoofing ] && mkdir /pentest/spoofing
[ ! -d /pentest/cisco ] && mkdir /pentest/cisco
#creating the wireless management interface - recommended the usb wireless adapater be in before running the installer
sudo mv interfaces /etc/network/ && sleep 2
sudo ifdown wlan0 && sudo ifup wlan0
sleep 2
#
if [ ! -d /pentest/misc/va-pt ] ; then
cd /pentest/misc && svn checkout http://va-pt.googlecode.com/svn/trunk/ va-pt
#allowing ssh tunneling
sudo cp sshd_config /etc/ssh/ && sudo service ssh restart
fi

clear
selection=
until [ "$selection" = "0" ]; do
     echo ""
     echo "|\     /|(  ___  )       (  ____ )\__   __/"
     echo "| )   ( || (   ) |       | (    )|   ) (   "
     echo "| |   | || (___) | _____ | (____)|   | |   "
     echo "( (   ) )|  ___  |(_____)|  _____)   | |   "
     echo " \ \_/ / | (   ) |       | (         | |   "
     echo "  \   /  | )   ( |       | )         | |   "
     echo "   \_/   |/     \|       |/          )_(   "
     echo ""
     echo "The Vulnerability Assessment and Penetration Testing Toolkit"
     echo ""
     echo "VA/PT PROGRAM MENU"
     echo "1 - Install Dependencies"
     echo "2 - Install SVN Toolkits"
     echo "3 - Install Static Code Software"
     echo "4 - Install/Update Exploit Code Repositories"
     echo "5 - Update all tool packages"
     echo ""
     echo "0 - Exit program"
     echo ""
     echo -n "Enter Selection:"
     read selection
     echo ""
     case $selection in
         1 ) /pentest/misc/va-pt/rasp-pi/deps.sh;;
         2 ) /pentest/misc/va-pt/rasp-pi/svn.sh;;
         3 ) /pentest/misc/va-pt/rasp-pi/static.sh;;
         4 ) /pentest/misc/va-pt/rasp-pi/exploits.sh;;
         5 ) /pentest/misc/va-pt/update-tools.sh;;
         0 ) exit;;
         * ) echo "Please enter your selection"
     esac
done
