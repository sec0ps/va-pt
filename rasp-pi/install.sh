#!/bin/bash
if [[ $EUID -eq 0 ]]; then
echo "This script should not be run as root.." 1>&2
exit 1
fi
echo "Updating and Installing Raspian Updates"
sudo apt-get update && sudo apt-get upgrade -y
echo "Setting the pi user to nologin - please do not use the pi user"
sudo usermod -s /usr/sbin/nologin pi
echo "You will need to enable ip_forwarding manually."
echo "Edit /etc/sysctl.conf and uncomment net.ipv4.ip_forward"
#
echo "Creating base directory for the toolset in /pentest"
if [ ! -d /pentest ] ; then
sudo mkdir /pentest
sudo chown -R $USER /pentest && chgrp -R $USER /pentest
fi
[ ! -d /pentest/temp ] && mkdir /pentest/temp
[ ! -d /pentest/wireless ] && mkdir /pentest/wireless
[ ! -d /pentest/exploits ] && mkdir /pentest/exploits
[ ! -d /pentest/exploits/powershell ] && mkdir /pentest/exploits/powershell
[ ! -d /pentest/web ] && mkdir /pentest/web
[ ! -d /pentest/scanners ] && mkdir /pentest/scanners
[ ! -d /pentest/misc ] && mkdir /pentest/misc
[ ! -d /pentest/enumeration ] && mkdir /pentest/enumeration
[ ! -d /pentest/voip ] && mkdir /pentest/voip
[ ! -d /pentest/database ] && mkdir /pentest/database
[ ! -d /pentest/passwords ] && mkdir /pentest/passwords
[ ! -d /pentest/fuzzers ] && mkdir /pentest/fuzzers
[ ! -d /pentest/cisco ] && mkdir /pentest/cisco
#
cd /pentest/misc && git clone https://github.com/sec0ps/va-pt.git
echo "Creating the wireless management interface"
sudo mv interfaces /etc/network/
sudo service networking restart
#sudo ifdown wlan0 && sudo ifup wlan0
#
#allowing ssh tunneling
sudo cp sshd_config /etc/ssh/ && sudo service ssh restart

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
     echo "4 - Update all tool packages"
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
         4 ) /pentest/misc/va-pt/update-tools.sh;;
         0 ) exit;;
         * ) echo "Please enter your selection"
     esac
done
