#!/bin/bash
if [[ $EUID -eq 0 ]]; then
echo "This script should not be run as root.." 1>&2
exit 1
fi
sudo apt install ntpdate -y
if [ ! -f /etc/network/if-up.d/ntpdate ] ; then
sudo ntpdate time.nist.gov
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
#[ ! -d /pentest/audit ] && mkdir /pentest/audit
[ ! -d /pentest/exfiltrate ] && mkdir /pentest/exfiltrate
if [ ! -d /pentest/misc/va-pt ] ; then
cd /pentest/misc && git clone https://github.com/sec0ps/va-pt.git 
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
     echo "4 - Install OpenVAS"
     echo "5 - Install Weakpass and wordlists (30+ gig)"
     echo "6 - Install Nvidia / OpenCL Headers"
     echo "7 - Update all tool packages"
     echo "8 - Install Firefox Extensions"
     echo ""
     echo "0 - Exit program"
     echo ""
     echo -n "Enter Selection:"
     read selection
     echo ""
     case $selection in
         1 ) /pentest/misc/va-pt/ubuntu18/deps.sh;;
         2 ) /pentest/misc/va-pt/ubuntu18/svn.sh;;
         3 ) /pentest/misc/va-pt/ubuntu18/static.sh;;
	 4 ) sudo apt-get install -y openvas-server openvas-client;;
	 4 ) /pentest/misc/va-pt/ubuntu18/wordlist.sh;;
	 6 ) sudo apt-get install -y nvidia-opencl-dev ocl-icd-libopencl1 opencl-headers;;
         7 ) /pentest/misc/va-pt/update-tools.sh;;
         8 ) firefox https://addons.mozilla.org/en-US/firefox/collections/sec0ps/vapt/ &;;
         0 ) exit;;
         * ) echo "Please enter your selection"
     esac
done
