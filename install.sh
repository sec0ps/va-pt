#!/bin/bash
if [[ $EUID -eq 0 ]]; then
echo "This script should not be run as root.." 1>&2
exit 1
fi
echo "Installing base packages and locking down the system - denying all inbound services excluding ssh and allowing all outbound"
sudo apt install vim subversion landscape-common ufw openssh-server net-tools libpangox-1.0-dev mlocate ntpdate screen whois
sudo apt-get install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable

if [ ! -f /etc/network/if-up.d/ntpdate ] ; then
sudo ntpdate time.nist.gov
fi

if [ ! -d /vapt ] ; then
sudo mkdir /vapt
sudo chown -R $USER /vapt && chgrp -R $USER /vapt
fi
[ ! -d /vapt/wireless ] && mkdir /vapt/wireless
[ ! -d /vapt/exploits ] && mkdir /vapt/exploits
[ ! -d /vapt/web ] && mkdir /vapt/web
[ ! -d /vapt/intel ] && mkdir /vapt/intel 
[ ! -d /vapt/scanners ] && mkdir /vapt/scanners
[ ! -d /vapt/misc ] && mkdir /vapt/misc
[ ! -d /vapt/enumeration ] && mkdir /vapt/enumeration
[ ! -d /vapt/passwords ] && mkdir /vapt/passwords
[ ! -d /vapt/fuzzers ] && mkdir /vapt/fuzzers
#[ ! -d /vapt/audit ] && mkdir /vapt/audit
[ ! -d /vapt/exfiltrate ] && mkdir /vapt/exfiltrate
if [ ! -d /vapt/misc/va-pt ] ; then
cd /vapt/misc && git clone https://github.com/sec0ps/va-pt.git 
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
         1 ) /vapt/misc/va-pt/deps.sh;;
         2 ) /vapt/misc/va-pt/svn.sh;;
         3 ) /vapt/misc/va-pt/static.sh;;
	 4 ) sudo apt-get install -y openvas-server openvas-client;;
	 4 ) /vapt/misc/va-pt/wordlist.sh;;
	 6 ) sudo apt-get install -y nvidia-opencl-dev ocl-icd-libopencl1 opencl-headers;;
         7 ) /vapt/misc/va-pt/update-tools.sh;;
         8 ) firefox https://addons.mozilla.org/en-US/firefox/collections/sec0ps/vapt/ &;;
         0 ) exit;;
         * ) echo "Please enter your selection"
     esac
done
