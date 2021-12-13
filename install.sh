#!/bin/bash
if [[ $EUID -eq 0 ]]; then
echo "This script should not be run as root.." 1>&2
exit 1
fi
echo "Installing base packages and locking down the system - denying all inbound services excluding ssh and allowing all outbound"
echo "This may take a few minutes.."
sudo apt update && sudo apt upgrade -y
sudo apt install -y vim subversion landscape-common ufw openssh-server net-tools libpangox-1.0-dev mlocate ntpdate screen whois kate libtool-bin
sudo apt install -y make gcc ncftp rar p7zip-full curl libpcap-dev libssl-dev hping3 libssh-dev g++ arp-scan wifite ruby-bundler freerdp2-dev
sudo apt install -y libsqlite3-dev nbtscan dsniff apache2 secure-delete autoconf libpq-dev libmysqlclient-dev libsvn-dev libssh-dev libsmbclient-dev
sudo apt install -y libgcrypt-dev libbson-dev libmongoc-dev python3-pip netsniff-ng httptunnel ptunnel-ng udptunnel pipx python3-venv ruby-dev
sudo apt install -y minicom default-jre gnome-tweaks macchanger recordmydesktop
wget http://old.kali.org/kali/pool/main/i/icu/libicu63_63.2-2_amd64.deb && sudo apt install -y ./libicu63_63.2-2_amd64.deb
rm libicu63_63.2-2_amd64.deb
sudo ln -s /usr/bin/python3 /usr/bin/python
sudo snap install powershell --classic

echo "Installing Kismet"
wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key | sudo apt-key add -
echo 'deb https://www.kismetwireless.net/repos/apt/release/focal focal main' | sudo tee /etc/apt/sources.list.d/kismet.list
sudo apt update
sudo apt install -y kismet

sudo ntpdate time.nist.gov
sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 4444/tcp
sudo ufw enable

if [ ! -d /vapt ] ; then
sudo mkdir /vapt
sudo chown -R $USER /vapt && chgrp -R $USER /vapt
fi
[ ! -d /vapt/temp ] && mkdir /vapt/temp
[ ! -d /vapt/wireless ] && mkdir /vapt/wireless
[ ! -d /vapt/exploits ] && mkdir /vapt/exploits
[ ! -d /vapt/web ] && mkdir /vapt/web
[ ! -d /vapt/intel ] && mkdir /vapt/intel 
[ ! -d /vapt/scanners ] && mkdir /vapt/scanners
[ ! -d /vapt/misc ] && mkdir /vapt/misc
[ ! -d /vapt/passwords ] && mkdir /vapt/passwords
[ ! -d /vapt/fuzzers ] && mkdir /vapt/fuzzers
[ ! -d /vapt/audit ] && mkdir /vapt/audit
[ ! -d /vapt/powershell ] && mkdir /vapt/powershell
[ ! -d /vapt/exfiltrate ] && mkdir /vapt/exfiltrate
if [ ! -d /vapt/misc/va-pt ] ; then
cd /vapt/misc && git clone https://github.com/sec0ps/va-pt.git 
fi
if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /vapt/temp && git clone https://github.com/miyagawa/cpanminus.git
cd cpanminus/App-cpanminus && perl Makefile.PL
make && sudo make install
cd /vapt/temp && rm -rf cpanminus/
fi
echo "Checking and Installing PERL Deps"
sudo cpanm Cisco::CopyConfig && sudo cpanm Net::Netmask
sudo cpanm XML::Writer && sudo cpanm String::Random
sudo cpanm Net::IP && sudo cpanm Net::DNS
echo "Installing Python Packages and Dependencies"
pip3 install dnspython
python3 -m pip install pipx
pipx ensurepath && pipx install crackmapexec
echo "Disbaling uneeded services from starting on boot"
sudo update-rc.d -f mysql remove && sudo update-rc.d -f apache2 remove
sudo update-rc.d -f cups remove && sudo update-rc.d -f cups-browsed remove
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
     echo "1 - Install SVN Toolkits"
     echo "2 - Install Static Code Software"
     echo "3 - Install OpenVAS"
     echo "4 - Install Weakpass and wordlists (30+ gig)"
     echo "5 - Install Nvidia / OpenCL Headers"
     echo "6 - Install Firefox Extensions"
     echo ""
     echo "0 - Exit program"
     echo ""
     echo -n "Enter Selection:"
     read selection
     echo ""
     case $selection in
         1 ) /vapt/misc/va-pt/svn.sh;;
         2 ) /vapt/misc/va-pt/static.sh;;
         3 ) sudo apt install -y openvas;;
	     4 ) /vapt/misc/va-pt/wordlist.sh;;
         5 ) sudo apt-get install -y nvidia-opencl-dev ocl-icd-libopencl1 opencl-headers;;
         6 ) firefox https://addons.mozilla.org/en-US/firefox/collections/sec0ps/vapt/ &;;
         0 ) exit;;
         * ) echo "Please enter your selection"
     esac
done
