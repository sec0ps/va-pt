#!/bin/bash
echo "Installing Packages"
sudo apt install -y make gcc ncftp rar p7zip-full curl libpcap-dev libssl-dev hping3 libssh-dev g++ arp-scan cewl wifite ruby-bundler freerdp2-dev
sudo apt install -y libsqlite3-dev nbtscan dsniff apache2 secure-delete autoconf libpq-dev libmysqlclient-dev libsvn-dev libssh-dev libsmbclient-dev
sudo apt install -y libgcrypt-dev libbson-dev libmongoc-dev python3-pip

#To Review for 20 inclusion
#sudo apt install -y  ruby-dev postgresql  python-lxml libxml2-dev libxslt1-dev python3-pip libncurses-dev
#sudo apt install -y firebird-dev  python-libpcap  libssh2-1-dev m4 smbclient 
#sudo apt install -y npm libgnutls28-dev libnetfilter-queue-dev libffi-dev 

echo "Installing Python Deps"
pip3 install dnspython
pip install crackmapexec
python -m pip install fierce

echo "Installing Ruby Gems"
sudo gem install bettercap wpscan

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

echo "Disbaling uneeded services from starting on boot"
sudo update-rc.d -f mysql remove && sudo update-rc.d -f apache2 remove
sudo update-rc.d -f cups remove && sudo update-rc.d -f cups-browsed remove



#sudo gem install bundler spider http_configuration mini_exiftool zip sqlite3 net-dns bettercap

#filtering stuff not needed on 18
#sudo apt-get install -y mysql-server iw ethtool dos2unix gtk-recordmydesktop postgresql
#sudo apt-get install -y    ruby-dev
#sudo apt-get install -y python-dev autoconf open-iscsi wireshark isc-dhcp-server libusb-dev 
#sudo apt-get install -y webhttrack finger rusers snmp reglookup gpsd libgps-dev apache2 libnet-ssh-perl kismet libnl-route-3-dev
#sudo apt-get install -y  libpq-dev  vim python-setuptools libmicrohttpd-dev horst kismet-plugins
#sudo apt-get install -y python-nltk python-soappy python-lxml python-svn python-scapy gtk2-engines-pixbuf graphviz python-gtksourceview2
#sudo apt-get install -y  libmysqlclient-dev libpcre3-dev   libidn11-dev libcurl4-gnutls-dev
#sudo apt-get install -y libxslt1-dev sipcrack libgmp3-dev python-mysqldb libnet1-dev flasm registry-tools python-pygraphviz
#sudo apt-get install -y libavahi-compat-libdnssd-dev gip ldap-utils bkhive ophcrack macchanger flamerobin dsniff sipsak libnetfilter-queue-dev
#sudo apt-get install -y ike-scan nfs-kernel-server httping ptunnel libaspell-dev autoconf libpcap-dev libnl-genl-3-200
#sudo apt-get install -y libyaml-dev default-jdk libreadline-dev python-pip python-beautifulsoup tshark libnl-genl-3-dev libnl-idiag-3-dev
#sudo apt-get install -y samba ldapscripts python-smbpasswd libevent-dev flex bison libgeoip-dev chntpw openconnect libffi-dev
##sudo apt-get install -y libnetfilter-conntrack-dev libncurses-dev liburcu-dev libnacl-dev zlib1g-dev libcli-dev python-pycurl vpnc
#sudo apt-get install -y ptunnel iodine udptunnel httptunnel netmask dnstracer dnswalk swig cmake libtalloc-dev libtevent-dev libpopt-dev
#sudo apt-get install -y libbsd-dev unixodbc unixodbc-dev freetds-dev sqsh tdsodbc autofs remmina remmina-plugin-rdp remmina-plugin-vnc
#sudo apt-get install -y squid python-libpcap ntpdate screen samba-common-bin upx whois libreadline-gplv2-dev gcc-mingw-w64-x86-64
#sudo apt-get install -y gcc-mingw-w64-i686 libsqlite3-dev tftp tftpd python-elixir python-pyasn1
#sudo apt-get install -y 

#sudo cpanm Encoding::BER && sudo cpanm Term::ANSIColor	
#sudo cpanm Getopt::Long && 
#sudo cpanm Socket && sudo cpanm Net::Whois::IP
#sudo cpanm Number::Bytes::Human && sudo cpanm Parallel::ForkManager
#sudo cpanm NetPacket::ICMP && 
##sudo cpanm LWP::UserAgent && sudo cpanm Object::InsideOut
#sudo cpanm  Test::Class && sudo cpanm WWW::Mechanize
#sudo cpanm Net::Whois::ARIN && sudo cpanm Test::MockObject
#sudo cpanm Template && sudo cpanm Net::CIDR
#sudo cpanm JSON && sudo cpanm Color::Output
#

#echo "Installing Python Deps"
#sudo pip uninstall pyasn1
#sudo pip install esmre pdfminer futures guess-language cluster msgpack-python python-ntlm clamd xdot
#sudo pip install lxml netaddr M2Crypto cherrypy mako M2Crypto dnspython requests capstone dicttoxml
#sudo pip install PyGithub GitPython pybloomfiltermmap esmre pdfminer futures guess-language 
#sudo pip install cluster msgpack-python python-ntlm clamd xdot netifaces pyinstaller wfuzz
#sudo pip install -e git+https://github.com/ramen/phply.git#egg=phply
#sudo pip install pbkdf2 pymongo ipcalc couchdb dicttoxml PyPDF2 olefile pyasn1 
#sudo pip3 install xcat
