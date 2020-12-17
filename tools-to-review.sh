#Deps to be reviewed
#echo "Installing Ruby Gems"
#sudo gem install bundler spider http_configuration mini_exiftool zip sqlite3 net-dns bettercap
#sudo gem uninstall bettercap wpscan

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

#To Review for 20 inclusion
#sudo apt install -y  postgresql  python-lxml libxml2-dev libxslt1-dev python3-pip libncurses-dev
#sudo apt install -y firebird-dev  python-libpcap  libssh2-1-dev m4 smbclient 
#sudo apt install -y npm libgnutls28-dev libnetfilter-queue-dev libffi-dev 

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

#Toos to be reviewed
echo "Beginning subverion package installation"
if [ ! -d /vapt/wireless/giskismet ] ; then
echo "Installing gisKismet"
cd /vapt/wireless && git clone https://github.com/xtr4nge/giskismet.git
cd /vapt/wireless/giskismet && sudo cpanm --installdeps .
sudo perl Makefile.PL && make
sudo make install
fi

if [ ! -d /vapt/fuzzers/sulley ] ; then
echo "Installing Sulley"
cd /vapt/fuzzers && git clone https://github.com/OpenRCE/sulley.git 
fi

if [ ! -d /vapt/web/joomscan ] ; then
echo "Instaling Joomla Scanner"
cd /vapt/web/ && git clone https://github.com/rezasp/joomscan.git
fi

if [ ! -d /var/www/html/beef ] ; then
echo "Installing Beef"
cd /var/www/html && sudo git clone https://github.com/beefproject/beef.git
fi

if [ ! -d /vapt/fuzzers/fuzzdb ] ; then
echo "Installing FuzzDB"
cd /vapt/fuzzers && git clone https://github.com/fuzzdb-project/fuzzdb.git
fi
if [ ! -d /vapt/fuzzers/jbrofuzz ] ; then
echo "Installing JBroFuzz"
cd /vapt/fuzzers && git clone https://github.com/twilsonb/jbrofuzz.git
fi

if [ ! -d /vapt/passwords/ntlmsspparse ] ; then
echo "Installing NTLMS Parse"
cd /vapt/passwords && git clone https://github.com/psychomario/ntlmsspparse.git
fi

if [ ! -d /vapt/scanners/groupenum ] ; then
echo "Installing Spiderlabs groupenum"
cd /vapt/scanners/ && git clone https://github.com/SpiderLabs/groupenum.git
fi

if [ ! -d /vapt/wireless/weape ] ; then
echo "Installing Wireless EAP Username Extractor"
cd /vapt/wireless && git clone https://github.com/commonexploits/weape.git
fi

if [ ! -d /vapt/passwords/PCredz ] ; then
echo "Installing PCredz"
cd /vapt/passwords && git clone https://github.com/lgandx/PCredz.git
fi
if [ ! -d /vapt/exploits/pth-toolkit ] ; then
echo "Installing the PTH Toolkit"
cd /vapt/exploits && git clone https://github.com/byt3bl33d3r/pth-toolkit.git
fi
if [ ! -d /vapt/passwords/gpp-decrypt ] ; then
echo "Installing gpp-dercypt"
cd /vapt/passwords && git clone https://github.com/BustedSec/gpp-decrypt.git
fi

if [ ! -d /vapt/exploits/PowerSploit ] ; then
echo "Installing PowerSploit"
cd /vapt/exploits/ && git clone https://github.com/mattifestation/PowerSploit.git
fi
if [ ! -d /vapt/exploits/ps1encode ] ; then
echo "Installing Powershell Encoder"
cd /vapt/exploits/ && git clone https://github.com/CroweCybersecurity/ps1encode.git
fi
if [ ! -d /vapt/exploits/Invoke-TheHash ] ; then
echo "Installing Powershell Invoke-TheHash"
cd /vapt/exploits/ && git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
fi
if [ ! -d /vapt/exploits/PowerShdll ] ; then
echo "Installing Power Shell DLL"
cd /vapt/exploits/ && git clone https://github.com/p3nt4/PowerShdll.git
fi

if [ ! -d /vapt/web/XSStrike ] ; then
echo "Installing XSStrike"
cd /vapt/web && git clone https://github.com/UltimateHackers/XSStrike
cd XSStrike && sudo pip install -r requirements.txt
fi
if [ ! -d /vapt/web/xsser ] ; then
echo "Installing XSSer"
cd /vapt/web/ && git clone https://github.com/epsylon/xsser-public.git xsser
fi


if [ ! -d /vapt/database/NoSQLMap ] ; then
echo "Installing NoSQLMAP"
cd /vapt/database && git clone https://github.com/tcstool/NoSQLMap.git
fi

if [ ! -d /vapt/web/droopescan ] ; then
echo "Installing Droopescan"
cd /vapt/web && git clone https://github.com/droope/droopescan.git droopescan
fi
if [ ! -d /vapt/scanners/sublist3r ] ; then
echo "Installing sublist3r"
cd /vapt/scanners && git clone https://github.com/aboul3la/Sublist3r.git sublist3r
fi
if [ ! -d /vapt/web/weevely ] ; then
echo "Installing weevely"
cd /vapt/web && git clone https://github.com/epinna/weevely3.git weevely
fi
if [ ! -d /vapt/exploits/spraywmi ] ; then
echo "Installing spraywmi"
cd /vapt/exploits && git clone https://github.com/trustedsec/spraywmi.git
fi

if [ ! -d /vapt/scanners/enum4linux ] ; then
echo "Installing Windows Enum Tools"
cd /vapt/scanners/ && git clone https://github.com/portcullislabs/enum4linux.git
cd /vapt/temp && wget http://labs.portcullis.co.uk/download/polenum-0.2.tar.bz2 --no-check-certificate
bunzip2 polenum-0.2.tar.bz2 && tar xvf polenum-0.2.tar
rm -rf polenum-0.2.tar && sudo mv polenum-0.2/polenum.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/polenum.py && rm -rf rm -rf polenum-0.2/
fi

if [ ! -d /vapt/wireless/asleap ] ; then
echo "Installing asleap"
cd /vapt/wireless/ && git clone https://github.com/joswr1ght/asleap.git
cd asleap && make
fi

if [ ! -d /vapt/web/ShortShells ] ; then
echo "Instlling Short Shells - web shell collection"
cd /vapt/web && git clone https://github.com/modux/ShortShells.git
fi
if [ ! -d /vapt/scanners/thc-ipv6 ] ; then
echo "Installing THC IPv6"
cd /vapt/scanners/ && git clone https://github.com/vanhauser-thc/thc-ipv6.git
cd thc-ipv6 && make
fi
if [ ! -d /vapt/web/svn-extractor ] ; then
echo "Installing SVN Extractor"
cd /vapt/web && git clone https://github.com/anantshri/svn-extractor.git
fi

echo "Installing local tools"
cp /vapt/misc/va-pt/tools/copy-router-config.pl /vapt/cisco/
cp /vapt/misc/va-pt/tools/merge-router-config.pl /vapt/cisco/
cp /vapt/misc/va-pt/tools/dnsrecon.rb /vapt/scanners/
cp /vapt/misc/va-pt/tools/mysqlaudit.py /vapt/database/
# end installer

