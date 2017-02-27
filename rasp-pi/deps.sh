echo "Installing UFW, denying all inbound services excluding ssh and allowing all outbound"
sudo apt-get install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

echo "Installing Packages"
sudo apt-get install -y mysql-server subversion git ncftp p7zip-full iw ethtool dos2unix postgresql
sudo apt-get install -y sqlite3 nbtscan dsniff libncurses-dev libpcap-dev libssl-dev hping3 openssh-server
sudo apt-get install -y python-dev autoconf open-iscsi wireshark isc-dhcp-server locate libusb-dev
sudo apt-get install -y webhttrack finger rusers snmp reglookup gpsd libgps-dev apache2 libnet-ssh-perl
sudo apt-get install -y kismet curl sslscan libpq-dev libxml2-dev vim python-setuptools
sudo apt-get install -y python-soappy python-lxml python-svn python-scapy gtk2-engines-pixbuf graphviz python-gtksourceview2
sudo apt-get install -y libssh-dev libmysqlclient-dev libpcre3-dev firebird-dev libsvn-dev libidn11-dev libcurl4-gnutls-dev
sudo apt-get install -y libxslt1-dev sipcrack libgmp3-dev python-mysqldb libnet1-dev flasm registry-tools
sudo apt-get install -y libavahi-compat-libdnssd-dev gip ldap-utils bkhive ophcrack macchanger flamerobin sipsak
sudo apt-get install -y ike-scan nfs-kernel-server httping ptunnel recoverdm extundelete ext3grep libaspell-dev autoconf
sudo apt-get install -y libyaml-dev openjdk-7-jre openjdk-7-jre-lib libreadline-dev python-pip python-beautifulsoup tshark
sudo apt-get install -y samba libpam-smbpass libevent-dev flex bison libgeoip-dev chntpw crunch python-pygraphviz
sudo apt-get install -y libnetfilter-conntrack-dev libncurses-dev liburcu-dev zlib1g-dev libcli-dev python-pycurl vpnc
sudo apt-get install -y ptunnel iodine udptunnel httptunnel netmask dnstracer dnswalk swig cmake libtalloc-dev libtevent-dev libpopt-dev
sudo apt-get install -y libbsd-dev unixodbc unixodbc-dev freetds-dev sqsh tdsodbc autofs remmina remmina-plugin-rdp remmina-plugin-vnc
sudo apt-get install -y squid python-libpcap ntpdate screen samba-common-bin upx whois libreadline-gplv2-dev libsqlite3-dev
sudo apt-get install -y python-elixir zip tftp tftpd libfreerdp-dev libssh2-1-dev mingw32-runtime mingw32-binutils python-pyasn1

ruby -v | grep "2.3.3"
if [ $? -eq 1 ] ; then
echo "Installing Ruby 2.3.3"
echo "This is going to take awhile, take a break..."
cd /pentest/temp && wget wget https://cache.ruby-lang.org/pub/ruby/2.3/ruby-2.3.3.tar.gz
tar xvf ruby-2.3.3.tar.gz && rm -rf ruby-2.3.3.tar.gz
cd ruby-2.3.3 && ./configure && make
sudo make install
fi
if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone https://github.com/miyagawa/cpanminus.git 
cd cpanminus && perl Makefile.PL
make && sudo make install
cd /pentest/temp && rm -rf cpanminus/
fi
if [ ! -f /usr/local/lib/perl/5.18.2/Math/Pari.pm ] ; then
echo "Installing PERL Libraries"
cd /pentest/temp && wget ftp://pari.math.u-bordeaux.fr/pub/pari/unix/OLD/2.1/pari-2.1.7.tgz 
tar xvf pari.tgz && rm -rf pari.tgz
cd pari-2.9.0/ && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080900.zip 
unzip Math-Pari-2.01080900.zip && rm -rf Math-Pari-2.01080900.zip
cd Math-Pari-2.0108090z0 && perl Makefile.PL
sudo make install
else
echo "Pari is installed, moving on"
fi

echo "Checking and Installing PERL Deps"
sudo cpanm Cisco::CopyConfig && sudo cpanm Net::Telnet
sudo cpanm Net::Netmask && sudo cpanm XML::Writer
sudo cpanm Encoding::BER && sudo cpanm Term::ANSIColor
sudo cpanm Getopt::Long && sudo cpanm XML::Writer
sudo cpanm Socket && sudo cpanm Net::Whois::IP
sudo cpanm Number::Bytes::Human && sudo cpanm Parallel::ForkManager
sudo cpanm NetPacket::ICMP && sudo cpanm String::Random
sudo cpanm LWP::UserAgent && sudo cpanm Object::InsideOut
sudo cpanm  Test::Class && sudo cpanm WWW::Mechanize
sudo cpanm Net::Whois::ARIN && sudo cpanm Test::MockObject
sudo cpanm Template && sudo cpanm Net::CIDR
sudo cpanm JSON && sudo cpanm Color::Output
sudo cpanm Net::IP
#sudo cpanm Net::SSH::Perl

echo "Installing Python Deps"
sudo pip install lxml netaddr M2Crypto cherrypy mako dnspython requests dicttoxml
sudo pip install PyGithub GitPython pybloomfiltermmap esmre pdfminer futures guess-language 
sudo pip install cluster msgpack-python python-ntlm clamd xdot netifaces pyinstaller
sudo pip install -e git+git://github.com/ramen/phply.git#egg=phply
sudo pip install pbkdf2 pymongo ipcalc couchdb dicttoxml PyPDF2 olefile

echo "Checking and Installing Ruby Gems"
sudo gem install bundler spider http_configuration mini_exiftool zip sqlite3 net-dns bettercap
#
