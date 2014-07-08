echo "Installing Ubuntu Packages"
sudo apt-get install -y wine wine-dev mysql-server subversion git ncftp rar p7zip-full iw ethtool dos2unix gtk-recordmydesktop postgresql
sudo apt-get install -y sqlite3 nbtscan dsniff uClibc++ libncurses-dev libpcap-dev libnl-dev libssl-dev hping3 openssh-server
sudo apt-get intsall -y python-dev python2.7-dev autoconf open-iscsi open-iscsi-utils wireshark dhcp3-server locate libusb-dev
sudo apt-get install -y webhttrack httrack finger rusers snmp reglookup gpsd gpsd-dbg libgps-dev apache2 libapache2-mod-auth-mysql
sudo apt-get install -y php5-mysql libapache2-mod-php5 curl sslscan ruby rubygems libpq-dev libxml2-dev vim python-setuptools
sudo apt-get install -y python-nltk python-soappy python-lxml python-svn python-scapy gtk2-engines-pixbuf graphviz python-gtksourceview2
sudo apt-get install -y libssh-dev libmysqlclient-dev libpcre3-dev Firebird2.1-dev libsvn-dev libncp-dev libidn11-dev libcurl4-gnutls-dev
sudo apt-get install -y libopenssl-ruby libxslt1-dev ruby-dev sipcrack libgmp3-dev python-mysqldb libnet1-dev flasm registry-tools
sudo apt-get install -y libavahi-compat-libdnssd-dev gip ldap-utils bkhive ophcrack macchanger-gtk cdpr flamerobin dsniff sipsak
sudo apt-get install -y ddrescue ike-scan nfs-kernel-server httping ptunnel recover recoverdm extundelete ext3grep libaspell-dev autoconf
sudo apt-get install -y libyaml-dev openjdk-7-jre openjdk-7-jre-lib libreadline-dev python-pip python-beautifulsoup tshark
sudo apt-get install -y samba libpam-smbpass libevent-dev flex bison libnl-3-dev libnl-genl-3-dev libgeoip-dev chntpw
sudo apt-get install -y libnetfilter-conntrack-dev libncurses6-dev liburcu-dev libnacl-dev zlib1g-dev libcli-dev python-pycurl vpnc
sudo apt-get install -y ptunnel iodine udptunnel httptunnel netmask dnstracer dnswalk swig cmake libtalloc-dev libtevent-dev libpopt-dev
sudo apt-get install -y libbsd-dev hostapd

ruby -v | grep "1.9.3"
if [ $? -eq 1 ] ; then
echo "Installing Ruby 1.9.3"
cd /pentest/temp && wget ftp://ftp.ruby-lang.org/pub/ruby/1.9/ruby-1.9.3-p392.tar.gz
tar xvf ruby-1.9.3-p392.tar.gz && rm -rf ruby-1.9.3-p392.tar.gz
cd ruby-1.9.3-p392 && ./configure && make
sudo make install
fi
if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus && perl Makefile.PL
make && sudo make install
cd /pentest/temp && rm -rf cpanminus/
fi
if [ ! -f /usr/local/lib/perl/5.14.2/Math/Pari.pm ] ; then
echo "Installing PERL Libraries"
cd /pentest/temp && wget http://pkgs.fedoraproject.org/repo/pkgs/perl-Math-Pari/pari-2.1.7.tgz/357b7a42e89e2761a5367bbcbfcca5f2/pari-2.1.7.tgz
tar xvf pari-2.1.7.tgz && rm -rf pari-2.1.7.tgz
cd pari-2.1.7/ && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080605.tar.gz
tar xvf Math-Pari-2.01080605.tar.gz && rm -rf Math-Pari-2.01080605.tar.gz
cd Math-Pari-2.01080605 && perl Makefile.PL
sudo make install
else
echo "Pari is installed, moving on"
fi

echo "Checking and Installing PERL Deps"
sudo cpanm Cisco::CopyConfig && sudo cpanm Net::Telnet
sudo cpanm Net::SSH::Perl && sudo cpanm Net::IP
sudo cpanm Net::Netmask && sudo cpanm XML::Writer
sudo cpanm Encoding::BER && sudo cpanm Term::ANSIColor
sudo cpanm Getopt::Long && sudo cpanm XML::Writer
sudo cpanm Socket && sudo cpanm Net::Whois::IP
sudo cpanm Number::Bytes::Human && sudo cpanm Parallel::ForkManager
sudo cpanm NetPacket::ICMP && sudo cpanm String::Random

echo "Installing Python Deps"
sudo pip install lxml && sudo pip install netaddr
sudo pip install M2Crypto && sudo pip install cherrypy
sudo pip install mako && sudo pip install M2Crypto
sudo pip install cherrypy && sudo pip install dnspython
sudo pip install requests

echo "Checking and Installing Ruby Gems"
gem list | grep -w bundler
if [ ! $? -eq 0 ] ; then
sudo gem install bundler
fi
gem list | grep -w spider
if [ ! $? -eq 0 ] ; then
sudo gem install spider
fi
gem list | grep -w http_configuration
if [ ! $? -eq 0 ] ; then
sudo gem install http_configuration
fi
gem list | grep -w mini_exiftool
if [ ! $? -eq 0 ] ; then
sudo gem install mini_exiftool
fi
gem list | grep -w zip
if [ ! $? -eq 0 ] ; then
sudo gem install zip
fi
gem list | grep -w pg
if [ ! $? -eq 0 ] ; then
sudo gem install pg
fi
gem list | grep -w sqlite3
if [ ! $? -eq 0 ] ; then
sudo gem install sqlite3
fi
gem list | grep -w net-dns
if [ ! $? -eq 0 ] ; then
sudo gem install net-dns
fi
#need to add dep checking for this, wastes time on rechecks
#gem list | grep -w 
#if [ ! $? -eq 0 ] ; then
#
#fi
#
if [ ! -f /pentest/passwords/crunch ] ; then
echo "Installing crunch"
cd /pentest/passwords && wget http://dl.packetstormsecurity.net/Crack/crunch.cpp
gcc -o crunch crunch.cpp -lstdc++ && rm -rf crunch.cpp
fi

echo "enabling default ssl site for portal if needed"
service='https'
if sudo lsof -i :443 | grep $service > /dev/null
then
echo "$service is there, skipping this step"
else
echo "$service is not there, enabling default SSL configuration"
sudo a2enmod ssl
sudo a2ensite ssl
sudo a2enmod rewrite
sudo service apache2 force-reload
fi
echo "Updating locate database"
sudo updatedb
#if [ ! -d /opt/xplico ] ; then
#echo "Installing Xplico"
#sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" >> /etc/apt/sources.list'
#sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
#sudo apt-get update
#sudo apt-get install xplico
#sudo service apache2 restart
#echo "Xplico by default is now running on 9876 - http://localhost:9876"
#fi
#if [ ! -f /usr/bin/waveplay ] ; then
#echo "Installing waveplay"
#cd /pentest/temp && wget ftp://ftp.eenet.ee/pub/FreeBSD/distfiles/waveplay-20010924.tar.gz
#tar zxvf waveplay-20010924.tar.gz && cd waveplay-20010924
#make && sudo mv waveplay /usr/bin/
#sudo rm -rf /pentest/temp/waveplay*
#fi
