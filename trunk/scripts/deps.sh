echo "Installing Ubuntu Packages"
sudo apt-get install -y wine1.3 wine1.3-dev mysql-server subversion git ncftp rar p7zip-full iw ethtool dos2unix gtk-recordmydesktop postgresql
sudo apt-get install -y sqlite3 nbtscan dsniff uClibc++ libncurses-dev libpcap-dev libnl-dev libssl-dev hping3 openssh-server
sudo apt-get intsall -y python2.6-dev autoconf open-iscsi open-iscsi-utils virtualbox-ose virtualbox-guest-additions wireshark chntpw
sudo apt-get install -y webhttrack httrack finger rusers snmp reglookup gpsd gpsd-dbg libgps-dev apache2 libapache2-mod-auth-mysql
sudo apt-get install -y php5-mysql libapache2-mod-php5 curl sslscan ruby rubygems libpq-dev libxml2-dev vim python-setuptools
sudo apt-get install -y python-nltk python-soappy python-lxml python-svn python-scapy gtk2-engines-pixbuf graphviz python-gtksourceview2
sudo apt-get install -y libssh-dev libmysqlclient-dev libpcre3-dev Firebird2.1-dev libsvn-dev libncp-dev libidn11-dev libcurl4-gnutls-dev
sudo apt-get install -y libopenssl-ruby libxslt1-dev ruby-dev sipcrack libgmp3-dev python-mysqldb libnet1-dev flasm registry-tools
sudo apt-get install -y libavahi-compat-libdnssd-dev gip ldap-utils bkhive ophcrack macchanger-gtk cdpr flamerobin dsniff sipsak
sudo apt-get install -y ddrescue ike-scan nfs-common httping ptunnel recover recoverdm extundelete ext3grep

#if [ ! -d /opt/xplico ] ; then
#echo "Installing Xplico"
#sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" >> /etc/apt/sources.list'
#sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
#sudo apt-get update
#sudo apt-get install xplico
#sudo service apache2 restart
#echo "Xplico by default is now running on 9876 - http://localhost:9876"
#fi

#Oracle dependencies for metasploit, hydra, etc
#if [ ! -d /opt/oracle ] ; then
#cd /opt && mkdir oracle
#cd /pentest/temp
#wget basic-10.2.0.5.0-linux.zip && mv basic-10.2.0.5.0-linux.zip /opt/oracle
#wget sdk-10.2.0.5.0-linux.zip && mv sdk-10.2.0.5.0-linux.zip /opt/oracle
#wget sqlplus-10.2.0.5.0-linux.zip && mv sqlplus-10.2.0.5.0-linux.zip /opt/oracle
#cd /opt/oracle && unzip basic-10.2.0.5.0-linux.zip
#unzip sdk-10.2.0.5.0-linux.zip && sqlplus-10.2.0.5.0-linux.zip
#cd /pentest/temp && wget kubo-ruby-oci8-ruby-oci8-2.1.2-0-g012e146.zip
#unzip kubo-ruby-oci8-ruby-oci8-2.1.2-0-g012e146.zip && /pentest/temp/kubo-ruby-oci8-012e146
#insert remainder of the ruby/oracle crap here needed for metasploit
#metasploit oracle modules should work now
#./configure --with-oracle=/opt/oracle/instantclient_10_2/sdk/include/ --with-oracle-lib=/opt/oracle/instantclient_10_2/
#hydra segments on compile..no idea, will play with it more at some point..
#fi

if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus && perl Makefile.PL
make && sudo make install
cd /pentest/temp && rm -rf cpanminus/
fi
echo "Installing PERL Libraries"
if [ ! -d /usr/local/lib/perl/5.12.4/Math/ ] ; then
cd /pentest/temp && wget http://pari.math.u-bordeaux.fr/pub/pari/unix/OLD/pari-2.1.7.tgz
tar xvf pari-2.1.7.tgz && rm -rf pari-2.1.7.tgz
cd pari-2.1.7/ && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080605.tar.gz
tar xvf Math-Pari-2.01080605.tar.gz && rm -rf Math-Pari-2.01080605.tar.gz
cd Math-Pari-2.01080605 && perl Makefile.PL
sudo make install
fi

echo "Checking and Installing PERL Deps"
sudo cpanm Cisco::CopyConfig
sudo cpanm Net::Telnet
sudo cpanm Net::SSH::Perl
sudo cpanm Net::IP
sudo cpanm Net::Netmask
sudo cpanm XML::Writer
sudo cpanm Encoding::BER

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
#need to add dep checking for this, wastes time on rechecks
#gem list | grep -w 
#if [ ! $? -eq 0 ] ; then
#
#fi
cd && echo "export PATH=/var/lib/gems/1.8/bin/:$PATH" >> .bashrc
source ~/.bashrc
#
if [ ! -f /usr/local/lib/python2.6/dist-packages/pybloomfilter.so ] ; then
cd /pentest/temp && wget http://c.pypi.python.org/packages/source/p/pybloomfiltermmap/pybloomfiltermmap-0.2.0.tar.gz
tar zxvf pybloomfiltermmap-0.2.0.tar.gz && rm -rf pybloomfiltermmap-0.2.0.tar.gz
cd pybloomfiltermmap-0.2.0/ && sudo python2.6 setup.py install
cd /pentest/temp/ && sudo rm -rf pybloomfiltermmap-0.2.0/
fi
#if [ ! -f /usr/bin/waveplay ] ; then
#echo "Installing waveplay"
#cd /pentest/temp && wget ftp://ftp.eenet.ee/pub/FreeBSD/distfiles/waveplay-20010924.tar.gz
#tar zxvf waveplay-20010924.tar.gz && cd waveplay-20010924
#make && sudo mv waveplay /usr/bin/
#sudo rm -rf /pentest/temp/waveplay*
#fi
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
#Misc crap, need to review/remove
#cd /pentest/temp && wget http://search.cpan.org/CPAN/authors/id/S/SA/SAPER/Net-Pcap-0.16.tar.gz
#tar xvf Net-Pcap-0.16.tar.gz && rm -rf Net-Pcap-0.16.tar.gz
#cd Net-Pcap-0.16/ && perl Makefile.PL
#make && sudo make install
#cd ../ && rm -rf Net-Pcap-0.16/
#crap from the original netglub install..leaving it here in case I need it for reference
#wget http://pypi.python.org/packages/source/s/simplejson/simplejson-2.1.5.tar.gz && tar -xzvf simplejson-2.1.5.tar.gz
#rm -rf simplejson-2.1.5.tar.gz && cd simplejson-2.1.5
#sudo python setup.py build && sudo python setup.py install 
#cd /pentest/temp
#wget http://sourceforge.net/projects/pyxml/files/pyxml/0.8.4/PyXML-0.8.4.tar.gz
#tar -xvzf PyXML-0.8.4.tar.gz && rm -rf PyXML-0.8.4.tar.gz
#cd PyXML-0.8.4 && wget http://launchpadlibrarian.net/31786748/0001-Patch-for-Python-2.6.patch
#patch -p1 < 0001-Patch-for-Python-2.6.patch && sudo python setup.py install 
#cd /pentest/temp
#wget http://www.graphviz.org/pub/graphviz/stable/SOURCES/graphviz-2.26.3.tar.gz
#tar -xzvf graphviz-2.26.3.tar.gz
#cd graphviz-2.26.3 && ./configure
#make && sudo make install
#cd /pentest/temp
#wget http://sourceforge.net/projects/xmlrpc-c/files/Xmlrpc-c%20Super%20Stable/1.16.34/xmlrpc-c-1.16.34.tgz
#tar -zxvf xmlrpc-c-1.16.34.tgz && rm -rf xmlrpc-c-1.16.34.tgz
#cd xmlrpc-c-1.16.34
#./configure
#make && sudo make install
