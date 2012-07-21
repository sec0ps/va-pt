echo "Installing Ubuntu Packages"
sudo apt-get install -y ncftp rar python-setuptools python-configobj python-flickrapi gnome-common gtk-doc-tools libsoup2.4 python-pyexiv2 
sudo apt-get install -y libxml-libxml-perl libdbi-perl libdbd-sqlite3-perl alien librpmbuild1 lsb-core ncurses-term pax rpm rpm2cpio nfs-common
sudo apt-get install -y libgd2-xpm-dev flasm unetbootin unetbootin-translations open-iscsi open-iscsi-utils ldap-utils upx python-pymssql
sudo apt-get install -y gtk-recordmydesktop postgresql libpq-dev p7zip-full iw make ethtool dos2unix gcc subversion gip mysql-server
sudo apt-get install -y libmysqlclient-dev gem arp-scan libmysql-ruby php5-mysql libapache2-mod-auth-mysql sqlite3 hping3 openssh-server
sudo apt-get install -y uClibc++ libncurses-dev libidn11-dev libssl-dev libssh-dev cmake python-scapy python-sqlalchemy python2.6-dev
sudo apt-get install -y libpcap0.8 libnl-dev ruby cdpr p0f xprobe rdoc bluez-hcidump ruby1.8-dev wine liberror-perl git-core apache2 mono-2.0-devel
sudo apt-get install -y openjdk-6-jre openjdk-6-jre-lib python-lxml graphviz autoconf sqlmap libsqlite3-0 libsqlite3-dev sslscan sqlfairy
sudo apt-get install -y libcamlimages-ocaml libcamlimages-ocaml-dev libcamlimages-ocaml-dev libocamlgsl-ocaml libocamlgsl-ocaml-dev
sudo apt-get install -y ocaml-findlib ocaml-native-compilers m4 maven2 libxslt1.1 libxslt1-dev xsltproc ettercap-gtk libgmp3-dev xmltoman
sudo apt-get install -y build-essential libpcap-dev libnet1-dev libdumbnet-dev sipsak cvs netcat6 libwxgtk2.8-0 python-qt4 curl bison
sudo apt-get install -y python-qt3 libmysql++-dev libxml-smart-perl libextractor-plugins libextractor-dbg extract python-nltk python-soappy
sudo apt-get install -y python-svn python-dev sqlite3 nbtscan dsniff libapache2-mod-php5 python-mysqldb pyqt-tools sox rezound macchanger-gtk
sudo apt-get install -y webhttrack smbclient httping libnl2 libcap2-bin ndisgtk python-wxtools libdigest-hmac-perl rake doxygen libgnutls-dev
sudo apt-get install -y irpas python-bluetooth libstdc++5 smb4k kate libssh2-1-dev libimage-exiftool-perl vim rubygems libgpgme11-dev uuid-dev
sudo apt-get install -y texlive libcrypt-blowfish-perl libdigest-sha-perl libcrypt-cbc-perl libsort-versions-perl libcrypt-des-perl libdigest-* 
sudo apt-get install -y qt4-qmake qt4-dev-tools libcurl3-dbg libxmlrpc-core-c3-dev libperl-dev libruby omt libgraphviz-dev libpcre3-dev libsvn-dev
sudo apt-get install -y libfbclient2 firebird2.1-dev libncp-dev jxplorer bluefish bluefish-data bluefish-plugins tcpdump python-gnuplot python-qt3
sudo apt-get install -y python-pytools pdfcrack gzrt ophcrack ophcrack-cli sipcrack virtualbox-ose quicksynergy ngorca smb-nat libnet-nbname-perl 
sudo apt-get install -y flashplugin-installer jftp virtualbox-ose virtualbox-guest-additions wipe reglookup libxmlrpc-c3-dev httrack finger rusers
sudo apt-get install -y revelation python-impacket expat php-pear gpsd gpsd-dbg libgps-dev snmp python-svn python-pypdf python-beautifulsoup
sudo apt-get install -y bkhive xprobe2 safecopy ptunnel ngrep btscanner cabextract chntpw cmospwd cdpr dcfldd dc3dd ddrescue disktype fcrackzip
sudo apt-get install -y galleta pasco vinetto autopsy wine1.3-dev rifiuti2 recover extundelete recoverdm ext3grep python-gtksourceview2 zlib1g-dev 
sudo apt-get install -y libasound2-dev libbz2-dev vlc libvlc-dev gtk2-engines-pixbuf perl-doc ike-scan xchat outguess steghide python-septic snowdrop
sudo apt-get install -y flex libidn11-dev zlib-bin zlibc ruby-openssl texlive-latex-extra liblzo2-dev python-pysqlite2 sslsniff libnet-netmask-perl
sudo apt-get install -y inguma libreadline-dev registry-tools flamerobin

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

echo "Installing Pear Database Libraries"
sudo pear install DB
sudo pear install MDB2
sudo pear install MDB2_Driver_mysqli
sudo pear install MDB2_Driver_mysql
sudo pear upgrade-all
#
if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus
#sudo ./cpanm --installdeps .
perl Makefile.PL && make
sudo make install
fi

echo "Installing PERL Libraries"
if [ ! -d /usr/local/lib/perl/5.12.4/Math/ ] ; then
cd /pentest/temp && wget ftp://megrez.math.u-bordeaux.fr/pub/pari/unix/OLD/pari-2.1.7.tgz --proxy=off
tar xvf pari-2.1.7.tgz && rm -rf pari-2.1.7.tgz
cd pari-2.1.7/ && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080605.tar.gz --proxy=off
tar xvf Math-Pari-2.01080605.tar.gz && rm -rf Math-Pari-2.01080605.tar.gz
cd Math-Pari-2.01080605 && perl Makefile.PL
sudo make install
fi
if [ ! -f /usr/local/lib/python2.6/dist-packages/pybloomfilter.so ] ; then
cd /pentest/temp && wget http://c.pypi.python.org/packages/source/p/pybloomfiltermmap/pybloomfiltermmap-0.2.0.tar.gz
tar zxvf pybloomfiltermmap-0.2.0.tar.gz && rm -rf pybloomfiltermmap-0.2.0.tar.gz
cd pybloomfiltermmap-0.2.0/ && sudo python setup.py install
cd /pentest/temp/ && sudo rm -rf pybloomfiltermmap-0.2.0/
fi
sudo cpanm Cisco::CopyConfig
sudo cpanm Net::Whois::IP
sudo cpanm W3C::LinkChecker
sudo cpanm Number::Bytes::Human
sudo cpanm Time::HiRes
sudo cpanm Math::BigInt
sudo cpanm Net::Telnet
sudo cpanm Crypt::Rijndael
sudo cpanm Net::SSLeay
sudo cpanm Net::SNMP
sudo cpanm Socket6
sudo cpanm Net::SSH
sudo cpanm Net::SSH::Perl
sudo cpanm HTML::Tidy::libXML
sudo cpanm DBD::SQLite
sudo cpanm DBI
sudo cpanm IO::Socket::SSL
sudo cpanm NetPacket::ICMP
sudo cpanm Net::Netmask
sudo cpanm XML::Writer
sudo cpanm HTML::Tidy::libXML
sudo cpanm XML::LibXML
sudo cpanm DBI
sudo cpanm DBD::SQLite
sudo cpanm Net::Telnet::Cisco
sudo cpanm Net::Pcap
sudo cpanm XML::Twig
sudo cpanm Encoding::BER

echo "Installing Ruby Gems"
#need to add dep checking for this, wastes time on rechecks
sudo gem install em-resolv-replace
sudo gem install mongo
sudo gem install rchardet
sudo gem install SystemTimer
sudo gem install -v=0.4.2 i18n
sudo gem install -v=2.3.11 rails
sudo gem install rake -v=0.8.7
sudo gem install postgres
sudo gem install bson_ext
sudo gem install rake
sudo gem install rails
sudo gem install RedCloth
sudo gem install bundle
sudo gem install sqlite3
sudo gem install wxruby
sudo gem install rake-compiler
sudo gem install jeweler
sudo gem install pNet-DNS
sudo gem install fxruby
sudo gem install ip
sudo gem install httpclient
sudo gem install thor
sudo gem install factory_girl
sudo gem install dm-core
sudo gem install dm-migrations
sudo gem install json
sudo gem install ansi
sudo gem install term-ansicolor
sudo gem install dm-sqlite-adapter
sudo gem install mysql
sudo gem install spider
sudo gem install rubyzip
sudo gem install http_configuration
sudo gem install mime-types
sudo gem install mini_exiftool
sudo gem install hpricot
cd && echo "export PATH=/var/lib/gems/1.8/bin/:$PATH" >> .bashrc
source ~/.bashrc
#
if [ ! -f /usr/local/lib/python2.6/dist-packages/pybloomfiltermmap-0.2.0.egg-info ] ; then
cd /pentest/temp && wget http://pypi.python.org/packages/source/p/pybloomfiltermmap/pybloomfiltermmap-0.2.0.tar.gz
tar xvf pybloomfiltermmap-0.2.0.tar.gz && rm -rf pybloomfiltermmap-0.2.0.tar.gz
sudo python2.6 setup.py install
fi
if [ ! -f /usr/bin/waveplay ] ; then
echo "Installing waveplay"
cd /pentest/temp && wget ftp://ftp.eenet.ee/pub/FreeBSD/distfiles/waveplay-20010924.tar.gz --proxy=off
tar zxvf waveplay-20010924.tar.gz && cd waveplay-20010924
make && sudo mv waveplay /usr/bin/
rm -rf /pentest/temp/waveplay-20010924
fi
if [ ! -f /usr/bin/crunch ] ; then
echo "Installing crunch"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/Crack/crunch.cpp --proxy=off
gcc -o crunch crunch.cpp -lstdc++ && sudo mv crunch /usr/bin/
rm -rf crunch.cpp
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

#Misc crap I`m not sure where it came from, need to review/remove
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
