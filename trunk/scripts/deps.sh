echo "Installing Ubuntu Packages"
sudo apt-get install -y ncftp rar python-setuptools python-configobj python-flickrapi gnome-common gtk-doc-tools libsoup2.4 python-pyexiv2 registry-tools
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
sudo apt-get install -y texlive libcrypt-blowfish-perl libdigest-sha-perl libcrypt-cbc-perl libsort-versions-perl libcrypt-des-perl libdigest-* libreadline-dev
sudo apt-get install -y qt4-qmake qt4-dev-tools libcurl3-dbg libxmlrpc-core-c3-dev libperl-dev libruby omt libgraphviz-dev libpcre3-dev libsvn-dev
sudo apt-get install -y libfbclient2 firebird2.1-dev libncp-dev jxplorer bluefish bluefish-data bluefish-plugins tcpdump python-gnuplot python-qt3 inguma
sudo apt-get install -y python-pytools pdfcrack gzrt ophcrack ophcrack-cli sipcrack virtualbox-ose quicksynergy ngorca smb-nat libnet-nbname-perl libnet-netmask-perl
sudo apt-get install -y flashplugin-installer jftp virtualbox-ose virtualbox-guest-additions wipe reglookup libxmlrpc-c3-dev httrack finger rusers sslsniff
sudo apt-get install -y revelation python-impacket expat php-pear gpsd gpsd-dbg libgps-dev

echo "Installing Pear Database Libraries"
sudo pear install DB
sudo pear install MDB2
sudo pear install MDB2_Driver_mysqli
sudo pear install MDB2_Driver_mysql
sudo pear upgrade-all
#
#insert firewalk deps here
#cd /pentest/temp && wget http://prdownloads.sourceforge.net/libdnet/libdnet-1.11.tar.gz
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
sudo cpanm HTML::Tidy::libXML
sudo cpanm DBD::SQLite
sudo cpanm DBI
sudo cpanm IO::Socket:SSL
sudo cpanm NetPacket::ICMP
sudo cpanm Net::Netmask
sudo cpanm XML::Writer
sudo cpanm HTML::Tidy::libXML
sudo cpanm XML::LibXML
sudo cpanm DBI
sudo cpanm DBD::SQLite

echo "Installing Ruby Gems"
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
if [ ! -f /usr/bin/waveplay ] ; then
cd /pentest/temp && wget ftp://ftp.eenet.ee/pub/FreeBSD/distfiles/waveplay-20010924.tar.gz
tar zxvf waveplay-20010924.tar.gz && cd waveplay-20010924
make && sudo mv waveplay /usr/bin/
rm -rf /pentest/temp/waveplay-20010924
fi
if [ ! -f /usr/bin/crunch ] ; then
cd /pentest/temp && wget http://dl.packetstormsecurity.net/Crack/crunch.cpp
gcc -o crunch crunch.cpp -lstdc++ && sudo mv crunch /usr/bin/
rm -rf crunch.cpp
fi
sudo updatedb
#enable default ssl site for portal
sudo a2enmod ssl
sudo a2ensite ssl
sudo a2enmod rewrite
sudo service apache2 force-reload

#OpenVAS and Greenbone Packages
#wget http://www.openvas.org/download/wmi/wmi-1.3.14.tar.bz2
#wget http://www.openvas.org/download/wmi/openvas-wmi-1.3.14.patch
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/greenbone-security-assistant_2.0.1.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/gsd_1.2.0.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/libopenvas_4.0.6.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/openvas-administrator_1.1.2.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/openvas-cli_1.1.3.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/openvas-manager_2.0.4.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/openvas-scanner_3.2.5.orig.tar.gz
#wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/libmicrohttpd_0.9.17.orig.tar.gz
#sudo openvas-nvt-sync
#test -e /var/lib/openvas/users/om || sudo openvas-mkcert-client -n om -i
#sudo openvassd
#sudo openvasmd --migrate
#sudo openvasmd --rebuild
#sudo killall openvassd
#test -e /var/lib/openvas/users/admin || sudo openvasad -c add_user -n user -w pass -r Admin
#http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/

#Misc crap I`m not sure where it came from, need to review/remove
# misc perl modules
#cd /pentest/temp && wget http://search.cpan.org/CPAN/authors/id/S/SA/SAPER/Net-Pcap-0.16.tar.gz
#tar xvf Net-Pcap-0.16.tar.gz && rm -rf Net-Pcap-0.16.tar.gz
#cd Net-Pcap-0.16/ && perl Makefile.PL
#make && sudo make install
#cd ../ && rm -rf Net-Pcap-0.16/
#this section is still questionable
#cd /pentest/temp && wget ftp://megrez.math.u-bordeaux.fr/pub/pari/unix/OLD/pari-2.1.7.tgz
#tar xvf pari-2.1.7.tgz && rm -rf pari-2.1.7.tgz
#cd pari-2.1.7/ && ./Configure
#make all && sudo make install
#cd /pentest/temp && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080605.tar.gz
#tar xvf Math-Pari-2.01080605.tar.gz && rm -rf Math-Pari-2.01080605.tar.gz
#cd Math-Pari-2.01080605 && perl Makefile.PL
#sudo make install
#sudo cpanm Net::SSH::Perl
