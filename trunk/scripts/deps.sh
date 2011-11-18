sudo apt-get install -y ncftp rar python-setuptools python-configobj python-flickrapi gnome-common gtk-doc-tools libsoup2.4 python-pyexiv2 registry-tools
sudo apt-get install -y libxml-libxml-perl libdbi-perl libdbd-sqlite3-perl alien librpmbuild1 lsb-core ncurses-term pax rpm rpm2cpio nfs-common python-psyco
sudo apt-get install -y libgd2-xpm-dev flasm unetbootin unetbootin-translations open-iscsi open-iscsi-utils ldap-utils upx python-pymssql
sudo apt-get install -y gtk-recordmydesktop postgresql libpq-dev p7zip-full iw make ethtool dos2unix gcc subversion gip mysql-server
sudo apt-get install -y libmysqlclient-dev gem arp-scan libmysql-ruby php5-mysql libapache2-mod-auth-mysql sqlite3 hping3 openssh-server
sudo apt-get install -y uClibc++ libncurses-dev libidn11-dev libssl-dev libssh-dev cmake python-scapy python-sqlalchemy python2.6-dev
sudo apt-get install -y libpcap0.8 libnl-dev ruby cdpr p0f xprobe rdoc bluez-hcidump ruby1.8-dev wine liberror-perl git-core apache2 mono-2.0-devel
sudo apt-get install -y openjdk-6-jre openjdk-6-jre-lib python-lxml graphviz autoconf sqlmap openvas-server openvas-client libsqlite3-0 libsqlite3-dev sslscan
sudo apt-get install -y libcamlimages-ocaml libcamlimages-ocaml-dev libcamlimages-ocaml-dev libocamlgsl-ocaml libocamlgsl-ocaml-dev
sudo apt-get install -y ocaml-findlib ocaml-native-compilers m4 maven2 libxslt1.1 libxslt1-dev xsltproc ettercap-gtk libgmp3-dev
sudo apt-get install -y build-essential libpcap-dev libnet1-dev libdumbnet-dev sipsak cvs netcat6 libwxgtk2.8-0 python-qt4 curl
sudo apt-get install -y python-qt3 libmysql++-dev libxml-smart-perl libextractor-plugins libextractor-dbg extract python-nltk python-soappy
sudo apt-get install -y python-svn python-dev sqlite3 nbtscan dsniff libapache2-mod-php5 python-mysqldb pyqt-tools sox rezound macchanger-gtk
sudo apt-get install -y webhttrack smbclient xsmbrowser httping libnl2 libcap2-bin ndisgtk python-wxtools libdigest-hmac-perl rake
sudo apt-get install -y irpas python-bluetooth libstdc++5 smb4k kate libssh2-1-dev libimage-exiftool-perl
sudo apt-get install -y texlive libcrypt-blowfish-perl libdigest-sha-perl libcrypt-cbc-perl libsort-versions-perl libcrypt-des-perl libdigest-* libreadline-dev

dpkg-query -l | grep php-pear
if [ $? -eq 1 ] ; then
sudo apt-get --force-yes -y install php-pear
sudo pear install DB
sudo pear install MDB2
sudo pear install MDB2_Driver_mysqli
sudo pear install MDB2_Driver_mysql
sudo pear upgrade-all
fi
#rubygems1.9.1
#to add
#dpkg-query -l | grep 
#if [ $? -eq 1 ] ; then
#sudo apt-get --force-yes -y install 
#fi
if [ ! -f /usr/local/bin/cpanm ] ; then
cd /pentest/temp
git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus
sudo ./cpanm Exception::Class
sudo ./cpanm --installdeps .
perl Makefile.PL
make
sudo make install
fi
if [ ! -f /usr/local/bin/checklink ] ; then
sudo cpanm W3C::LinkChecker
fi
#
#insert firewalk deps here
#cd /pentest/temp && wget http://prdownloads.sourceforge.net/libdnet/libdnet-1.11.tar.gz
#
sudo gem install postgres
sudo gem install bson_ext
sudo gem install rake
sudo gem install rails
sudo gem install RedCloth
sudo gem install bundler
sudo gem install sqlite3-ruby
sudo gem install wxruby
sudo gem install rake-compiler
sudo gem install jeweler
sudo gem install pNet-DNS
sudo gem install fxruby
sudo gem install ip
sudo gem install httpclient
sudo gem install thor
sudo ln -s /var/lib/gems/1.8/bin/thor /usr/bin/thor
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
# misc perl modules
cd /pentest/temp && wget http://search.cpan.org/CPAN/authors/id/S/SA/SAPER/Net-Pcap-0.16.tar.gz
tar xvf Net-Pcap-0.16.tar.gz && rm -rf Net-Pcap-0.16.tar.gz
cd Net-Pcap-0.16/ && perl Makefile.PL
make && sudo make install
cd ../ && rm -rf Net-Pcap-0.16/
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
#this section is still questionable
cd /pentest/temp && wget ftp://megrez.math.u-bordeaux.fr/pub/pari/unix/OLD/pari-2.1.7.tgz
tar xvf pari-2.1.7.tgz && rm -rf pari-2.1.7.tgz
cd pari-2.1.7/ && ./Configure
make all && sudo make install
cd /pentest/temp && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080605.tar.gz
tar xvf Math-Pari-2.01080605.tar.gz && rm -rf Math-Pari-2.01080605.tar.gz
cd Math-Pari-2.01080605 && perl Makefile.PL
sudo make install
sudo cpanm Net::SSH::Perl
