#Raspberry PI Deps Installer
sudo apt-get install -y gcc sudo subversion ntpdate autoconf make libssl-dev libpcap-dev libpcre3-dev freeipmi-tools
sudo apt-get install -y git g++ vim libyaml-dev postgresql libpq-dev python-setuptools python-pip python2.7-dev libsqlite3-dev
sudo apt-get install -y libxslt1-dev libxml2-dev python-pip iw libncurses-dev libnl-dev pkg-config mtd-utils libgmp-dev
sudo apt-get install -y python-mysqldb python-beautifulsoup python-pycurl libidn11-dev unzip libavahi-compat-libdnssd-dev
sudo apt-get install -y dsniff ldap-utils hping3 libevent-dev libidn11-dev libavahi-compat-libdnssd-dev libssh-dev
sudo apt-get install -y libmysqlclient-dev libreadline-dev libusb-dev python-scapy tcpdump tcpreplay ettercap-text-only
sudo apt-get install -y macchanger udptunnel xprobe wireshark nbtscan sipcrack proxychains httptunnel sipsack sslsniff
sudo apt-get install -y ike-scan ssldump vpnc openvpn ethtool ruby-dev httrack rusers snmp reglookup gpsd libapache2-mod-php5
sudo apt-get install -y apache2 ptunnel iodine netmask dnstracer dnswalk locate proxytunnel
sudo ntpdate time.nist.gov

if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus && perl Makefile.PL
make && sudo make install
cd /pentest/temp && rm -rf cpanminus/
fi

if [ ! -f /usr/local/lib/perl/5.14.2/Math/Pari.pm ] ; then
echo "Installing PERL Libraries"
cd /pentest/temp && wget http://pari.math.u-bordeaux.fr/pub/pari/unix/OLD/pari-2.1.7.tgz
tar xvf pari-2.1.7.tgz && rm -rf pari-2.1.7.tgz
cd pari-2.1.7/ && wget http://search.cpan.org/CPAN/authors/id/I/IL/ILYAZ/modules/Math-Pari-2.01080605.tar.gz
tar xvf Math-Pari-2.01080605.tar.gz && rm -rf Math-Pari-2.01080605.tar.gz
cd Math-Pari-2.01080605 && perl Makefile.PL
sudo make install
else
echo "Pari is installed, moving on"
fi

sudo cpanm Net::SSLeay
sudo cpanm HTTP::Request::Common
sudo cpanm LWP::UserAgent
sudo cpanm WWW::Mechanize
sudo cpanm Net::Telnet
sudo cpanm Net::SSH::Perl

ruby -v | grep "1.9.3"
if [ $? -eq 1 ] ; then
echo "Installing Ruby 1.9.3"
cd /pentest/temp && wget ftp://ftp.ruby-lang.org/pub/ruby/1.9/ruby-1.9.3-p392.tar.gz
tar xvf ruby-1.9.3-p392.tar.gz && rm -rf ruby-1.9.3-p392.tar.gz
cd ruby-1.9.3-p392 && ./configure && make
sudo make install
fi
