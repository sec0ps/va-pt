#Raspberry PI Deps Installer
sudo apt-get install -y gcc sudo subversion ntpdate autoconf make libssl-dev libpcap-dev libpcre3-dev freeipmi-tools
sudo apt-get install -y git g++ vim libyaml-dev postgresql libpq-dev python-setuptools python-pip python2.7-dev libsqlite3-dev
sudo apt-get install -y libxslt1-dev libxml2-dev python-pip iw libncurses-dev libnl-dev pkg-config mtd-utils libgmp-dev
sudo apt-get install -y python-mysqldb python-beautifulsoup python-pycurl libidn11-dev unzip libavahi-compat-libdnssd-dev
sudo apt-get install -y dsniff ldap-utils hping3 libevent-dev libidn11-dev libavahi-compat-libdnssd-dev libssh-dev
sudo apt-get install -y libmysqlclient-dev libreadline-dev libusb-dev

if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus && perl Makefile.PL
make && sudo make install
cd /pentest/temp && rm -rf cpanminus/
fi
