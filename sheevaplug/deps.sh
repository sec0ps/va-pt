sudo apt-get install -y gcc sudo subversion ntpdate autoconf make libssl-dev libpcap-dev libpcre3-dev
sudo apt-get install -y git g++ vim libyaml-dev postgresql libpq-dev python-setuptools python-pip python2.7-dev libsqlite3-dev
sudo apt-get install -y libxslt1-dev libxml2-dev python-pip iw libncurses-dev libnl-dev pkg-config mtd-utils

if [ ! -f /usr/local/bin/cpanm ] ; then
echo "Installing CPANimus"
cd /pentest/temp && git clone git://github.com/miyagawa/cpanminus.git
cd cpanminus && perl Makefile.PL
make && sudo make install
cd /pentest/temp && rm -rf cpanminus/
fi

sudo cpanm Net::SSLeay
sudo cpanm HTTP::Request::Common
sudo cpanm LWP::UserAgent
sudo cpanm WWW::Mechanize

ruby -v | grep "1.9.3"
if [ $? -eq 1 ] ; then
echo "Installing Ruby 1.9.3"
cd /pentest/temp && wget ftp://ftp.ruby-lang.org/pub/ruby/1.9/ruby-1.9.3-p392.tar.gz
tar xvf ruby-1.9.3-p392.tar.gz && rm -rf ruby-1.9.3-p392.tar.gz
cd ruby-1.9.3-p392 && ./configure && make
sudo make install
fi


