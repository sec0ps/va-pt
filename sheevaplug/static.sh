ruby -v | grep "1.9.3"
if [ $? -eq 1 ] ; then
echo "Installing Ruby 1.9.3"
cd /pentest/temp && wget ftp://ftp.ruby-lang.org/pub/ruby/1.9/ruby-1.9.3-p448.tar.gz
tar xvf ruby-1.9.3-p448.tar.gz && rm -rf ruby-1.9.3-p448.tar.gz
cd ruby-1.9.3-p448 && ./configure && make
sudo make install
fi

