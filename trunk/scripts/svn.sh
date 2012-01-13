if [ ! -d /pentest/wireless/giskismet ] ; then
echo "Installing gisKismet"
cd /pentest/wireless && svn co https://my-svn.assembla.com/svn/giskismet/trunk giskismet
cd /pentest/wireless/gismisket && perl Makefile.PL
make
fi
if [ ! -d /pentest/wireless/wifite/ ] ; then
echo "Installing Wifitie"
cd /pentest/wireless && svn checkout http://wifite.googlecode.com/svn/trunk/ wifite
fi
if [ ! -d /pentest/exploits/set ] ; then
echo "Installing SET"
cd /pentest/exploits && svn co http://svn.secmaniac.com/social_engineering_toolkit set
fi
if [ ! -d /pentest/exploits/framework3 ] ; then
echo "Installing Metasploit"
cd /pentest/exploits && svn co http://metasploit.com/svn/framework3/trunk/ framework3
fi
if [ ! -d /pentest/web/wapiti ] ; then
echo "Installing Wapiti"
cd /pentest/web && svn co https://wapiti.svn.sourceforge.net/svnroot/wapiti wapiti
fi
if [ ! -d /pentest/web/wfuzz ] ; then
echo "Installing wfuzz"
cd /pentest/web && svn checkout http://wfuzz.googlecode.com/svn/trunk/ wfuzz
cd /pentest/web/wfuzz && chmod 700 wfuzz.py
fi
if [ ! -d /pentest/web/fimap ] ; then
echo "Installing fimap"
cd /pentest/web && svn checkout http://fimap.googlecode.com/svn/trunk/ fimap
fi
if [ ! -d /pentest/web/zap ] ; then
echo "Installing ZED Attack Proxy"
cd /pentest/temp && wget http://zaproxy.googlecode.com/files/ZAP_1.3.4_Linux.tar.gz
tar zxvf ZAP_1.3.4_Linux.tar.gz && rm -rf ZAP_1.3.4_Linux.tar.gz
mv ZAP_1.3.4/ /pentest/web/zap
cd /pentest/web/zap && chmod 700 zap.sh
cd /pentest/web && svn checkout --force http://zaproxy.googlecode.com/svn/trunk/ zap 
fi
if [ ! -d /pentest/web/w3af ] ; then
echo "Installing w3af"
cd /pentest/temp && wget http://c.pypi.python.org/packages/source/p/pybloomfiltermmap/pybloomfiltermmap-0.2.0.tar.gz
tar zxvf pybloomfiltermmap-0.2.0.tar.gz && rm -rf pybloomfiltermmap-0.2.0.tar.gz
cd pybloomfiltermmap-0.2.0/ && sudo python setup.py install
cd /pentest/web && svn co https://w3af.svn.sourceforge.net/svnroot/w3af/trunk w3af/
fi
if [ ! -d /pentest/web/waffit/.svn ] ; then
echo "Installing waffit"
cd /pentest/web && svn checkout http://waffit.googlecode.com/svn/trunk/ waffit
cd /pentest/web/waffit && chmod 700 wafw00f.py
fi
if [ ! -d /pentest/fuzzers/sulley ] ; then
echo "Installing Sulley"
cd /pentest/fuzzers && svn checkout http://sulley.googlecode.com/svn/trunk/ sulley
fi
if [ ! -d /pentest/web/nikto ] ; then
echo "Installing Nikto"
cd /pentest/web && svn co http://svn2.assembla.com/svn/Nikto_2/trunk nikto
fi
if [ ! -d /pentest/enumeration/theHarvester ] ; then
echo "Installing the Harvester"
cd /pentest/enumeration && git clone https://github.com/laramies/theHarvester.git
cd /pentest/enumeration/theHarvester && chmod 700 theHarvester.py
fi
if [ ! -d /pentest/web/sslyze ] ; then
cd /pentest/web && svn checkout http://sslyze.googlecode.com/svn/trunk/ sslyze
fi
if [ ! -d /var/www/beef/.svn/ ] ; then
echo "Installing Beef"
cd /var/www && sudo svn co http://beef.googlecode.com/svn/trunk/ beef/
fi
if [ ! -d /pentest/enumeration/fierce2 ] ; then
echo "Installing Fierce2"
cd /pentest/enumeration && svn co https://svn.assembla.com/svn/fierce/fierce2/trunk/ fierce2/
cd fierce2 && sudo cpanm --installdeps .
perl Makefile.PL && make
sudo make install
fi
if [ ! -d /pentest/wireless/kismet ] ; then
echo "Installing Kismet"
cd /pentest/wireless && svn co https://www.kismetwireless.net/code/svn/trunk kismet
cd /pentest/wireless/kismet
./configure && make dep
make && sudo make install
fi
if [ ! -d /pentest/wireless/aircrack-ng ] ; then
echo "Installing Aircrack Tools"
cd /pentest/wireless && svn co http://trac.aircrack-ng.org/svn/trunk aircrack-ng
cd /pentest/wireless/aircrack-ng && make
sudo make install && airodump-ng-oui-update
fi
if [ ! -d /pentest/wireless/airgraph-ng ] ; then
cd /pentest/wireless && svn co http://trac.aircrack-ng.org/svn/trunk/scripts/airgraph-ng airgraph-ng
cd /pentest/wireless/airgraph-ng && chmod 755 airgraph-ng
fi
if [ ! -d /pentest/web/captcha-breaker ] ; then
echo "Installing Captcha Breaker"
cd /pentest/web && svn checkout http://captcha-breaker.googlecode.com/svn/trunk/ captcha-breaker
fi
if [ ! -d /pentest/enumeration/dnsmap ] ; then
echo "Installing DNSMap"
cd /pentest/enumeration && svn checkout http://dnsmap.googlecode.com/svn/trunk/ dnsmap
cd /pentest/enumeration/dnsmap && wget http://dnsmap.googlecode.com/files/wordlist_TLAs.txt
fi
if [ ! -d /pentest/database/sqlmap ] ; then
echo "Installing SQL Map"
cd /pentest/database && svn checkout https://svn.sqlmap.org/sqlmap/trunk/sqlmap sqlmap
fi
if [ ! -d /pentest/database/sqlninja ] ; then
echo "Installing SQL Ninja"
cd /pentest/database && svn co https://sqlninja.svn.sourceforge.net/svnroot/sqlninja
sudo cpanm IO::Socket::SSL && sudo cpanm NetPacket::ICMP
fi
if [ ! -d /pentest/web/laudanum ] ; then
echo "Installing Laudanum"
cd /pentest/web && svn co https://laudanum.svn.sourceforge.net/svnroot/laudanum laudanum
fi
if [ ! -d /pentest/database/fuzzdb ] ; then
echo "Installing FuzzDB"
cd /pentest/database && svn checkout http://fuzzdb.googlecode.com/svn/trunk/ fuzzdb
fi
if [ ! -d /pentest/enumeration/monkeyfist ] ; then
echo "Installing MonkeyFist"
cd /pentest/enumeration && svn checkout http://monkeyfist.googlecode.com/svn/trunk/ monkeyfist
fi
if [ ! -d /pentest/fuzzers/jbrofuzz ] ; then
echo "Installing JBroFuzz"
cd /pentest/fuzzers && svn co https://jbrofuzz.svn.sourceforge.net/svnroot/jbrofuzz jbrofuzz
cd /pentest/fuzzers/jbrofuzz/jar && chmod 700 jbrofuzz.sh
fi
if [ ! -d /pentest/web/phpshell ] ; then
echo "Installing PHP Shell"
cd /pentest/web && svn co https://phpshell.svn.sourceforge.net/svnroot/phpshell phpshell
fi
if [ ! -d /pentest/web/htshells ] ; then
echo "Installing htshells"
cd /pentest/web && git clone git://github.com/wireghoul/htshells.git
fi
if [ ! -d /pentest/enumeration/dnsenum ] ; then
echo "Installing DNSenum"
cd /pentest/enumeration && svn checkout http://dnsenum.googlecode.com/svn/trunk/ dnsenum
fi
if [ ! -d /pentest/fuzzers/wsfuzzer ] ; then
echo "Installing WSFuzzer"
cd /pentest/fuzzers && svn co https://wsfuzzer.svn.sourceforge.net/svnroot/wsfuzzer wsfuzzer
fi
if [ ! -d /pentest/wireless/pyrit ] ; then
echo "Installing Pyrit"
cd /pentest/wireless && svn co http://pyrit.googlecode.com/svn/trunk/ pyrit
cd /pentest/wireless/pyrit/pyrit && python setup.py build 
sudo python setup.py install
fi
if [ ! -d /pentest/exploits/middler ] ; then
echo "Installing Middler"
cd /pentest/exploits && svn checkout http://middler.googlecode.com/svn/trunk/ middler
fi
if [ ! -d /pentest/exploits/keimpx ] ; then
echo "Installing keimpx"
cd /pentest/exploits && svn checkout http://keimpx.googlecode.com/svn/trunk/ keimpx
fi
if [ ! -d /pentest/misc/redmine ] ; then
echo "Installing Redmine"
cd /pentest/misc && svn co http://redmine.rubyforge.org/svn/branches/1.2-stable redmine
echo "Enter the root mysql password to create the redmine database and user"
mysql -u root -p -e "create database redmine character set utf8;"
mysql -u root -p -e "grant all privileges on redmine.* to 'redmine'@'localhost' identified by 'redminelocal';"
cp config/database.yml.example config/database.yml
rake db:migrate RAILS_ENV="production"
echo "If this fails make sure require 'rake/dsl_definition' is in the Rakefile ands you setup database.yml"
fi
if [ ! -d /pentest/voip/sipvicious ] ; then
echo "Installing SIPVicious"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/sip/sipvicious-0.2.6.tar.gz
tar zxvf sipvicious-0.2.6.tar.gz && rm -rf sipvicious-0.2.6.tar.gz
mv sipvicious/ /pentest/voip/ && cd /pentest/voip/sipvicious
svn up
fi
if [ ! -d /pentest/scanners/nmap ] ; then
echo "Installing and compiling nmap"
cd /pentest/scanners && svn co --username guest --password "" svn://svn.insecure.org/nmap/ nmap
cd /pentest/scanners/nmap
make clean
./configure && make
sudo make install
fi
if [ ! -d /pentest/scanners/ncrack ] ; then
echo "Installing and compiling ncrack"
cd /pentest/scanners && svn co --username guest --password "" svn://svn.insecure.org/ncrack ncrack
cd /pentest/scanners/ncrack
make clean
./configure && make
sudo make install
# install Vuln Portal
if [ ! -d /var/www/search ] ; then
echo "Installing Vulnerability Database Portal"
cd /var/www/ && sudo svn checkout http://va-pt.googlecode.com/svn/trunk/search search
echo "The portal is now available at http://localhost/search/"
#
