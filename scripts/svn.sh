echo "Beginning subverion package installation"
if [ ! -d /pentest/wireless/giskismet ] ; then
echo "Installing gisKismet"
cd /pentest/wireless && svn co https://my-svn.assembla.com/svn/giskismet/trunk giskismet
cd /pentest/wireless/giskismet && sudo cpanm --installdeps .
perl Makefile.PL && make
fi
if [ ! -d /pentest/wireless/wifite/ ] ; then
echo "Installing Wifitie"
cd /pentest/wireless && svn checkout http://wifite.googlecode.com/svn/trunk/ wifite
fi
if [ ! -d /pentest/exploits/set ] ; then
echo "Installing the Social Engineering Toolkit"
cd /pentest/exploits && git clone https://github.com/trustedsec/social-engineer-toolkit/ set
cd set && sudo python setup.py install
fi
if [ ! -d /pentest/exploits/framework3 ] ; then
echo "Installing Metasploit"
cd /pentest/exploits && git clone https://github.com/rapid7/metasploit-framework.git framework3
sudo bundle install
fi
if [ ! -d /pentest/exploits/warvox ] ; then
echo "Installing Warvox"
cd /pentest/exploits && svn co http://www.metasploit.com/svn/warvox/trunk warvox
fi
if [ ! -d /pentest/web/wapiti ] ; then
echo "Installing Wapiti"
cd /pentest/web && svn co https://wapiti.svn.sourceforge.net/svnroot/wapiti wapiti
fi
if [ ! -d /pentest/fuzzers/wfuzz ] ; then
echo "Installing wfuzz"
cd /pentest/fuzzers && svn checkout http://wfuzz.googlecode.com/svn/trunk/ wfuzz
cd /pentest/fuzzers/wfuzz && chmod 700 wfuzz.py
fi
if [ ! -d /pentest/web/fimap ] ; then
echo "Installing fimap"
cd /pentest/web && svn checkout http://fimap.googlecode.com/svn/trunk/ fimap
fi
if [ ! -d /pentest/web/zap ] ; then
echo "Installing ZED Attack Proxy"
cd /pentest/temp && wget http://zaproxy.googlecode.com/files/ZAP_2.1.0_Linux.tar.gz
tar xvf ZAP_2.1.0_Linux.tar.gz && rm -rf ZAP_2.1.0_Linux.tar.gz
mv ZAP_2.1.0/ /pentest/web/zap && cd /pentest/web && svn checkout --force http://zaproxy.googlecode.com/svn/trunk/ zap 
fi
if [ ! -d /pentest/web/w3af ] ; then
echo "Installing w3af"
cd /pentest/web && git clone https://github.com/andresriancho/w3af.git w3af 
sudo pip install PyGithub GitPython pybloomfiltermmap esmre pdfminer futures guess-language cluster msgpack-python python-ntlm
sudo pip install -e git+git://github.com/ramen/phply.git#egg=phply
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
if [ ! -d /pentest/web/joomscan ] ; then
echo "Instaling Joomla Scanner"
cd /pentest/web/ && svn co https://joomscan.svn.sourceforge.net/svnroot/joomscan joomscan
cd /pentest/web/joomscan/trunk && chmod 755 joomscan.pl
fi
if [ ! -d /pentest/enumeration/theharvester ] ; then
echo "Installing the Harvester"
cd /pentest/enumeration && svn checkout http://theharvester.googlecode.com/svn/trunk/ theharvester
cd /pentest/enumeration/theharvester && chmod 755 theHarvester.py
fi
if [ ! -d /pentest/web/sslyze ] ; then
cd /pentest/web && git clone https://github.com/iSECPartners/sslyze.git
fi
if [ ! -d /var/www/beef/.git/ ] ; then
echo "Installing Beef"
cd /var/www && sudo git clone https://github.com/beefproject/beef.git
fi
if [ ! -d /pentest/enumeration/fierce2 ] ; then
echo "Installing Fierce2"
cd /pentest/enumeration && svn co https://svn.assembla.com/svn/fierce/fierce2/trunk/ fierce2
cd fierce2 && sudo cpanm --installdeps .
perl Makefile.PL && make
sudo make install
fi
if [ ! -d /pentest/wireless/kismet ] ; then
echo "Installing Kismet"
cd /pentest/wireless && git clone https://www.kismetwireless.net/kismet.git
cd /pentest/wireless/kismet
./configure && make dep
make && sudo make install
fi
#if [ ! -d /pentest/wireless/airgraph-ng ] ; then
#cd /pentest/wireless && svn co http://trac.aircrack-ng.org/svn/trunk/scripts/airgraph-ng airgraph-ng
#cd /pentest/wireless/airgraph-ng && chmod 755 airgraph-ng
#fi
if [ ! -d /pentest/wireless/reaver ] ; then
echo "Installing Reaver"
cd /pentest/wireless && svn checkout http://reaver-wps.googlecode.com/svn/trunk/ reaver
cd /pentest/wireless/reaver/src && ./configure
make
fi
if [ ! -d /pentest/web/captcha-breaker ] ; then
echo "Installing Captcha Breaker"
cd /pentest/web && svn checkout http://captcha-breaker.googlecode.com/svn/trunk/ captcha-breaker
fi
if [ ! -d /pentest/enumeration/dnsmap ] ; then
echo "Installing DNSMap"
cd /pentest/enumeration && svn checkout http://dnsmap.googlecode.com/svn/trunk/ dnsmap
cd /pentest/enumeration/dnsmap && gcc -o dnsmap dnsmap.c
fi
if [ ! -d /pentest/database/sqlmap ] ; then
echo "Installing SQL Map"
cd /pentest/database && git clone https://github.com/sqlmapproject/sqlmap.git
fi
if [ ! -d /pentest/database/sqlninja ] ; then
echo "Installing SQL Ninja"
cd /pentest/database && svn co https://sqlninja.svn.sourceforge.net/svnroot/sqlninja sqlninja
fi
if [ ! -d /pentest/web/laudanum ] ; then
echo "Installing Laudanum"
cd /pentest/web && svn co https://laudanum.svn.sourceforge.net/svnroot/laudanum laudanum
fi
if [ ! -d /pentest/fuzzers/fuzzdb ] ; then
echo "Installing FuzzDB"
cd /pentest/fuzzers && svn checkout http://fuzzdb.googlecode.com/svn/trunk/ fuzzdb
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
if [ ! -d /pentest/passwords/pyrit ] ; then
echo "Installing Pyrit"
cd /pentest/passwords && svn co http://pyrit.googlecode.com/svn/trunk/ pyrit
cd /pentest/passwords/pyrit/pyrit && python setup.py build 
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
if [ ! -d /pentest/audit/routerdefense ] ; then
echo "Installing Router Defense"
cd /pentest/audit && svn checkout http://routerdefense.googlecode.com/svn/trunk/ routerdefense
fi
if [ ! -d /pentest/web/wpscan ] ; then
echo "Installing Wordpress Scanner"
cd /pentest/web && git clone https://github.com/wpscanteam/wpscan.git
sudo bundle install --without test development
fi
if [ ! -f /usr/local/bin/smbclient.py ] ; then
echo "Installing Impacket"
cd /pentest/temp && svn checkout http://impacket.googlecode.com/svn/trunk/ impacket
cd impacket && sudo python setup.py install
cd /pentest/temp && sudo rm -rf impacket
fi
if [ ! -d /pentest/web/WhatWeb ] ; then
echo "Installing WhatWeb"
cd /pentest/web && git clone git://github.com/urbanadventurer/WhatWeb.git
fi
#if [ ! -d /pentest/misc/redmine ] ; then
#echo "Installing Redmine"
#cd /pentest/misc && svn co http://redmine.rubyforge.org/svn/branches/1.2-stable redmine
#echo "Enter the root mysql password to create the redmine database and user"
#mysql -u root -p -e "create database redmine character set utf8;"
#mysql -u root -p -e "grant all privileges on redmine.* to 'redmine'@'localhost' identified by 'redminelocal';"
#cd /pentest/misc/redmine && cp config/database.yml.example config/database.yml
#echo ""
#echo "enter the correct username/password for the redmine install in config/database.yml before attempting start"
#echo "If this fails make sure require 'rake/dsl_definition' is in the Rakefile ands you setup database.yml"
#echo "Once you have entered the correct user/pass migrate the db rake db:migrate RAILS_ENV="production""
#fi
if [ ! -d /pentest/scanners/nmap ] ; then
echo "Installing and compiling nmap"
cd /pentest/scanners && svn co https://svn.nmap.org/nmap nmap
cd /pentest/scanners/nmap && ./configure
make && sudo make install
fi
if [ ! -d /pentest/scanners/ncrack ] ; then
echo "Installing and compiling ncrack"
cd /pentest/scanners && svn co https://svn.nmap.org/ncrack ncrack
cd /pentest/scanners/ncrack && ./configure
make && sudo make install
fi
if [ ! -d /pentest/passwords/ntlmsspparse ] ; then
echo "Installing NTLMS Parse"
cd /pentest/passwords && git clone https://github.com/psychomario/ntlmsspparse.git
fi
if [ ! -d /pentest/enumeration/ptscripts ] ; then
echo "Installing recon-ng"
cd /pentest/enumeration && svn checkout http://ptscripts.googlecode.com/svn/trunk/ ptscripts
fi
if [ ! -d /pentest/exploits/Responder ] ; then
echo "Installing Spiderlabs Resonder"
cd /pentest/exploits/ && git clone https://github.com/SpiderLabs/Responder.git
fi
# install Vuln Portal
if [ ! -d /var/www/search ] ; then
echo "Installing Vulnerability Database Portal"
cd /var/www/ && sudo svn co http://va-pt.googlecode.com/svn/trunk/search search
echo "The vulnerability search portal is now available at http://localhost/search/"
fi
#if [ ! -d /var/www/portal ] ; then
#echo "Installing the VA-PT Portal"
#cd /var/www/ && sudo svn checkout https://va-pt.googlecode.com/svn/trunk/portal portal
#echo Creating necessary database and structure, enter the root mysql password
#mysqladmin create application -u root -p && mysql -u root -p -e "grant all privileges on application.* to 'vapt'@'localhost';"
#echo "adding default user account - vapt/vapt"
#echo "The VA-PT Portal is now available at http://localhost/portal"
#fi
echo "Installing local tools"
cp /pentest/misc/va-pt/tools/copy-router-config.pl /pentest/cisco/
cp /pentest/misc/va-pt/tools/merge-router-config.pl /pentest/cisco/
cp /pentest/misc/va-pt/tools/dnsrecon.rb /pentest/enumeration/
echo "Subversion package installation complete"
