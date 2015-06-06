[ ! -d /pentest/enumeration/ike ] && mkdir /pentest/enumeration/ike
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
cd /pentest/exploits/framework3 && bundle install
sudo chmod o+r /usr/local/lib/ruby/gems/2.1.0/gems/robots-0.10.1/lib/robots.rb
fi
if [ ! -d /pentest/exploits/Veil-Catapult ] ; then
echo "Installing Veil Catapult"
cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil-Catapult.git 
sudo /pentest/exploits/Veil-Catapult/setup.sh
fi
if [ ! -d /pentest/exploits/Veil-Evasion ] ; then
echo "Installing Veil Evasion"
cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil-Evasion.git 
sudo /pentest/exploits/Veil-Evasion/setup/setup.sh
fi
if [ ! -d /pentest/exploits/Veil-PowerView ] ; then
echo "Installing Veil PowerView"
cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil-PowerView.git
fi
if [ ! -d /pentest/voip/warvox ] ; then
echo "Installing Warvox"
cd /pentest/voip && git clone https://github.com/rapid7/warvox.git
fi
if [ ! -d /pentest/web/wapiti ] ; then
echo "Installing Wapiti"
cd /pentest/web && svn co https://svn.code.sf.net/p/wapiti/code/ wapiti
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
if [ ! -d /pentest/web/w3af ] ; then
echo "Installing w3af"
cd /pentest/web && git clone https://github.com/andresriancho/w3af.git w3af 
sudo pip install PyGithub GitPython pybloomfiltermmap esmre pdfminer futures guess-language cluster msgpack-python python-ntlm clamd xdot
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
cd /pentest/web/ && svn co http://svn.code.sf.net/p/joomscan/code/trunk joomscan
cd /pentest/web/joomscan/ && chmod 755 joomscan.pl
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
if [ ! -d /pentest/wireless/aircrack-ng ] ; then
echo "Installing Aircrack-NG"
cd /pentest/wireless && svn co http://svn.aircrack-ng.org/trunk/ aircrack-ng
cd aircrack-ng && make
sudo make install && sudo airodump-ng-oui-update
fi
#if [ ! -d /pentest/wireless/airgraph-ng ] ; then
#cd /pentest/wireless && svn co http://svn.aircrack-ng.org/trunk/ aircrack-ng
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
cd /pentest/database && svn checkout http://svn.code.sf.net/p/sqlninja/code/ sqlninja
fi
if [ ! -d /pentest/web/laudanum ] ; then
echo "Installing Laudanum"
cd /pentest/web && svn co https://svn.code.sf.net/p/laudanum/code/ laudanum
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
cd /pentest/fuzzers && svn co https://svn.code.sf.net/p/jbrofuzz/code/ jbrofuzz
cd /pentest/fuzzers/jbrofuzz/jar && chmod 700 jbrofuzz.sh
fi
if [ ! -d /pentest/web/phpshell ] ; then
echo "Installing PHP Shell"
cd /pentest/web && svn checkout svn://svn.code.sf.net/p/phpshell/code/trunk phpshell
fi
if [ ! -d /pentest/web/htshells ] ; then
echo "Installing htshells"
cd /pentest/web && git clone git://github.com/wireghoul/htshells.git
fi
#if [ ! -d /pentest/enumeration/dnsenum ] ; then
#echo "Installing DNSenum"
#cd /pentest/enumeration && svn checkout http://dnsenum.googlecode.com/svn/trunk/ dnsenum
#fi
if [ ! -d /pentest/fuzzers/wsfuzzer ] ; then
echo "Installing WSFuzzer"
cd /pentest/fuzzers && svn checkout svn://svn.code.sf.net/p/wsfuzzer/code/trunk wsfuzzer
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
bundle install --without test development
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
if [ ! -d /pentest/web/jboss-autopwn ] ; then
echo "Install Jboss Autopwn"
cd /pentest/web && git clone https://github.com/SpiderLabs/jboss-autopwn.git
fi
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
if [ ! -d /pentest/enumeration/ike/groupenum ] ; then
echo "Installing Spiderlabs groupenum"
cd /pentest/enumeration/ike && git clone https://github.com/SpiderLabs/groupenum.git
fi
if [ ! -d /pentest/web/watobo ] ; then
echo "Installing Watobo"
cd /pentest/web/ && svn checkout http://svn.code.sf.net/p/watobo/code/ watobo
fi
if [ ! -d /pentest/misc/netsniff-ng ] ; then
echo "Installing Netsniff-ng"
cd /pentest/misc && git clone git://github.com/borkmann/netsniff-ng.git
fi
if [ ! -d /pentest/voip/sipvicious ] ; then
echo "Installing SIPVicious"
cd /pentest/voip && svn checkout http://sipvicious.googlecode.com/svn/trunk/ sipvicious
fi
if [ ! -d /pentest/web/sslsplit ] ; then
echo "Installing SSL Split"
cd /pentest/web && git clone https://github.com/droe/sslsplit.git
cd sslsplit && make
sudo make install
fi
if [ ! -d /pentest/wireless/weape ] ; then
echo "Installing Wireless EAP Username Extractor"
cd /pentest/wireless && git clone https://github.com/commonexploits/weape.git
fi
if [ ! -d /pentest/passwords/john ] ; then
echo "Installing John the Ripper Jumbo Pack"
cd /pentest/passwords && git clone https://github.com/magnumripper/JohnTheRipper.git john
cd john/src && ./configure && make -s
sudo make install
fi
if [ ! -d /pentest/enumeration/hydra ] ; then
echo "Installing THC-Hydra"
cd /pentest/enumeration/ && git clone https://github.com/vanhauser-thc/thc-hydra.git hydra
cd hydra && ./configure
make && sudo make install
fi
if [ ! -d /pentest/enumeration/spiderfoot ] ; then
echo "Installing Spiderfoot"
cd /pentest/enumeration && git clone https://github.com/smicallef/spiderfoot.git spiderfoot
fi
if [ ! -d /pentest/wireless/wifijammer ] ; then
echo "Installing wifijammer"
cd /pentest/wireless && git clone https://github.com/DanMcInerney/wifijammer.git
fi
if [ ! -d /var/www/html/search ] ; then
echo "Installing Vulnerability Database Portal"
cd /var/www/html && sudo svn co http://va-pt.googlecode.com/svn/trunk/search search
echo "The vulnerability search portal is now available at http://localhost/search/"
fi
if [ ! -d /pentest/wireless/fruitwifi ] ; then
cd /pentest/temp && wget https://github.com/xtr4nge/FruityWifi/archive/master.zip
unzip master.zip  && rm -rf unzip master.zip
mv FruityWifi-master/ /pentest/wireless/fruitwifi && cd /pentest/wireless/fruitwifi
sudo ./install-FruityWifi.sh 
fi
if [ ! -d /pentest/passwords/PCredz ] ; then
echo "Installing PCredz"
cd /pentest/passwords && git clone https://github.com/lgandx/PCredz.git
fi
if [ ! -d /pentest/voip/viproy ] ; then
echo "Installing Viproy"
cd /pentest/voip/ && git clone https://github.com/fozavci/viproy-voipkit.git viproy
cd /pentest/voip/viproy
cp lib/msf/core/auxiliary/* /pentest/exploits/framework3/lib/msf/core/auxiliary/
echo "require 'msf/core/auxiliary/sip'" >> /pentest/exploits/framework3/lib/msf/core/auxiliary/mixins.rb
echo "require 'msf/core/auxiliary/skinny'" >> /pentest/exploits/framework3/lib/msf/core/auxiliary/mixins.rb
cp modules/auxiliary/voip/viproy* /pentest/exploits/framework3/modules/auxiliary/voip/
cp modules/auxiliary/spoof/cisco/viproy_cdp.rb /pentest/exploits/framework3/modules/auxiliary/spoof/cisco/
echo "You can execute msfconsole now. Viproy modules placed under auxiliary/voip/viproy*"
fi
if [ ! -d /pentest/exploits/pth-toolkit ] ; then
cd /pentest/exploits && git clone https://github.com/byt3bl33d3r/pth-toolkit.git
else
echo "PTH-Toolkit is already installed."
fi
if [ ! -d /pentest/exploits/smbexec ] ; then
echo "Installing smbexec"
cd /pentest/temp && git clone https://github.com/pentestgeek/smbexec.git
cd smbexec && sudo ./install.sh
bundle install
fi
#if [ ! -d /var/www/html/portal ] ; then
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
cp /pentest/misc/va-pt/tools/mysqlaudit.py /pentest/database/
# end installer
