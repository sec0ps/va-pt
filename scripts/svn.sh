echo "Beginning subverion package installation"
if [ ! -d /pentest/wireless/giskismet ] ; then
echo "Installing gisKismet"
cd /pentest/wireless && git clone git://git.kali.org/packages/giskismet.git 
cd /pentest/wireless/giskismet && sudo cpanm --installdeps .
sudo perl Makefile.PL && make
sudo make install
fi
if [ ! -d /pentest/wireless/wifite/ ] ; then
echo "Installing Wifitie"
cd /pentest/wireless && git clone https://github.com/derv82/wifite.git
fi
if [ ! -d /pentest/exploits/set ] ; theneil
echo "Installing the Social Engineering Toolkit"
cd /pentest/exploits && git clone https://github.com/trustedsec/social-engineer-toolkit/ set
cd set && sudo python setup.py install
fi
if [ ! -d /pentest/exploits/framework3 ] ; then
echo "Installing Metasploit"
cd /pentest/exploits && git clone https://github.com/rapid7/metasploit-framework.git framework3
cd /pentest/exploits/framework3 && bundle install
sudo chmod o+r /var/lib/gems/2.3.0/gems/robots-0.10.1/lib/robots.rb
fi
if [ ! -d /pentest/web/fimap ] ; then
echo "Installing fimap"
cd /pentest/web && git clone https://github.com/Oweoqi/fimap.git
fi
if [ ! -d /pentest/web/w3af ] ; then
echo "Installing w3af"
cd /pentest/web && git clone https://github.com/andresriancho/w3af.git w3af 
sudo pip install PyGithub GitPython pybloomfiltermmap esmre pdfminer futures guess-language cluster msgpack-python python-ntlm clamd xdot
sudo pip install -e git+git://github.com/ramen/phply.git#egg=phply
fi
if [ ! -d /pentest/web/wafw00f ] ; then
echo "Installing wafw00f"
cd /pentest/web && git clone https://github.com/EnableSecurity/wafw00f.git
cd /pentest/web/wafw00f && sudo python setup.py install
fi
fi
if [ ! -d /pentest/fuzzers/sulley ] ; then
echo "Installing Sulley"
cd /pentest/fuzzers && git clone https://github.com/OpenRCE/sulley.git 
fi
if [ ! -d /pentest/web/nikto ] ; then
echo "Installing Nikto"
cd /pentest/web && git clone https://github.com/sullo/nikto.git
fi
if [ ! -d /pentest/web/joomscan ] ; then
echo "Instaling Joomla Scanner"
cd /pentest/web/ && svn co http://svn.code.sf.net/p/joomscan/code/trunk joomscan
cd /pentest/web/joomscan/ && chmod 755 joomscan.pl
fi
if [ ! -d /pentest/enumeration/theHarvester ] ; then
echo "Installing the Harvester"
cd /pentest/enumeration && git clone https://github.com/laramies/theHarvester.git 
cd /pentest/enumeration/theHarvester && chmod 755 theHarvester.py
fi
if [ ! -d /var/www/html/beef ] ; then
echo "Installing Beef"
cd /var/www/html && sudo git clone https://github.com/beefproject/beef.git
fi
if [ ! -d /pentest/enumeration/fierce2 ] ; then
echo "Installing Fierce2"
cd /pentest/enumeration && svn co https://svn.assembla.com/svn/fierce/fierce2/trunk/ fierce2
cd fierce2 && sudo cpanm --installdeps .
sudo perl Makefile.PL && make
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
cd /pentest/wireless && git clone https://github.com/aircrack-ng/aircrack-ng.git
cd aircrack-ng && make
sudo make install && sudo airodump-ng-oui-update
fi
if [ ! -d /pentest/wireless/reaver ] ; then
echo "Installing Reaver"
cd /pentest/wireless && git clone https://github.com/gabrielrcouto/reaver-wps.git reaver
cd /pentest/wireless/reaver/src && ./configure
make && sudo make install
fi
if [ ! -d /pentest/enumeration/dnsmap ] ; then
echo "Installing DNSMap"
cd /pentest/enumeration && git clone https://github.com/makefu/dnsmap.git
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
cd /pentest/fuzzers && git clone https://github.com/fuzzdb-project/fuzzdb.git
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
if [ ! -d /pentest/enumeration/dnsenum ] ; then
echo "Installing DNSenum"
cd /pentest/enumeration && git clone https://github.com/fwaeytens/dnsenum.git 
fi
if [ ! -d /pentest/fuzzers/wsfuzzer ] ; then
echo "Installing WSFuzzer"
cd /pentest/fuzzers && svn checkout svn://svn.code.sf.net/p/wsfuzzer/code/trunk wsfuzzer
fi
if [ ! -d /pentest/passwords/Pyrit ] ; then
echo "Installing Pyrit"
cd /pentest/passwords && git clone https://github.com/JPaulMora/Pyrit.git
cd /pentest/passwords/Pyrit && python setup.py build 
sudo python setup.py install
fi
if [ ! -d /pentest/exploits/keimpx ] ; then
echo "Installing keimpx"
cd /pentest/exploits && git clone https://github.com/inquisb/keimpx.git 
figroup
if [ ! -d /pentest/audit/routerdefense ] ; then
echo "Installing Router Defense"
cd /pentest/audit && git clone https://github.com/pello/routerdefense.git 
fi
if [ ! -d /pentest/web/wpscan ] ; then
echo "Installing Wordpress Scanner"
cd /pentest/web && git clone https://github.com/wpscanteam/wpscan.git
cd wpscan && bundle install --without test development
fi
if [ ! -f /usr/local/bin/smbclient.py ] ; then
echo "Installing Impacket"
cd /pentest/temp && git clone https://github.com/CoreSecurity/impacket.git
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
echo "Installing nmap and ncrack"
cd /pentest/scanners && git clone https://github.com/nmap/nmap.git
cd nmap && ./configure
make && sudo make install
fi
if [ ! -d /pentest/passwords/ntlmsspparse ] ; then
echo "Installing NTLMS Parse"
cd /pentest/passwords && git clone https://github.com/psychomario/ntlmsspparse.git
fi
if [ ! -d /pentest/exploits/Responder ] ; then
echo "Installing Spiderlabs Resonder"
cd /pentest/exploits/ && git clone https://github.com/SpiderLabs/Responder.git
fi
if [ ! -d /pentest/enumeration/groupenum ] ; then
echo "Installing Spiderlabs groupenum"
cd /pentest/enumeration/ && git clone https://github.com/SpiderLabs/groupenum.git
fi
if [ ! -d /pentest/web/watobo ] ; then
echo "Installing Watobo"
cd /pentest/web/ && svn checkout http://svn.code.sf.net/p/watobo/code/ watobo
fi
if [ ! -d /pentest/enumeration/netsniff-ng ] ; then
echo "Installing Netsniff-ng"
cd /pentest/enumeration && git clone https://github.com/borkmann/netsniff-ng.git
fi
if [ ! -d /pentest/voip/sipvicious ] ; then
echo "Installing SIPVicious"
cd /pentest/voip && git clone https://github.com/EnableSecurity/sipvicious.git
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
if [ ! -d /pentest/enumeration/hydra ] ; then
echo "Installing THC-Hydra"
cd /pentest/enumeration/ && git clone https://github.com/vanhauser-thc/thc-hydra.git hydra
cd hydra && ./configure
make && sudo make install
fi
if [ ! -d /pentest/wireless/wifijammer ] ; then
echo "Installing wifijammer"
cd /pentest/wireless && git clone https://github.com/DanMcInerney/wifijammer.git
fi
if [ ! -d /pentest/passwords/PCredz ] ; then
echo "Installing PCredz"
cd /pentest/passwords && git clone https://github.com/lgandx/PCredz.git
fi
if [ ! -d /pentest/voip/voiphopper ] ; then
echo "Installing VOIP Hopper"
cd /pentest/voip & git clone https://github.com/iknowjason/voiphopper.git
fi
if [ ! -d /pentest/voip/enumiax ] ; then
cd /pentest/voip && git clone https://github.com/foreni-packages/enumiax.git
fi
if [ ! -d /pentest/cisco/torch ] ; then
echo "Installing Cisco Torch"
cd /pentest/cisco && git clone git://git.kali.org/packages/cisco-torch.git
fi
if [ ! -d /pentest/exploits/pth-toolkit ] ; then
echo "Installing the PTH Toolkit"
cd /pentest/exploits && git clone https://github.com/byt3bl33d3r/pth-toolkit.git
fi
if [ ! -d /pentest/passwords/gpp-decrypt ] ; then
echo "Installing gpp-dercypt"
cd /pentest/passwords && git clone git://git.kali.org/packages/gpp-decrypt.git
fi
if [ ! -d /pentest/web/aesshell ] ; then
echo "Installing AES Shell"
cd /pentest/temp && wget https://dl.packetstormsecurity.net/UNIX/penetration/rootkits/aesshell-0.7.tar.bz2 --no-check-certificate
bunzip2 aesshell-0.7.tar.bz2 && tar xvf aesshell-0.7.tar
rm -rf aesshell-0.7.tar && mv aesshell/ /pentest/web
fi
if [ ! -d /pentest/cisco/cisco-SNMP-enumeration ] ; then
echo "Installing Cisco SNMP Enum"
cd /pentest/cisco && git clone  https://github.com/nccgroup/cisco-SNMP-enumeration.git
fi
if [ ! -d /pentest/web/arachni ] ; then
echo "Installing Arachni Web Scanner"
cd /pentest/web && git clone https://github.com/Arachni/arachni.git
cd arachni && bundle install
fi
if [ ! -d /pentest/exploits/powershell/PowerTools ] ; then
echo "Installing PowerTools"
cd /pentest/exploits/powershell && git clone https://github.com/PowerShellEmpire/PowerTools.git
echo "Installing PowerSploit"
git clone https://github.com/mattifestation/PowerSploit.git
fi
if [ ! -d /pentest/enumeration/recon-ng ] ; then
echo "Installing Recon-NG"
cd /pentest/enumeration/ && git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git
fi
if [ ! -d /pentest/enumeration/medusa ] ; then
echo "Installing Medusa"
cd /pentest/enumeration/ && git clone https://github.com/jmk-foofus/medusa.git
cd medusa && ./configure
make && sudo make install
fi
if [ ! -d /pentest/enumeration/pasv-agrsv ] ; then
echo "Installing Passive Aggresive OSINT TOol"
cd /pentest/enumeration && git clone https://github.com/isaudits/pasv-agrsv.git
fi
if [ ! -d /pentest/exploits/pentestly ] ; then
echo "Installing Pentestly"
cd /pentest/exploits/ && git clone https://github.com/praetorian-inc/pentestly
fi
if [ ! -d /pentest/web/rawr ] ; then
echo "Installing Rawr - Rapid Assessment of Web Resources"
cd /pentest/web/ && git clone https://bitbucket.org/al14s/rawr.git
cd rawr && sudo ./install.sh
fi
if [ ! -d /pentest/exploits/CrackMapExec ] ; then
echo "Installing CrackMapExec"
cd /pentest/exploits && git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec && git submodule init
git submodule update --recursive && sudo python setup.py install
fi
if [ ! -d /pentest/web/xsser ] ; then
echo "Installing XSSer"
cd /pentest/web/ && git clone https://github.com/epsylon/xsser-public.git xsser
fi
if [ ! -d /pentest/exploits/exploitdb ] ; then
echo "Installing latest ExploitDB archive"
cd /pentest/exploits && git clone https://github.com/offensive-security/exploit-database.git
mv exploit-database exploitdb
fi
if [ ! -d /pentest/passwords/Usernames ]; then
echo "Installing the wordlist collection"
cd /pentest/temp && git clone https://github.com/danielmiessler/SecLists.git
cd SecLists && mv Passwords /pentest/passwords
mv Usernames /pentest/passwords && cd /pentest/temp
rm -rf SecLists/
fi
if [ ! -d /pentest/database/NoSQLMap ] ; then
echo "Installing NoSQLMAP"
cd /pentest/database && git clone https://github.com/tcstool/NoSQLMap.git
fi
if [ ! -d /pentest/exploits/cloakify ] ; then
echo "Installing Cloakify"
cd /pentest/exploits && git clone https://github.com/TryCatchHCF/Cloakify.git cloakify
fi
if [ ! -d /pentest/exploits/CrackMapExec ] ; then
echo "Installing CrackMapExec"
cd /pentest/exploits && git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec && sudo python setup.py install
fi
if [ ! -d /pentest/misc/Cheatsheets ] ; then
echo "Installing Cheatsheet collection"
cd /pentest/misc && git clone https://github.com/jshaw87/Cheatsheets.git
fi
if [ ! -d /pentest/web/brutexss ] ; then
echo "Installing bruteXSS"
cd /pentest/web && git clone https://github.com/shawarkhanethicalhacker/BruteXSS.git brutexss
fi
if [ ! -d /pentest/web/droopescan ] ; then
echo "Installing Droopescan"
cd /pentest/web && git clone https://github.com/droope/droopescan.git droopescan
fi
if [ ! -d /pentest/enumeration/sublist3r ] ; then
echo "Installing sublist3r"
cd /pentest/enumeration && git clone https://github.com/aboul3la/Sublist3r.git sublist3r
fi
if [ ! -d /pentest/web/weevely ] ; then
echo "Installing weevely"
cd /pentest/web && git clone https://github.com/epinna/weevely3.git weevely
fi
if [ ! -d /pentest/exploits/spraywmi ] ; then
echo "Installing spraywmi"
cd /pentest/exploits && git clone https://github.com/trustedsec/spraywmi.git
fi
#if [ ! -d /pentest/exploits/Veil-Catapult ] ; then
#echo "Installing Veil Catapult"
#cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil-Catapult.git 
#sudo /pentest/exploits/Veil-Catapult/setup.sh
#fi
if [ ! -d /pentest/exploits/Veil-Evasion ] ; then
echo "Installing Veil Evasion"
cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil-Evasion.git 
sudo /pentest/exploits/Veil-Evasion/setup/setup.sh
fi
#if [ ! -d /pentest/exploits/Veil-PowerView ] ; then
#echo "Installing Veil PowerView"
#cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil-PowerView.git
#fi
#if [ ! -d /pentest/exploits/smbexec ] ; then
#echo "Installing smbexec"
#cd /pentest/temp && git clone https://github.com/pentestgeek/smbexec.git
#cd smbexec && sudo ./install.sh
#ln -s /opt/smbexec/ /pentest/exploits/smbexec && bundle install
#fi
if [ ! -d /pentest/enumeration/rdp-sec-check ] ; then
echo "Installing RDP Security Checker"
cd /pentest/enumeration/ && git clone https://github.com/portcullislabs/rdp-sec-check.git
fi
if [ ! -d /pentest/enumeration/enum4linux ] ; then
echo "Installing Windows Enum Tools"
cd /pentest/enumeration/ && git clone https://github.com/portcullislabs/enum4linux.git
cd /pentest/temp && wget http://labs.portcullis.co.uk/download/polenum-0.2.tar.bz2 --no-check-certificate
bunzip2 polenum-0.2.tar.bz2 && tar xvf polenum-0.2.tar
rm -rf polenum-0.2.tar && sudo mv polenum-0.2/polenum.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/polenum.py && rm -rf rm -rf polenum-0.2/
fi
if [ ! -d /pentest/wireless/cowpatty ] ; then
echo "Installing CowPatty"
cd /pentest/wireless && git clone https://github.com/roobixx/cowpatty.git
make
fi
if [ ! -d /pentest/wireless/asleap ] ; then
echo "Installing asleap"
cd /pentest/wireless/ && git clone https://github.com/joswr1ght/asleap.git
make
fi
if [ ! -d /pentest/misc/pentest-tools/ ] ; then
cd /pentest/misc && git clone https://github.com/joshuaskorich/pentest-tools.git
fi
if [ ! -d /pentest/audit/graudit ] ; then
echo "Installing Grep Auditing Utility"
cd /pentest/audit && git clone https://github.com/wireghoul/graudit.git
fi
if [ ! -d /pentest/audit/rips ] ; then
echo "Downloading RIPS PHP Static Source Code Analyzer"
cd /pentest/audit && git clone https://github.com/robocoder/rips-scanner.git
fi
if [ ! -d /pentest/passwords/hashcat ] ; then
echo "Installing Hashcat"
cd /pentest/passwords/ && git clone https://github.com/hashcat/hashcat.git
fi
if [ ! -d /pentest/passwords/JohnTheRipper ] ; then
echo "Installing JohnTheRipper"
cd /pentest/passwords/ && git clone https://github.com/magnumripper/JohnTheRipper.git
cd JohnTheRipper && ./configure
make -sj4
fi
#
echo "Installing local tools"
cp /pentest/misc/va-pt/tools/copy-router-config.pl /pentest/cisco/
cp /pentest/misc/va-pt/tools/merge-router-config.pl /pentest/cisco/
cp /pentest/misc/va-pt/tools/dnsrecon.rb /pentest/enumeration/
cp /pentest/misc/va-pt/tools/mysqlaudit.py /pentest/database/
# end installer
#if [ ! -d /pentest/voip/viproy ] ; then
#echo "Installing Viproy"
#cd /pentest/voip/ && git clone https://github.com/fozavci/viproy-voipkit.git viproy
#cd /pentest/voip/viproy
#cp lib/msf/core/auxiliary/* /pentest/exploits/framework3/lib/msf/core/auxiliary/
#echo "require 'msf/core/auxiliary/sip'" >> /pentest/exploits/framework3/lib/msf/core/auxiliary/mixins.rb
#echo "require 'msf/core/auxiliary/skinny'" >> /pentest/exploits/framework3/lib/msf/core/auxiliary/mixins.rb
#cp modules/auxiliary/voip/viproy* /pentest/exploits/framework3/modules/auxiliary/voip/
#cp modules/auxiliary/spoof/cisco/viproy_cdp.rb /pentest/exploits/framework3/modules/auxiliary/spoof/cisco/
#echo "You can execute msfconsole now. Viproy modules placed under auxiliary/voip/viproy*"
#fi
