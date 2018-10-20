echo "Beginning subverion package installation"
if [ ! -d /pentest/wireless/giskismet ] ; then
echo "Installing gisKismet"
cd /pentest/wireless && git clone git://git.kali.org/packages/giskismet.git 
cd /pentest/wireless/giskismet && sudo cpanm --installdeps .
sudo perl Makefile.PL && make
sudo make install
fi
#if [ ! -d /pentest/wireless/wifite/ ] ; then
#echo "Installing Wifite"
#cd /pentest/wireless && git clone https://github.com/derv82/wifite.git
#fi
if [ ! -d /pentest/exploits/set ] ; then
echo "Installing the Social Engineering Toolkit"
cd /pentest/exploits && git clone https://github.com/trustedsec/social-engineer-toolkit/ set
cd set && sudo python setup.py install
fi
if [ ! -d /pentest/exploits/metasploit-framework ] ; then
echo "Installing Metasploit"
cd /pentest/exploits && git clone https://github.com/rapid7/metasploit-framework.git
cd /pentest/exploits/metasploit-framework && sudo apt install ruby-bundler
bundle install
fi
if [ ! -d /pentest/web/fimap ] ; then
echo "Installing fimap"
cd /pentest/web && git clone https://github.com/Oweoqi/fimap.git
fi
if [ ! -d /pentest/web/w3af ] ; then
echo "Installing w3af"
cd /pentest/web && git clone https://github.com/andresriancho/w3af.git w3af 
./w3af_console && sudo /tmp/w3af_dependency_install.sh
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
cd /pentest/web/ && git clone https://github.com/rezasp/joomscan.git
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
if [ ! -d /pentest/enumeration/fierce ] ; then
echo "Installing Fierce"
cd /pentest/enumeration && git clone https://github.com/mschwager/fierce.git
cd fierce && pip install -r requirements.txt
sudo python setup.py install 
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
if [ ! -d /pentest/fuzzers/fuzzdb ] ; then
echo "Installing FuzzDB"
cd /pentest/fuzzers && git clone https://github.com/fuzzdb-project/fuzzdb.git
fi
if [ ! -d /pentest/fuzzers/jbrofuzz ] ; then
echo "Installing JBroFuzz"
cd /pentest/fuzzers && git clone https://github.com/twilsonb/jbrofuzz.git
fi
if [ ! -d /pentest/web/php-webshells ] ; then
echo "Installing PHP Shell"
cd /pentest/web && git clone https://github.com/JohnTroony/php-webshells.git
fi
if [ ! -d /pentest/web/htshells ] ; then
echo "Installing htshells"
cd /pentest/web && git clone git://github.com/wireghoul/htshells.git
fi
if [ ! -d /pentest/enumeration/dnsenum ] ; then
echo "Installing DNSenum"
cd /pentest/enumeration && git clone https://github.com/fwaeytens/dnsenum.git 
fi
if [ ! -d /pentest/passwords/DPAT ] ; then
echo "Installing Domain Password Auditing Tool"
cd /pentest/passwords && git clone https://github.com/clr2of8/DPAT.git
fi
if [ ! -d /pentest/exploits/keimpx ] ; then
echo "Installing keimpx"
cd /pentest/exploits && git clone https://github.com/inquisb/keimpx.git 
fi
if [ ! -d /pentest/audit/routerdefense ] ; then
echo "Installing Router Defense"
cd /pentest/audit && git clone https://github.com/pello/routerdefense.git 
fi
if [ ! -d /pentest/audit/audit_scripts ] ; then
echo "Installing Host Audit Scripts"
cd /pentest/audit && git clone https://github.com/vanhauser-thc/audit_scripts.git
fi
if [ ! -d /pentest/web/wpscan ] ; then
echo "Installing Wordpress Scanner"
cd /pentest/web && git clone https://github.com/wpscanteam/wpscan.git
cd wpscan && bundle install --without test development
fi
if [ ! -f /usr/local/bin/smbclient.py ] ; then
echo "Installing Impacket"
cd /pentest/exploits && git clone https://github.com/CoreSecurity/impacket.git
cd impacket && sudo python setup.py install
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
echo "Installing lgandx Responder"
cd /pentest/exploits/ && git clone https://github.com/lgandx/Responder.git Responder
fi
if [ ! -d /pentest/enumeration/groupenum ] ; then
echo "Installing Spiderlabs groupenum"
cd /pentest/enumeration/ && git clone https://github.com/SpiderLabs/groupenum.git
fi
if [ ! -d /pentest/web/watobo ] ; then
echo "Installing Watobo"
cd /pentest/web/ && git clone https://github.com/siberas/watobo.git
fi
if [ ! -d /pentest/enumeration/netsniff-ng ] ; then
echo "Installing Netsniff-ng"
cd /pentest/enumeration && git clone https://github.com/borkmann/netsniff-ng.git
cd netsniff-ng && ./configure
make && sudo make install
fi
if [ ! -d /pentest/voip/sipvicious ] ; then
echo "Installing SIPVicious"
cd /pentest/voip && git clone https://github.com/EnableSecurity/sipvicious.git
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
if [ ! -d /pentest/exploits/pth-toolkit ] ; then
echo "Installing the PTH Toolkit"
cd /pentest/exploits && git clone https://github.com/byt3bl33d3r/pth-toolkit.git
fi
if [ ! -d /pentest/passwords/gpp-decrypt ] ; then
echo "Installing gpp-dercypt"
cd /pentest/passwords && git clone https://github.com/BustedSec/gpp-decrypt.git
fi
if [ ! -d /pentest/cisco/cisco-SNMP-enumeration ] ; then
echo "Installing Cisco SNMP Enum"
cd /pentest/cisco && git clone  https://github.com/nccgroup/cisco-SNMP-enumeration.git
fi
##if [ ! -d /pentest/web/arachni ] ; then
#echo "Installing Arachni Web Scanner"
#cd /pentest/temp && wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
#cd /pentest/web && git clone https://github.com/Arachni/arachni.git
#cd arachni && bundle install
#fi
if [ ! -d /pentest/exploits/powershell/PowerTools ] ; then
echo "Installing PowerTools"
cd /pentest/exploits/powershell && git clone https://github.com/PowerShellEmpire/PowerTools.git
fi
if [ ! -d /pentest/exploits/powershell/PowerSploit ] ; then
echo "Installing PowerSploit"
cd /pentest/exploits/powershell/ && git clone https://github.com/mattifestation/PowerSploit.git
fi
if [ ! -d /pentest/exploits/powershell/ps1encode ] ; then
echo "Installing Powershell Encoder"
cd /pentest/exploits/powershell/ && git clone https://github.com/CroweCybersecurity/ps1encode.git
fi
if [ ! -d /pentest/exploits/powershell/Invoke-TheHash ] ; then
echo "Installing Powershell Invoke-TheHash"
cd /pentest/exploits/powershell/ && git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
fi
if [ ! -d /pentest/exploits/powershell/PowerShdll ] ; then
echo "Installing Power Shell DLL"
cd /pentest/exploits/powershell && git clone https://github.com/p3nt4/PowerShdll.git
fi
if [ ! -d /pentest/enumeration/recon-ng ] ; then
echo "Installing Recon-NG"
cd /pentest/enumeration/ && git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git
fi
if [ ! -d /pentest/enumeration/pasv-agrsv ] ; then
echo "Installing Passive Aggresive OSINT TOol"
cd /pentest/enumeration && git clone https://github.com/isaudits/pasv-agrsv.git
fi
if [ ! -d /pentest/enumeration/skiptracer ] ; then
echo "Installing SKIPTRACER OSINT Tool"
cd /pentest/enumeration && git clone https://github.com/xillwillx/skiptracer.git
cd skiptracer && pip install -r requirements.txt
fi
if [ ! -d /pentest/enumeration/medusa ] ; then
echo "Installing Medusa"
cd /pentest/enumeration/ && git clone https://github.com/jmk-foofus/medusa.git
cd medusa && ./configure --enable-module-ssh=yes
make && sudo make install
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
if [ ! -d /pentest/web/Photon ] ; then
echo "Installing Photon - Web App Recon Tool"
cd /pentest/web/ && git clone https://github.com/s0md3v/Photon.git
cd Photon && pip install -r requirements.txt
fi
if [ ! -d /pentest/web/XSStrike ] ; then
echo "Installing XSStrike"
cd /pentest/web && git clone https://github.com/UltimateHackers/XSStrike
cd XSStrike && sudo pip install -r requirements.txt
fi
#installing via pip for the time being
#if [ ! -d /pentest/exploits/CrackMapExec ] ; then
#echo "Installing CrackMapExec"
#cd /pentest/exploits && git clone https://github.com/byt3bl33d3r/CrackMapExec.git
#cd CrackMapExec && git submodule init
#git submodule update --recursive && sudo python setup.py install
#fi
if [ ! -d /pentest/web/xsser ] ; then
echo "Installing XSSer"
cd /pentest/web/ && git clone https://github.com/epsylon/xsser-public.git xsser
fi
if [ ! -d /pentest/exploits/exploitdb ] ; then
echo "Installing latest ExploitDB archive"
cd /pentest/exploits && git clone https://github.com/offensive-security/exploit-database.git exploitdb
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
if [ ! -d /pentest/exfiltrate/cloakify ] ; then
echo "Installing Cloakify"
cd /pentest/exfiltrate && git clone https://github.com/TryCatchHCF/Cloakify.git cloakify
fi
if [ ! -d /pentest/exfiltrate/udp2raw-tunnel ] ; then
echo "Installing udp2raw-tunnel"
cd /pentest/exfiltrate && git clone https://github.com/wangyu-/udp2raw-tunnel.git
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
cd cowpatty && make
fi
if [ ! -d /pentest/wireless/asleap ] ; then
echo "Installing asleap"
cd /pentest/wireless/ && git clone https://github.com/joswr1ght/asleap.git
cd asleap && make
fi
if [ ! -d /pentest/misc/pentest-tools/ ] ; then
cd /pentest/misc && git clone https://github.com/joshuaskorich/pentest-tools.git
fi
if [ ! -d /pentest/audit/graudit ] ; then
echo "Installing Grep Auditing Utility"
cd /pentest/audit && git clone https://github.com/wireghoul/graudit.git
fi
if [ ! -d /pentest/audit/rips-scanner ] ; then
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
cd JohnTheRipper/src && ./configure
make -sj4 && make install
fi
if [ ! -d /pentest/enumeration/spiderfoot ] ; then
echo "Spiderfoot OSINT Tool"
cd /pentest/enumeration && git clone https://github.com/smicallef/spiderfoot.git
fi
if [ ! -d /pentest/web/ShortShells ] ; then
echo "Instlling Short Shells - web shell collection"
cd /pentest/web && git clone https://github.com/modux/ShortShells.git
fi
if [ ! -d  /pentest/exploits/powershell/Empire ] ; then
echo "Installing Powershell Empire"
cd /pentest/exploits/powershell && git clone https://github.com/EmpireProject/Empire.git
cd Empire/setup && sudo ./install.sh
fi
if [ ! -d /pentest/web/winshock-test ] ; then
echo "Installing Winshock Test Script"
cd /pentest/web && git clone https://github.com/anexia-it/winshock-test.git
fi
if [ ! -d /pentest/enumeration/thc-ipv6 ] ; then
echo "Installing THC IPv6"
cd /pentest/enumeration/ && git clone https://github.com/vanhauser-thc/thc-ipv6.git
cd thc-ipv6 && make
fi
if [ ! -d /pentest/web/svn-extractor ] ; then
echo "Installing SVN Extractor"
cd /pentest/web && git clone https://github.com/anantshri/svn-extractor.git
fi
if [ ! -d /pentest/passwords/CeWL ] ; then
echo "Installing Cewl Password Generator"
cd /pentest/web && git clone https://github.com/digininja/CeWL.git
fi
if [ ! -d /pentest/exploits/Veil ] ; then
echo "Installing Veil Framework"
cd /pentest/exploits && git clone https://github.com/Veil-Framework/Veil.git
cd Veil && sudo ./config/setup.sh --force --silent
fi
#
echo "Installing local tools"
cp /pentest/misc/va-pt/tools/copy-router-config.pl /pentest/cisco/
cp /pentest/misc/va-pt/tools/merge-router-config.pl /pentest/cisco/
cp /pentest/misc/va-pt/tools/dnsrecon.rb /pentest/enumeration/
cp /pentest/misc/va-pt/tools/mysqlaudit.py /pentest/database/
# end installer
