#Migration Verified
#General exploitation frameworks
if [ ! -d /vapt/exploits/metasploit-framework ] ; then
echo "Installing Metasploit"
cd /vapt/exploits && git clone https://github.com/rapid7/metasploit-framework.git
cd /vapt/exploits/metasploit-framework && bundle install
fi
if [ ! -d /vapt/exploits/set ] ; then
echo "Installing the Social Engineering Toolkit"
cd /vapt/exploits && git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd set && sudo python setup.py install
fi
if [ ! -d /vapt/exploits/exploitdb ] ; then
echo "Installing latest ExploitDB archive"
cd /vapt/exploits && git clone https://github.com/offensive-security/exploit-database.git exploitdb
fi
if [ ! -d /vapt/exploits/Responder ] ; then
echo "Installing lgandx Responder"
cd /vapt/exploits/ && git clone https://github.com/lgandx/Responder.git
fi
if [ ! -f /usr/local/bin/smbclient.py ] ; then
echo "Installing Impacket"
cd /vapt/exploits && git clone https://github.com/CoreSecurity/impacket.git
cd impacket && python setup.py install
fi

#web testing tools
if [ ! -d /vapt/web/nikto ] ; then
echo "Installing Nikto"
cd /vapt/web && git clone https://github.com/sullo/nikto.git
fi
if [ ! -d /vapt/web/php-webshells ] ; then
echo "Installing PHP Shell"
cd /vapt/web && git clone https://github.com/JohnTroony/php-webshells.git
fi
if [ ! -d /vapt/web/htshells ] ; then
echo "Installing htshells"
cd /vapt/web && git clone git://github.com/wireghoul/htshells.git
fi
if [ ! -d /vapt/web/WhatWeb ] ; then
echo "Installing WhatWeb"
cd /vapt/web && git clone git://github.com/urbanadventurer/WhatWeb.git
fi
if [ ! -d /vapt/web/watobo ] ; then
echo "Installing Watobo"
cd /vapt/web/ && git clone https://github.com/siberas/watobo.git
fi

#database testing tools


#generic scanners
if [ ! -d /vapt/scanners/sqlmap ] ; then
echo "Installing SQL Map"
cd /vapt/scanners && git clone https://github.com/sqlmapproject/sqlmap.git
fi
if [ ! -d /vapt/scanners/nmap ] ; then
echo "Installing nmap and ncrack"
cd /vapt/scanners && git clone https://github.com/nmap/nmap.git
cd nmap && ./configure
make && sudo make install
fi
if [ ! -d /vapt/scanners/hydra ] ; then
echo "Installing THC-Hydra"
cd /vapt/scanners && git clone https://github.com/vanhauser-thc/thc-hydra.git hydra
cd hydra && ./configure
make && sudo make install
fi
if [ ! -d /vapt/scanners/fierce ] ; then
echo "Installing Fierce"
cd /vapt/scanners && git clone https://github.com/mschwager/fierce.git
cd fierce && python3 -m pip install -r requirements.txt
fi
if [ ! -d /vapt/scanners/dnsmap ] ; then
echo "Installing DNSMap"
cd /vapt/scanners && git clone https://github.com/makefu/dnsmap.git
cd /vapt/scanners/dnsmap && gcc -o dnsmap dnsmap.c
fi
if [ ! -d /vapt/scanners/dnsenum ] ; then
echo "Installing DNSenum"
cd /vapt/scanners && git clone https://github.com/fwaeytens/dnsenum.git 
fi
if [ ! -d /vapt/scanners/cisco-SNMP-enumeration ] ; then
echo "Installing Cisco SNMP Enum"
cd /vapt/scanners && git clone  https://github.com/nccgroup/cisco-SNMP-enumeration.git
fi

#OSINT/Intel Tool
if [ ! -d /vapt/intel/recon-ng ] ; then
echo "Installing Recon-NG"
cd /vapt/intel/ && git clone https://github.com/lanmaster53/recon-ng.git
fi
if [ ! -d /vapt/intel/spiderfoot ] ; then
echo "Spiderfoot OSINT Tool"
cd /vapt/intel && git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot && pip3 install -r requirements.txt
fi
if [ ! -d /vapt/intel/theHarvester ] ; then
echo "Installing the Harvester"
cd /vapt/intel && git clone https://github.com/laramies/theHarvester.git 
cd /vapt/intel/theHarvester && pip3 install -r requirements.txt
fi

#To be reviewed
echo "Beginning subverion package installation"
if [ ! -d /vapt/wireless/giskismet ] ; then
echo "Installing gisKismet"
cd /vapt/wireless && git clone https://github.com/xtr4nge/giskismet.git
cd /vapt/wireless/giskismet && sudo cpanm --installdeps .
sudo perl Makefile.PL && make
sudo make install
fi

if [ ! -d /vapt/fuzzers/sulley ] ; then
echo "Installing Sulley"
cd /vapt/fuzzers && git clone https://github.com/OpenRCE/sulley.git 
fi

if [ ! -d /vapt/web/joomscan ] ; then
echo "Instaling Joomla Scanner"
cd /vapt/web/ && git clone https://github.com/rezasp/joomscan.git
fi

if [ ! -d /var/www/html/beef ] ; then
echo "Installing Beef"
cd /var/www/html && sudo git clone https://github.com/beefproject/beef.git
fi


if [ ! -d /vapt/fuzzers/fuzzdb ] ; then
echo "Installing FuzzDB"
cd /vapt/fuzzers && git clone https://github.com/fuzzdb-project/fuzzdb.git
fi
if [ ! -d /vapt/fuzzers/jbrofuzz ] ; then
echo "Installing JBroFuzz"
cd /vapt/fuzzers && git clone https://github.com/twilsonb/jbrofuzz.git
fi



if [ ! -d /vapt/web/jboss-autopwn ] ; then
echo "Install Jboss Autopwn"
cd /vapt/web && git clone https://github.com/SpiderLabs/jboss-autopwn.git
fi

if [ ! -d /vapt/passwords/ntlmsspparse ] ; then
echo "Installing NTLMS Parse"
cd /vapt/passwords && git clone https://github.com/psychomario/ntlmsspparse.git
fi

if [ ! -d /vapt/scanners/groupenum ] ; then
echo "Installing Spiderlabs groupenum"
cd /vapt/scanners/ && git clone https://github.com/SpiderLabs/groupenum.git
fi

if [ ! -d /vapt/wireless/weape ] ; then
echo "Installing Wireless EAP Username Extractor"
cd /vapt/wireless && git clone https://github.com/commonexploits/weape.git
fi

if [ ! -d /vapt/wireless/wifijammer ] ; then
echo "Installing wifijammer"
cd /vapt/wireless && git clone https://github.com/DanMcInerney/wifijammer.git
fi
if [ ! -d /vapt/passwords/PCredz ] ; then
echo "Installing PCredz"
cd /vapt/passwords && git clone https://github.com/lgandx/PCredz.git
fi
if [ ! -d /vapt/exploits/pth-toolkit ] ; then
echo "Installing the PTH Toolkit"
cd /vapt/exploits && git clone https://github.com/byt3bl33d3r/pth-toolkit.git
fi
if [ ! -d /vapt/passwords/gpp-decrypt ] ; then
echo "Installing gpp-dercypt"
cd /vapt/passwords && git clone https://github.com/BustedSec/gpp-decrypt.git
fi

if [ ! -d /vapt/web/arachni ] ; then
echo "Installing Arachni Web Scanner"
cd /vapt/temp && wget https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
tar zxvf arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
mv arachni-1.5.1-0.5.12/ /vapt/web/arachni && rm arachni-1.5.1-0.5.12-linux-x86_64.tar.gz
fi
if [ ! -d /vapt/exploits/powershell/PowerTools ] ; then
echo "Installing PowerTools"
cd /vapt/exploits/powershell && git clone https://github.com/PowerShellEmpire/PowerTools.git
fi
if [ ! -d /vapt/exploits/powershell/PowerSploit ] ; then
echo "Installing PowerSploit"
cd /vapt/exploits/powershell/ && git clone https://github.com/mattifestation/PowerSploit.git
fi
if [ ! -d /vapt/exploits/powershell/ps1encode ] ; then
echo "Installing Powershell Encoder"
cd /vapt/exploits/powershell/ && git clone https://github.com/CroweCybersecurity/ps1encode.git
fi
if [ ! -d /vapt/exploits/powershell/Invoke-TheHash ] ; then
echo "Installing Powershell Invoke-TheHash"
cd /vapt/exploits/powershell/ && git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
fi
if [ ! -d /vapt/exploits/powershell/PowerShdll ] ; then
echo "Installing Power Shell DLL"
cd /vapt/exploits/powershell && git clone https://github.com/p3nt4/PowerShdll.git
fi

if [ ! -d /vapt/web/Photon ] ; then
echo "Installing Photon - Web App Recon Tool"
cd /vapt/web/ && git clone https://github.com/s0md3v/Photon.git
cd Photon && pip install -r requirements.txt
fi
if [ ! -d /vapt/web/XSStrike ] ; then
echo "Installing XSStrike"
cd /vapt/web && git clone https://github.com/UltimateHackers/XSStrike
cd XSStrike && sudo pip install -r requirements.txt
fi
if [ ! -d /vapt/web/xsser ] ; then
echo "Installing XSSer"
cd /vapt/web/ && git clone https://github.com/epsylon/xsser-public.git xsser
fi

if [ ! -d /vapt/passwords/Usernames ]; then
echo "Installing the wordlist collection"
cd /vapt/temp && git clone https://github.com/danielmiessler/SecLists.git
cd SecLists && mv Passwords /vapt/passwords
mv Usernames /vapt/passwords && cd /vapt/temp
rm -rf SecLists/
fi
if [ ! -d /vapt/database/NoSQLMap ] ; then
echo "Installing NoSQLMAP"
cd /vapt/database && git clone https://github.com/tcstool/NoSQLMap.git
fi
if [ ! -d /vapt/exfiltrate/cloakify ] ; then
echo "Installing Cloakify"
cd /vapt/exfiltrate && git clone https://github.com/TryCatchHCF/Cloakify.git cloakify
fi
if [ ! -d /vapt/exfiltrate/udp2raw-tunnel ] ; then
echo "Installing udp2raw-tunnel"
cd /vapt/exfiltrate && git clone https://github.com/wangyu-/udp2raw-tunnel.git
fi
if [ ! -d /vapt/web/brutexss ] ; then
echo "Installing bruteXSS"
cd /vapt/web && git clone https://github.com/shawarkhanethicalhacker/BruteXSS-1.git brutexss
fi
if [ ! -d /vapt/web/droopescan ] ; then
echo "Installing Droopescan"
cd /vapt/web && git clone https://github.com/droope/droopescan.git droopescan
fi
if [ ! -d /vapt/scanners/sublist3r ] ; then
echo "Installing sublist3r"
cd /vapt/scanners && git clone https://github.com/aboul3la/Sublist3r.git sublist3r
fi
if [ ! -d /vapt/web/weevely ] ; then
echo "Installing weevely"
cd /vapt/web && git clone https://github.com/epinna/weevely3.git weevely
fi
if [ ! -d /vapt/exploits/spraywmi ] ; then
echo "Installing spraywmi"
cd /vapt/exploits && git clone https://github.com/trustedsec/spraywmi.git
fi
if [ ! -d /vapt/scanners/rdp-sec-check ] ; then
echo "Installing RDP Security Checker"
cd /vapt/scanners/ && git clone https://github.com/portcullislabs/rdp-sec-check.git
fi
if [ ! -d /vapt/scanners/enum4linux ] ; then
echo "Installing Windows Enum Tools"
cd /vapt/scanners/ && git clone https://github.com/portcullislabs/enum4linux.git
cd /vapt/temp && wget http://labs.portcullis.co.uk/download/polenum-0.2.tar.bz2 --no-check-certificate
bunzip2 polenum-0.2.tar.bz2 && tar xvf polenum-0.2.tar
rm -rf polenum-0.2.tar && sudo mv polenum-0.2/polenum.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/polenum.py && rm -rf rm -rf polenum-0.2/
fi
if [ ! -d /vapt/wireless/cowpatty ] ; then
echo "Installing CowPatty"
cd /vapt/wireless && git clone https://github.com/roobixx/cowpatty.git
cd cowpatty && make
fi
if [ ! -d /vapt/wireless/asleap ] ; then
echo "Installing asleap"
cd /vapt/wireless/ && git clone https://github.com/joswr1ght/asleap.git
cd asleap && make
fi

if [ ! -d /vapt/passwords/hashcat ] ; then
echo "Installing Hashcat"
cd /vapt/passwords/ && git clone https://github.com/hashcat/hashcat.git
fi
if [ ! -d /vapt/passwords/JohnTheRipper ] ; then
echo "Installing JohnTheRipper"
cd /vapt/passwords/ && git clone https://github.com/magnumripper/JohnTheRipper.git
cd JohnTheRipper/src && ./configure
make -sj4 && make install
fi

if [ ! -d /vapt/web/ShortShells ] ; then
echo "Instlling Short Shells - web shell collection"
cd /vapt/web && git clone https://github.com/modux/ShortShells.git
fi
if [ ! -d /vapt/scanners/thc-ipv6 ] ; then
echo "Installing THC IPv6"
cd /vapt/scanners/ && git clone https://github.com/vanhauser-thc/thc-ipv6.git
cd thc-ipv6 && make
fi
if [ ! -d /vapt/web/svn-extractor ] ; then
echo "Installing SVN Extractor"
cd /vapt/web && git clone https://github.com/anantshri/svn-extractor.git
fi
if [ ! -d /vapt/passwords/CeWL ] ; then
echo "Installing Cewl Password Generator"
cd /vapt/passwords && git clone https://github.com/digininja/CeWL.git
fi
echo "Installing local tools"
cp /vapt/misc/va-pt/tools/copy-router-config.pl /vapt/cisco/
cp /vapt/misc/va-pt/tools/merge-router-config.pl /vapt/cisco/
cp /vapt/misc/va-pt/tools/dnsrecon.rb /vapt/scanners/
cp /vapt/misc/va-pt/tools/mysqlaudit.py /vapt/database/
# end installer
