#Migration Verified
#General exploitation frameworks
if [ ! -d /vapt/exploits/metasploit-framework ] ; then
echo "Installing Metasploit"
cd /vapt/exploits && git clone https://github.com/rapid7/metasploit-framework.git
cd /vapt/exploits/metasploit-framework && bundle install
fi
if [ ! -d /vapt/exploits/social-engineer-toolkit ] ; then
echo "Installing the Social Engineering Toolkit"
cd /vapt/exploits && git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit && pip3 install -r requirements.txt
fi
if [ ! -d /vapt/exploits/exploit-database ] ; then
echo "Installing latest ExploitDB archive"
cd /vapt/exploits && git clone https://github.com/offensive-security/exploit-database.git
fi
if [ ! -d /vapt/exploits/Responder ] ; then
echo "Installing lgandx Responder"
cd /vapt/exploits/ && git clone https://github.com/lgandx/Responder.git
fi
if [ ! -d /vapt/exploits/impacket ] ; then
echo "Installing Impacket"
cd /vapt/exploits && git clone https://github.com/CoreSecurity/impacket.git
cd impacket && pip3 install -r requirements.txt
sudo python setup.py install
fi
if [ ! -d /vapt/exploits/beef ] ; then
echo "Installing Beef"
cd /vapt/exploits/ && git clone https://github.com/beefproject/beef.git
fi
if [ ! -d /vapt/exploits/ADFSpray ] ; then
cd /vapt/exploits/ && git clone https://github.com/xFreed0m/ADFSpray.git
cd ADFSpray && pip3 install -r requirements.txt
fi
if [ ! -d /vapt/exploits/mimikatz ] ; then
cd /vapt/exploits/ && git clone https://github.com/gentilkiwi/mimikatz.git
fi
if [ ! -d /vapt/exploits/DeathStar ] ; then
cd /vapt/exploits/ && git clone https://github.com/byt3bl33d3r/DeathStar.git
cd DeathStar && pip3 install -r requirements.txt
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
if [ ! -d /vapt/web/joomscan ] ; then
echo "Instaling Joomla Scanner"
cd /vapt/web/ && git clone https://github.com/rezasp/joomscan.git
fi

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
sudo python setup.py install
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
cd /vapt/intel/recon-ng && pip3 install -r REQUIREMENTS
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
if [ ! -d /vapt/intel/scrying ] ; then
echo "Installing Scrying"
cd /vapt/intel/ && git clone https://github.com/nccgroup/scrying.git
fi
if [ ! -d /vapt/intel/EyeWitness ] ; then
echo "Installing EyeWitness"
cd /vapt/intel/ && git clone https://github.com/FortyNorthSecurity/EyeWitness.git
fi
if [ ! -d /vapt/intel/GRecon ] ; then
echo "Installing GRecon"
cd /vapt/intel/ && git clone https://github.com/adnane-X-tebbaa/GRecon.git
cd /vapt/intel/GRecon && python3 -m pip install -r requirements.txt
fi

#Password tools
if [ ! -d /vapt/passwords/JohnTheRipper ] ; then
echo "Installing JohnTheRipper"
cd /vapt/passwords/ && git clone https://github.com/magnumripper/JohnTheRipper.git
cd JohnTheRipper/src && ./configure
make -s clean && make -sj4
make install
fi
if [ ! -d /vapt/passwords/hashcat ] ; then
echo "Installing Hashcat"
cd /vapt/passwords/ && git clone https://github.com/hashcat/hashcat.git
fi
if [ ! -d /vapt/passwords/CeWL ] ; then
echo "Installing Cewl Password Generator"
cd /vapt/passwords && git clone https://github.com/digininja/CeWL.git
fi
if [ ! -d /vapt/passwords/SecLists ]; then
echo "Installing the wordlist collection"
cd /vapt/passwords && git clone https://github.com/danielmiessler/SecLists.git
fi

#Fuzzers
if [ ! -d /vapt/fuzzers/boofuzz ] ; then
echo "Installing boofuzz"
cd /vapt/fuzzers && git clone https://github.com/jtpereyda/boofuzz.git
fi

#Powershell tools
if [ ! -d /vapt/powershell/PowerSploit ] ; then
echo "Installing PowerSploit"
cd /vapt/powershell && git clone https://github.com/mattifestation/PowerSploit.git
fi
if [ ! -d /vapt/powershell/ps1encode ] ; then
echo "Installing Powershell Encoder"
cd /vapt/powershell && git clone https://github.com/CroweCybersecurity/ps1encode.git
fi
if [ ! -d /vapt/powershell/Invoke-TheHash ] ; then
echo "Installing Powershell Invoke-TheHash"
cd /vapt/powershell && git clone https://github.com/Kevin-Robertson/Invoke-TheHash.git
fi
if [ ! -d /vapt/powershell/PowerShdll ] ; then
echo "Installing Power Shell DLL"
cd /vapt/powershell && git clone https://github.com/p3nt4/PowerShdll.git
fi

#Misc Audit Tools
if [ ! -d /vapt/audit/PowerZure ] ; then
cd /vapt/audit && git clone https://github.com/hausec/PowerZure.git
fi
if [ ! -d /vapt/audit/PlumHound ] ; then
cd /vapt/audit && git clone https://github.com/PlumHound/PlumHound.git
cd PlumHound && pip3 install -r requirements.txt
fi
#under review
#if [ ! -d /vapt/audit/caldera ] ; then
#cd /vapt/audit && git clone https://github.com/mitre/caldera.git
#cd caldera && pip3 install -r requirements.txt
#fi
