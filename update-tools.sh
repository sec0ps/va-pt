echo "Beginning package updates"
echo "Updating SET"
cd /pentest/exploits/set && git pull
echo "Updating Metasploit"
cd /pentest/exploits/framework3 && git pull
bundle install
echo "Updating w3af"
cd /pentest/web/w3af && git pull 
echo "Updating wafw00f"
cd /pentest/web/wafw00f && git pull
echo "Updating Sulley"
cd /pentest/fuzzers/sulley && git pull 
echo "Updating Nikto"
cd /pentest/web/nikto && git pull
echo "Updating The Harvester"
cd /pentest/enumeration/theHarvester && git pull
echo "updating htshells"
cd /pentest/web/htshells && git pull
echo "Updating WPScanner"
cd /pentest/web/wpscan && git pull
echo "Updating Beef"
cd /var/www/html/beef && sudo git pull
echo "Updating Fierce"
cd /pentest/enumeration/fierce && git pull
#echo "Updating Kismet"
#cd /pentest/wireless/kismet && git pull
echo "Updating SVN Extractor"
cd /pentest/web/svn-extractor && git pull
echo "Updating Arachni Web Scanner"
cd /pentest/web/arachni && git pull
echo "Updating Watobo"
cd /pentest/web/watobo & git pull
echo "Updating Aircrack Tools"
cd /pentest/wireless/aircrack-ng && git pull
echo "Updating Reaver"
cd /pentest/wireless/reaver && git pull
echo "Updating fimap"
cd /pentest/web/fimap && git pull 
echo "Updating SQL Map"
cd /pentest/database/sqlmap && git pull
echo "Updatign FuzzDB"
cd /pentest/fuzzers/fuzzdb && git pull
echo "Updating JBroFuzz"
cd /pentest/fuzzers/jbrofuzz && git pull
echo "Updating DNS Enum"
cd /pentest/enumeration/dnsenum && git pull
echo "Updating DNSmap"
cd /pentest/enumeration/dnsmap && git pull
echo "Updating Pyrit"
cd /pentest/passwords/Pyrit && git pull
echo "Updating Router Defense"
cd /pentest/audit/routerdefense/ && git pull
echo "Updating Wifite"
cd /pentest/wireless/wifite && git pull
echo "Updating Joomla Scanner"
cd /pentest/web/joomscan && git pull
echo "Updating PHP Web Shells"
cd /pentest/web/php-webshells && git pull
echo "Updating DPAT"
cd /pentest/passwords/DPAT && git pull
echo "Updating NMAP"
cd /pentest/scanners/nmap && svn up
make clean && ./configure
make && sudo make install
sudo nmap --script-updatedb
echo "Updating WhatWeb"
cd /pentest/web/WhatWeb && git pull
echo "Updating Responder"
cd /pentest/exploits/Responder && git pull
echo "Updating Responder 2"
cd /pentest/exploits/Responder-New && git pull
echo "Updating SSL Split"
cd /pentest/web/sslsplit && git pull
echo "Updating netsniff-ng"
cd /pentest/enumeration/netsniff-ng && git pull
echo "Updating Jboss Autopwn"
cd /pentest/web/jboss-autopwn && git pull
echo "Updating Weape"
cd /pentest/wireless/weape && git pull
echo "Updating NTLM Parser"
cd /pentest/passwords/ntlmsspparse && git pull
echo "Updating RPD Sec Check"
cd /pentest/enumeration/rdp-sec-check && git pull
echo "Updating John the Ripper"
cd /pentest/passwords/JohnTheRipper && git pull
echo "Updating THC-Hydra"
cd /pentest/enumeration/hydra && git pull
echo "Updating THC IPv6"
cd /pentest/enumeration/thc-ipv6 && git pull
echo "Updating wifijammer"
cd /pentest/wireless/wifijammer && git pull
echo "Updating Enum4Linux"
cd /pentest/enumeration/enum4linux && git pull
#echo "Updating Veil Catapult"
#cd /pentest/exploits/Veil-Catapult && git pull
#echo "Updating Veil Evasion"
#cd /pentest/exploits/Veil-Evasion && git pull
#echo "Updating Veil PowerView"
#cd /pentest/exploits/Veil-PowerView && git pull
echo "Updating CowPatty"
cd /pentest/wireless/cowpatty && git pull
echo "Updating ASLeap"
cd /pentest/wireless/asleap && git pull
echo "Updating SIPvicious"
cd /pentest/voip/sipvicious && git pull
echo "Updating VOIPhopper"
cd /pentest/voip/voiphopper && git pull
echo "Updating PCredz"
cd /pentest/passwords/PCredz && git pull
echo "Updating Recon-NG"
cd /pentest/enumeration/recon-ng/ && git pull
echo "Updating the ExploitDB archive"
cd /pentest/exploits/exploitdb && git pull
echo "Updating Passive Aggresive"
cd /pentest/enumeration/pasv-agrsv && git pull
echo "Updating Medusa"
cd /pentest/enumeration/medusa && git pull
echo "Updating Pentestly"
cd /pentest/exploits/pentestly && git pull
echo "Updating Rawr"
cd /pentest/web/rawr && git pull
#echo "Updating CrackMapExec"
#cd /pentest/exploits/CrackMapExec && git pull
echo "Updating XSSer"
cd /pentest/web/xsser && git pull
echo "Updating NoSQLMAP"
cd /pentest/database/NoSQLMap && git pull
echo "Updating SQLNinja"
cd /pentest/database/sqlninja && git pull
echo "Updating Cloakify"
cd /pentest/exfiltrate/cloakify/ && git pull
echo "Updating keimpx"
cd /pentest/exploits/keimpx && git pull
echo "Updating Cheatsheet Collection"
cd /pentest/misc/Cheatsheets && git pull
echo "Updating BruteXSS"
cd /pentest/web/brutexss && git pull
echo "Updating GroupEnum"
cd /pentest/enumeration/groupenum && git pull
echo "Updating Droopescan"
cd /pentest/web/droopescan && git pull
echo "Updating sublist3r"
cd /pentest/enumeration/sublist3r && git pull
echo "Updating weevely"
cd /pentest/web/weevely && git pull
echo "Updating spraywmi"
cd /pentest/exploits/spraywmi && git pull
echo "Updating IMPACKET"
cd /pentest/exploits/impacket && git pull
sudo python setup.py install
echo "Updating UDP2Raw Tunneler"
cd /pentest/exfiltrate/udp2raw-tunnel && git pull
echo "Updating Hashcat"
cd /pentest/passwords/hashcat && git pull
echo "Updating Spiderfoot"
cd /pentest/enumeration/spiderfoot && git pull
echo "Updating ShortShells"
cd /pentest/web/ShortShells && git pull
#
echo "Updating PTH Toolkit"
cd /pentest/exploits/pth-toolkit && git pull
echo "Updating Powersploit"
cd /pentest/exploits/powershell/PowerSploit && git pull
echo "Updating Powershell Encoder"
cd /pentest/exploits/powershell/ps1encode && git pull
echo "Updating Invoke the Hash"
cd /pentest/exploits/powershell/Invoke-TheHash && git pull
echo "Updating Powershell DLL"
cd /pentest/exploits/powershell/PowerShdll && git pull
echo "Updating Empire"
cd /pentest/exploits/powershell/Empire && git pull
echo "Updating XSStrike"
cd /pentest/web/XSStrike && git pull
#
echo "Updating Bettercap"
sudo gem update bettercap
#
if [ -f /usr/sbin/openvas-nvt-sync ] ; then
echo "Updating OpenVAS"
sudo /usr/sbin/openvas-nvt-sync --wget
else
echo "OpenVAS is not installed, skipping"
fi
if [ -f /opt/nessus/sbin/nessuscli ] ; then
echo "Updating Nessus Plugins"
sudo /opt/nessus/sbin/nessuscli update --plugins-only
else
echo "Nessus is not installed, skipping"
fi
echo "Updating VA-PT"
cd /pentest/misc/va-pt && git pull 
