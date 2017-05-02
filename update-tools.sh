echo "Beginning package updates"
echo "Updating SET"
cd /pentest/exploits/set && git pull
echo "Updating Metasploit"
cd /pentest/exploits/framework3 && git pull
sudo bundle install && sudo chown -R $USER.$USER *
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
echo "Updating Fierce2"
cd /pentest/enumeration/fierce2 && svn up
echo "Updating Kismet"
cd /pentest/wireless/kismet && git pull
echo "Updating Aircrack Tools"
cd /pentest/wireless/aircrack-ng && git pull
echo "Updating fimap"
cd /pentest/web/fimap && git pull 
echo "Updating SQL Map"
cd /pentest/database/sqlmap && git pull
echo "Updatign FuzzDB"
cd /pentest/fuzzers/fuzzdb && git pull
echo "Updating DNS Enum"
cd /pentest/enumeration/dnsenum && git pull 
echo "Updating Pyrit"
cd /pentest/passwords/Pyrit && git pull
#echo "Updating SIPVicious"
#cd /pentest/voip/sipvicious/ && svn up
echo "Updating Router Defense"
cd /pentest/audit/routerdefense/ && git pull
echo "Updating Wifite"
cd /pentest/wireless/wifite && git pull
echo "Updating nmap, ncrack and ncat"
cd /pentest/scanners/nmap && svn up
make clean && ./configure
make && sudo make install
sudo nmap --script-updatedb
echo "Updating WhatWeb"
cd /pentest/web/WhatWeb && git pull
echo "Updating Responder"
cd /pentest/exploits/Responder && git pull
echo "Updating SSL Split"
cd /pentest/web/sslsplit && git pull
echo "Updating netsniff-ng"
cd /pentest/enumeration/netsniff-ng && git pull
echo "Updating Jboss Autopwn"
cd /pentest/web/jboss-autopwn && git pull
echo "Updating Weape"
cd /pentest/wireless/weape && git pull
echo "Updating smbexec"
cd /pentest/exploits/smbexec && git pull
bundle install
#echo "Updating John the Ripper"
#cd /pentest/passwords/john && git pull
echo "Updating THC-Hydra"
cd /pentest/enumeration/hydra && git pull
echo "Updating wifijammer"
cd /pentest/wireless/wifijammer && git pull
#echo "Updating Veil Catapult"
#cd /pentest/exploits/Veil-Catapult && git pull
#echo "Updating Veil Evasion"
#cd /pentest/exploits/Veil-Evasion && git pull
#echo "Updating Veil PowerView"
#cd /pentest/exploits/Veil-PowerView && git pull
echo "Updating PCredz"
cd /pentest/passwords/PCredz && git pull
echo "Updating Recon-NG"
cd /pentest/enumeration/recon-ng/ && git pull
echo "Updating the ExploitDB archive"
cd /pentest/exploits/exploit-database && git pull
echo "Updating Passive Aggresive"
cd /pentest/enumeration/pasv-agrsv && git pull
echo "Updating Medusa"
cd /pentest/enumeration/medusa && git pull
echo "Updating Pentestly"
cd /pentest/exploits/pentestly && git pull
echo "Updating Rawr"
cd /pentest/web/rawr && git pull
echo "Updating CrackMapExec"
cd /pentest/exploits/CrackMapExec && git pull
echo "Updating XSSer"
cd /pentest/web/xsser && git pull
echo "Updating NoSQLMAP"
cd /pentest/database/NoSQLMap && git pull
echo "Updating Cloakify"
cd /pentest/exploits/cloakify && git pull
echo "Updating Bettercap"
sudo gem update bettercap
echo "Updating CrackMapExec"
cd /pentest/exploits/CrackMapExec && git pull
echo Updating keimpx
cd /pentest/exploits/keimpx && git pull
echo "Updating Cheatsheet Collection"
cd /pentest/misc/Cheatsheets && git pull
echo "Updating BruteXSS"
cd /pentest/web/brutexss && git pull
echo "Updating Droopescan"
cd /pentest/web/droopescan && git pull
echo "Updating sublist3r"
cd /pentest/enumeration/sublist3r && git pull
echo "Updating weevely"
cd /pentest/web/weevely && git pull
echo "Updating spraywmi"
cd /pentest/exploits/spraywmi && git pull
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
