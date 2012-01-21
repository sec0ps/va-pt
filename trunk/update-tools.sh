echo "Beginning package updates"
echo "Updating gisKismet"
cd /pentest/wireless/giskismet && svn up
echo "Updating SET"
cd /pentest/exploits/set && svn up
echo "Updating Metasploit"
cd /pentest/exploits/framework3 && svn up
echo "Updating Wapiti"
cd /pentest/web/wapiti && svn up
echo "Updating ZED Attack Proxy"
cd /pentest/web/zap && svn up
echo "Updating w3af"
cd /pentest/web/w3af && svn update --force
echo "Updating waffit"
cd /pentest/web/waffit && svn update
echo "Updating Sulley"
cd /pentest/fuzzers/sulley && svn up
echo "Updating Nikto"
cd /pentest/web/nikto && svn up
echo "Updating The Harvester"
cd /pentest/enumeration/theHarvester && git pull
echo "updating htshells"
cd /pentest/web/htshells && git pull
echo "Updating SSLyze"
cd /pentest/web/sslyze && svn up
#echo "Updating Dradis"
#cd /pentest/misc/dradis && svn up
echo "Updating wfuzz"
cd /pentest/fuzzers/wfuzz && svn up
#echo "Updating Beef"
#cd /var/www/beef && sudo svn update
echo "Updating Fierce2"
cd /pentest/enumeration/fierce2 && svn update
echo "Updating Kismet"
cd /pentest/wireless/kismet && svn up
echo "Updating Aircrack Tools"
cd /pentest/wireless/aircrack-ng && svn up
echo "Updating Airgraph-NG"
cd /pentest/wireless/airgraph-ng && svn up
echo "Updating fimap"
cd /pentest/web/fimap && svn up
echo "Updating SQL Map"
cd /pentest/database/sqlmap && svn up
echo "Updatign FuzzDB"
cd /pentest/fuzzers/fuzzdb && svn up
echo "Updating Monkeyfist"
cd /pentest/enumeration/monkeyfist && svn up
echo "Updating WSFuzzer"
cd /pentest/fuzzers/wsfuzzer && svn up
echo "Updating Captcha Breaker"
cd /pentest/web/captcha-breaker && svn up
echo "Updating DNSMap"
cd /pentest/enumeration/dnsmap && svn up
echo "Updating SQLNinja"
cd /pentest/database/sqlninja && svn up
echo "Updating Laudanum"
cd /pentest/web/laudanum && svn up
echo "Updating JBroFuzz"
cd /pentest/fuzzers/jbrofuzz && svn up
echo "Updating PHP Shell"
cd /pentest/web/phpshell && svn up
echo "Updating DNS Enum"
cd /pentest/enumeration/dnsenum && svn up
echo "Updating Pyrit"
cd /pentest/wireless/pyrit && svn up
echo "Updating Middler"
cd /pentest/exploits/middler && svn up
echo "Updating keimpx"
cd /pentest/exploits/keimpx && svn up
echo "Updating SIPVicious"
cd /pentest/voip/sipvicious/ && svn up
echo "Updating Wifite"
cd /pentest/wireless/wifite && svn up
echo "Updating and recompiling nmap"
cd /pentest/scanners/nmap && svn up
echo "Updating and recompiling ncat"
cd /pentest/scanners/nmap/ncat && svn up
echo "Updating and compiling ncrack"
cd /pentest/scanners/ncrack && svn up
echo "Updating VA-PT"
cd /pentest/misc/va-pt && svn up
echo "Updating the Vulnerability Database Portal"
cd /var/www/search && sudo svn up
echo "Updating HTTPrint"
cd /pentest/enumeration/httprint && mv signatures.txt signatures.txt.old
wget http://net-square.com/httprint/signatures.txt
echo "Updating OpenVAS"
sudo openvas-nvt-sync
if [ -f /opt/nessus/sbin/nessus-update-plugins ] ; then
echo "Updating Nessus Plugins"
sudo /opt/nessus/sbin/nessus-update-plugins
fi
/pentest/web/skipfish/skipfish -h | grep "version"
if [ $? != "2.03b" ] ; then
echo "skipfish is up to date"
else
echo "skipfish is not up to date, updating now."
rm -rf /pentest/web/skipfish && /pentest/misc/va-pt/scripts/static.sh
fi
/pentest/passwords/john/run/john | grep "ver:"
if [ $? != "1.7.9-jumbo-5" ] ; then
echo "john the ripper is up to date"
else
echo "john the ripper is not up to date, updating now."
rm -rf /pentest/passwords/john && /pentest/misc/va-pt/scripts/static.sh
fi
/pentest/enumeration/hydra/hydra | grep "THC"
if [ $? != "v7.1" ] ; then
echo "THC Hydra is up to date"
else
echo "THC Hydra is not up to date, updating now."
rm -rf /pentest/enumeration/hydra && /pentest/misc/va-pt/scripts/static.sh
fi
echo "Updating Local Exploit Repository"
rm -rf /pentest/exploits/exploitdb && /pentest/misc/va-pt/scripts/exploits.sh
#
while true; do
    read -p "Do you want to update the local exploit database? (y/n)" yn
    case $yn in
        [Yy]* ) /pentest/misc/va-pt/scripts/db-update.sh;  break;;
        [Nn]* ) echo "Exiting the updater."; exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
