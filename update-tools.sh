#Update deps or install new deps where applicable
sudo apt update && sudo apt upgrade -y

echo "Updating Exploit Tools"
cd /vapt/exploits/social-engineer-toolkit && git pull
cd /vapt/exploits/metasploit-framework && git pull
cd /vapt/exploits/ADFSpray && git pull
cd /vapt/exploits/beef && git pull
cd /vapt/exploits/DeathStar && git pull
cd /vapt/exploits/impacket && git pull
cd /vapt/exploits/mimikatz && git pull
cd /vapt/exploits/Responder && git pull

echo "Updating Audit Tools"
cd /vapt/audit/PlumHound && git pull
cd /vapt/audit/PowerZure && git pull

echo "Updating Fuzzer Tools"
cd /vapt/fuzzers/boofuzz && git pull

echo "Updating Intel Tools"
cd /vapt/intel/indicator-intelligence && git pull
cd /vapt/intel/LinkedInDumper && git pull
cd /vapt/intel/EyeWitness && git pull
cd /vapt/intel/recon-ng && git pull
cd /vapt/intel/scrying && git pull
cd /vapt/intel/spiderfoot && git pull
cd /vapt/intel/theHarvester && git pull
cd /vapt/intel/GRecon && git pull
cd /vapt/intel/sherlock && git pull
pip3 install metafinder --upgrade

echo "Updating Password Tools"
cd /vapt/passwords/CeWL && git pull
cd /vapt/passwords/hashcat && git pull
cd /vapt/passwords/JohnTheRipper && git pull
cd /vapt/passwords/SecLists && git pull

echo "Updating Powershell Tools"
cd /vapt/powershell/Invoke-TheHash && git pull
cd /vapt/powershell/PowerShdll && git pull
cd /vapt/powershell/PowerSploit && git pull
cd /vapt/powershell/ps1encode && git pull

echo "Updating Web Tools"
cd /vapt/web/htshells && git pull
cd /vapt/web/joomscan && git pull
cd /vapt/web/nikto && git pull
cd /vapt/web/php-webshells && git pull
cd /vapt/web/watobo && git pull
cd /vapt/web/WhatWeb && git pull
cd /vapt/web/XSStrike && git pull
cd /vapt/web/XSS-LOADER && git pull
cd /vapt/web/wapiti && git pull

echo "Updating Scanner Tools"
cd /vapt/scanners/dnsrecon && git pull
cd /vapt/scanners/FindUncommonShares && git pull
cd /vapt/scanners/cisco-SNMP-enumeration && git pull
cd /vapt/scanners/dnsenum && git pull
cd /vapt/scanners/dnsmap && git pull
cd /vapt/scanners/fierce && git pull
cd /vapt/scanners/hydra && git pull
cd /vapt/scanners/sqlmap && git pull
cd /vapt/scanners/nmap && git pull
make clean && ./configure
make && sudo make install
sudo nmap --script-updatedb
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
cd /vapt/misc/va-pt && git pull
echo "Update Complete"
