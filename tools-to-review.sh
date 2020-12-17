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

if [ ! -d /vapt/scanners/enum4linux ] ; then
echo "Installing Windows Enum Tools"
cd /vapt/scanners/ && git clone https://github.com/portcullislabs/enum4linux.git
cd /vapt/temp && wget http://labs.portcullis.co.uk/download/polenum-0.2.tar.bz2 --no-check-certificate
bunzip2 polenum-0.2.tar.bz2 && tar xvf polenum-0.2.tar
rm -rf polenum-0.2.tar && sudo mv polenum-0.2/polenum.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/polenum.py && rm -rf rm -rf polenum-0.2/
fi

if [ ! -d /vapt/wireless/asleap ] ; then
echo "Installing asleap"
cd /vapt/wireless/ && git clone https://github.com/joswr1ght/asleap.git
cd asleap && make
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

echo "Installing local tools"
cp /vapt/misc/va-pt/tools/copy-router-config.pl /vapt/cisco/
cp /vapt/misc/va-pt/tools/merge-router-config.pl /vapt/cisco/
cp /vapt/misc/va-pt/tools/dnsrecon.rb /vapt/scanners/
cp /vapt/misc/va-pt/tools/mysqlaudit.py /vapt/database/
# end installer

