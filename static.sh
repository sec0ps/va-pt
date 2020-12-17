echo "Static software package installation beginning"

#Completed
if [ ! -f /vapt/scanners/snmpcheck-1.8.pl ] ; then
echo "Installing snmpcheck"
cd /vapt/scanners && wget http://www.nothink.org/perl/snmpcheck/downloads/snmpcheck-1.8.pl -O snmpcheck.pl
chmod 700 /vapt/scanners/snmpcheck.pl
fi

#Pending Review
if [ ! -d /vapt/web/zap ] ; then
echo "Installing ZED Attack Proxy"
cd /vapt/temp && wget https://github.com/zaproxy/zaproxy/releases/download/v2.8.0/ZAP_2.8.0_Linux.tar.gz 
tar xvf ZAP_2.8.0_Linux.tar.gz && rm -rf ZAP_2.8.0_Linux.tar.gz
mv ZAP_2.8.0/ /vapt/web/zap
fi

if [ ! -f /vapt/cisco/copy-router-config.pl ] ; then
cd /vapt/cisco && wget http://littlehacker.persiangig.com/cisco/copy-router-config.pl
chmod 755 copy-router-config.pl
fi
#if [ ! -d /vapt/wireless/hostapd-wpe ] ; then
#echo "Installing Hostapd-WPE"
#cd /vapt/wireless/ && mkdir hostapd-wpe
#cd hostapd-wpe && git clone https://github.com/OpenSecurityResearch/hostapd-wpe
#wget https://w1.fi/releases/hostapd-2.6.tar.gz
#tar -zxf hostapd-2.6.tar.gz && rm -rf hostapd-2.6.tar.gz
#cd hostapd-2.6 && patch -p1 < ../hostapd-wpe/hostapd-wpe.patch 
#cd hostapd && make
#cd ../../hostapd-wpe/certs && ./bootstrap
#fi
if [ ! -f /vapt/database/sqlbrute.py ] ; then
echo "Installing SQLBrute"
cd /vapt/database && wget http://packetstorm.foofus.com/UNIX/scanners/sqlbrute.py.txt -O sqlbrute.py
cd /vapt/database && chmod 700 sqlbrute.py
fi

if [ ! -d /vapt/scanners/snmp/snmpenum ] ; then
echo "Installing SNMPenum"
cd /vapt/scanners/snmp && mkdir snmpenum
cd snmpenum && wget http://dl.packetstormsecurity.net/UNIX/scanners/snmpenum.zip --no-check-certificate
unzip snmpenum.zip && rm -rf snmpenum.zip
chmod 700 snmpenum.pl
fi

if [ ! -d /vapt/exploits/windows-tools ] ; then
echo "Installing Windows Tools"
cd /vapt/exploits && mkdir windows-tools
cd windows-tools && wget http://download.sysinternals.com/files/PSTools.zip
unzip PSTools.zip && rm -rf PSTools.zip
wget http://dl.packetstormsecurity.net/groups/checksum/nc.exe --no-check-certificate
cd /vapt/temp && wget http://www.foofus.net/fizzgig/fgdump/fgdump-2.1.0-exeonly.tar.bz2
bunzip2 fgdump-2.1.0-exeonly.tar.bz2 && rm -rf fgdump-2.1.0-exeonly.tar.bz2
tar xvf fgdump-2.1.0-exeonly.tar && rm -rf fgdump-2.1.0-exeonly.tar
mv Release/fgdump.exe /vapt/exploits/windows-tools/ && rm -rf Release/
wget http://www.tarasco.org/security/dnsfun/dnsfun.zip && unzip dnsfun.zip
rm dnsfun.zip && mv dnsfun.* /vapt/exploits/windows-tools/
fi
if [ ! -f /vapt/enumeration/ike/ikeprobe.exe ] ; then
echo "Installing VPN Tools"
cd /vapt/temp && wget http://www.ernw.de/download/ikeprobe.zip --no-check-certificate
unzip ikeprobe.zip && rm -rf ikeprobe.zip
mkdir /vapt/enumeration/ike
mv ikeprobe.exe /vapt/enumeration/ike/ && mv libeay32.dll /vapt/enumeration/ike/
cd /vapt/enumeration/ike && wget http://prdownloads.sourceforge.net/project/ikecrack/ikecrack-perl/1.00/ikecrack-snarf-1.00.pl
fi
if [ ! -d /vapt/web/aspshell ] ; then
echo "Installing ASPshell"
cd /vapt/web && mkdir aspshell
cd aspshell && wget http://downloads.sourceforge.net/project/aspshell/aspshell/aspshell%200.2/aspshell-0.2.zip
unzip aspshell-0.2.zip && rm -rf aspshell-0.2.zip
fi
if [ ! -d /vapt/web/wsb ] ; then
echo "Installing WebShell Backdoor"
cd /vapt/web && wget http://dl.packetstormsecurity.net/UNIX/penetration/rootkits/wsb.tar.gz --no-check-certificate
tar xvf wsb.tar.gz && rm -rf wsb.tar.gz
fi
if [ ! -d /vapt/exploits/armitage ] ; then
echo "Installing Armitage"
cd /vapt/temp && wget http://www.fastandeasyhacking.com/download/armitage150813.tgz
tar xvf armitage150813.tgz  && mv armitage/ /vapt/exploits
echo "Be sure to edit the database.yml file in /opt/metasploit/apps/pro/ui/config/"
fi
echo "Static Code installation complete"
