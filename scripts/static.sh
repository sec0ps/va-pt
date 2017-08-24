echo "Static software package installation beginning"
#
if [ ! -d /pentest/web/zap ] ; then
echo "Installing ZED Attack Proxy"
cd /pentest/temp && wget https://github.com/zaproxy/zaproxy/releases/download/2.6.0/ZAP_2.6.0_Linux.tar.gz
tar xvf ZAP_2.6.0_Linux.tar.gz && rm -rf ZAP_2.6.0_Linux.tar.gz
mv ZAP_2.6.0/ /pentest/web/zap
fi
if [ ! -d /pentest/scanners/snmp ] ; then
echo "Installing OneSixtyOne & snmpcheck"
mkdir /pentest/scanners/snmp
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/scanners/onesixtyone-0.3.tar.gz --no-check-certificate
tar zxvf onesixtyone-0.3.tar.gz && rm -rf onesixtyone-0.3.tar.gz
mv onesixtyone-0.3//snmp/onesixtyone && gcc -o onesixtyone onesixtyone.c
cd /pentest/scanners/snmp && wgset http://www.nothink.org/perl/snmpcheck/downloads/snmpcheck-1.8.pl -O snmpcheck.pl
chmod 700 /pentest/scanners/snmp/snmpcheck.pl
fi
if [ ! -f /pentest/cisco/copy-router-config.pl ] ; then
cd /pentest/cisco && wget http://littlehacker.persiangig.com/cisco/copy-router-config.pl
chmod 755 copy-router-config.pl
fi
if [ ! -d /pentest/wireless/hostapd-2.2 ] ; then
echo "Installing Hostapd-WPE"
cd /pentest/wireless/ && git clone https://github.com/OpenSecurityResearch/hostapd-wpe
wget http://hostap.epitest.fi/releases/hostapd-2.2.tar.gz
tar -zxf hostapd-2.2.tar.gz && rm -rf hostapd-2.2.tar.gz
cd hostapd-2.2 && patch -p1 < ../hostapd-wpe/hostapd-wpe.patch 
cd hostapd && make
cd ../../hostapd-wpe/certs && ./bootstrap
fi
if [ ! -f /pentest/database/sqlbrute.py ] ; then
echo "Installing SQLBrute"
cd /pentest/database && wget http://packetstorm.foofus.com/UNIX/scanners/sqlbrute.py.txt -O sqlbrute.py
cd /pentest/database && chmod 700 sqlbrute.py
fi
if [ ! -d /pentest/database/tnspoison ] ; then
echo "Installing TNS Poison"
cd /pentest/database && mkdir tnspoison
cd tnspoison/ && wget http://www.joxeankoret.com/download/tnspoison.zip
unzip tnspoison.zip && rm -rf tnspoison.zip
fi
if [ ! -d /pentest/enumeration/thc-ipv6 ] ; then
echo "Installing THC IPv6"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/groups/thc/thc-ipv6-2.7.tar.gz --no-check-certificate
tar zxvf thc-ipv6-2.7.tar.gz && rm -rf thc-ipv6-2.7.tar.gz
mv thc-ipv6-2.7 /pentest/enumeration/thc-ipv6 && cd /pentest/enumeration/thc-ipv6
make all && sudo make install
fi
if [ ! -d /pentest/enumeration/thc-pptp-bruter ] ; then
echo "Installing THC PPTP Bruteforcer"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/groups/thc/thc-pptp-bruter-0.1.4.tar.gz --no-check-certificate
tar xvf thc-pptp-bruter-0.1.4.tar.gz && mv THC-pptp-bruter-0.1.4/ /pentest/enumeration/thc-pptp-bruter
rm -rf thc-pptp-bruter-0.1.4.tar.gz && cd /pentest/enumeration/thc-pptp-bruter/
./configure && make
fi
if [ ! -d /pentest/scanners/snmp/snmpenum ] ; then
echo "Installing SNMPenum"
cd /pentest/scanners/snmp && mkdir snmpenum
cd snmpenum && wget http://dl.packetstormsecurity.net/UNIX/scanners/snmpenum.zip --no-check-certificate
unzip snmpenum.zip && rm -rf snmpenum.zip
chmod 700 snmpenum.pl
fi
if [ ! -d /pentest/audit/nipper ] ; then
echo "Installing Nipper"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/cisco/nipper-0.11.7.tgz --no-check-certificate
tar zxvf nipper-0.11.7.tgz && rm -rf nipper-0.11.7.tgz
mv nipper-0.11.7/ /pentest/audit/nipper
cd /pentest/audit/nipper && make
sudo make install
fi
if [ ! -d /pentest/enumeration/dirbuster ] ; then
cd /pentest/temp && wget http://downloads.sourceforge.net/project/dirbuster/DirBuster%20%28jar%20%2B%20lists%29/0.12/DirBuster-0.12.tar.bz2
bunzip2 DirBuster-0.12.tar.bz2 && tar xvf DirBuster-0.12.tar
rm -rf DirBuster-0.12.tar && mv DirBuster-0.12 /pentest/enumeration/dirbuster
cd /pentest/enumeration/dirbuster
echo "java -jar DirBuster-0.12.jar" >> start-dirbuster.sh && chmod 700 start-dirbuster.sh
fi
if [ ! -d /pentest/exploits/windows-tools ] ; then
echo "Installing Windows Tools"
cd /pentest/exploits && mkdir windows-tools
cd windows-tools && wget http://download.sysinternals.com/files/PSTools.zip
unzip PSTools.zip && rm -rf PSTools.zip
wget http://dl.packetstormsecurity.net/groups/checksum/nc.exe --no-check-certificate
cd /pentest/temp && wget http://www.foofus.net/fizzgig/fgdump/fgdump-2.1.0-exeonly.tar.bz2
bunzip2 fgdump-2.1.0-exeonly.tar.bz2 && rm -rf fgdump-2.1.0-exeonly.tar.bz2
tar xvf fgdump-2.1.0-exeonly.tar && rm -rf fgdump-2.1.0-exeonly.tar
mv Release/fgdump.exe /pentest/exploits/windows-tools/ && rm -rf Release/
wget http://www.tarasco.org/security/dnsfun/dnsfun.zip && unzip dnsfun.zip
rm dnsfun.zip && mv dnsfun.* /pentest/exploits/windows-tools/
fi
if [ ! -f /pentest/enumeration/ike/ikeprobe.exe ] ; then
echo "Installing VPN Tools"
cd /pentest/temp && wget http://www.ernw.de/download/ikeprobe.zip --no-check-certificate
unzip ikeprobe.zip && rm -rf ikeprobe.zip
mkdir /pentest/enumeration/ike
mv ikeprobe.exe /pentest/enumeration/ike/ && mv libeay32.dll /pentest/enumeration/ike/
cd /pentest/enumeration/ike && wget http://prdownloads.sourceforge.net/project/ikecrack/ikecrack-perl/1.00/ikecrack-snarf-1.00.pl
fi
if [ ! -d /pentest/web/mantra ] ; then
echo "Installing OWASP Mantra"
cd /pentest/temp && wget https://downloads.sourceforge.net/project/getmantra/Mantra%20Security%20Toolkit/Janus%20-%200.92%20Beta/OWASP%20Mantra%20Janus%20Linux%2064.tar.gz?r=&ts=1502414226&use_mirror=superb-sea2 -O MantraLexicon.tar.gz
mv OWASP\ Mantra\ Janus\ Linux\ 64.tar.gz\?r\= OWASP-Mantra.tar.gz && tar zxvf OWASP-Mantra.tar.gz
rm -rf OWASP-Mantra.tar.gz && ./OWASP\ Mantra-0.92-Linux-x86_64-Install
fi
if [ ! -f /pentest/exploits/windows-tools/wce.exe ] ; then
echo "Installing Windows Credential Editor"
cd /pentest/exploits/windows-tools && wget http://www.ampliasecurity.com/research/wce_v1_42beta_x64.zip
unzip wce_v1_42beta_x64.zip && rm -rf wce_v1_42beta_x64.zip Changelog LICENSE.txt
fi
if [ ! -d /pentest/web/aspshell ] ; then
echo "Installing ASPshell"
cd /pentest/web && mkdir aspshell
cd aspshell && wget http://downloads.sourceforge.net/project/aspshell/aspshell/aspshell%200.2/aspshell-0.2.zip
unzip aspshell-0.2.zip && rm -rf aspshell-0.2.zip
fi
if [ ! -d /pentest/web/wsb ] ; then
echo "Installing WebShell Backdoor"
cd /pentest/web && wget http://dl.packetstormsecurity.net/UNIX/penetration/rootkits/wsb.tar.gz --no-check-certificate
tar xvf wsb.tar.gz && rm -rf wsb.tar.gz
fi
if [ ! -d /pentest/web/svn-extractor ] ; then
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/scanners/svn-extractor-master.zip --no-check-certificate
unzip svn-extractor-master.zip && mv svn-extractor-master/ /pentest/web/svn-extractor
rm -rf svn-extractor-master*
fi
if [ ! -d /pentest/exploits/armitage ] ; then
echo "Installing Armitage"
cd /pentest/temp && wget http://www.fastandeasyhacking.com/download/armitage150813.tgz
tar xvf armitage150813.tgz  && mv armitage/ /pentest/exploits
echo "Be sure to edit the database.yml file in /opt/metasploit/apps/pro/ui/config/"
fi
if [ ! -f /pentest/passwords/weakpass] ; then
echo "Downloading the weakpass archive"
cd /pentest/passwords && wget http://www.mediafire.com/file/x5ci9iv66x54e6v/weakpass_2.7z
7z e weakpass_2.7z
fi
echo "Static Code installation complete"
