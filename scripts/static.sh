echo "Static software package installation beginning"
if [ ! -d /pentest/scanners/snmp ] ; then
echo "Installing OneSixtyOne & snmpcheck"
mkdir /pentest/scanners/snmp
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/scanners/onesixtyone-0.3.tar.gz
tar zxvf onesixtyone-0.3.tar.gz && rm -rf onesixtyone-0.3.tar.gz
mv onesixtyone-0.3/ /pentest/scanners/snmp/onesixtyone
cd /pentest/scanners/snmp/onesixtyone && gcc -o onesixtyone onesixtyone.c
cd /pentest/scanners/snmp && wget http://www.nothink.org/perl/snmpcheck/downloads/snmpcheck-1.8.pl -O snmpcheck.pl
chmod 700 /pentest/scanners/snmp/snmpcheck.pl
fi
if [ ! -d /pentest/cisco/cge ] ; then
echo "Installing Cisco Global Exploiter"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/0405-exploits/cge-13.tar.gz
tar zxvf cge-13.tar.gz && cge-13.tar.gz
mv cge-13/ /pentest/cisco/cge && cd /pentest/cisco/cge
chmod 700 cge.pl && dos2unix cge.pl
fi
if [ ! -f /pentest/cisco/copy-router-config.pl ] ; then
cd /pentest/cisco && wget http://littlehacker.persiangig.com/cisco/copy-router-config.pl
chmod 755 copy-router-config.pl
fi
if [ ! -d /pentest/voip/sipvicious ] ; then
echo "Installing SIPVicious"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/sip/sipvicious-0.2.6.tar.gz
tar zxvf sipvicious-0.2.6.tar.gz && rm -rf sipvicious-0.2.6.tar.gz
mv sipvicious/ /pentest/voip/ && cd /pentest/voip/sipvicious
fi
if [ ! -d /pentest/enumeration/hydra ] ; then
echo "Installing THC Hydra"
cd /pentest/temp && wget http://www.thc.org/releases/hydra-7.3.tar.gz
tar zxvf hydra-7.3.tar.gz && rm -rf hydra-7.3.tar.gz
cd hydra-7.3 && ./configure && make
sudo make install
cd /pentest/temp/ && mv hydra-7.3 /pentest/enumeration/hydra
fi
if [ ! -d /pentest/web/stompy ] ; then
echo "Installing Stompy"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/web/stompy.tgz
tar zxvf stompy.tgz && rm -rf stompy.tgz
mv stompy /pentest/web/
fi
if [ ! -d /pentest/web/ratproxy ] ; then
echo "Installing Ratproxy"
cd /pentest/temp && wget http://ratproxy.googlecode.com/files/ratproxy-1.58.tar.gz
tar zxvf ratproxy-1.58.tar.gz && rm -rf ratproxy-1.58.tar.gz
mv ratproxy/ /pentest/web/ && cd /pentest/web/ratproxy
make
fi

if [ ! -d /pentest/wireless/asleap ] ; then
echo "Installing asleap"
cd /pentest/temp && wget http://prdownloads.sourceforge.net/project/asleap/asleap/asleap-1.4/asleap-1.4.tgz
tar xvf asleap-1.4.tgz && rm -rf asleap-1.4.tgz
mv asleap/ /pentest/wireless && cd /pentest/wireless/asleap
make
fi
#if [ ! -d /pentest/voip/smap ] ; then
#echo "Installing SMAP"
#cd /pentest/temp && wget http://www.protectors.cc/blog/uploads/vapt/smap.tar.gz
#tar zxvf smap.tar.gz && rm -rf smap.tar.gz
#mv smap/ /pentest/voip/smap
#cd /pentest/voip/smap && make
#fi
if [ ! -f /pentest/database/sqlbrute.py ] ; then
echo "Installing SQLBrute"
cd /pentest/database && wget http://packetstormsecurity.org/files/view/44881/sqlbrute.py.txt -O sqlbrute.py
cd /pentest/database && chmod 700 sqlbrute.py
fi
if [ ! -d /pentest/voip/ace ] ; then
cd /pentest/temp && wget http://prdownloads.sourceforge.net/ucsniff/ace/ace-1.10.tar.gz
tar xvf ace-1.10.tar.gz && rm -rf ace-1.10.tar.gz
mv ace-1.10 /pentest/voip/ace
cd /pentest/voip/ace && make
fi
#if [ ! -d /pentest/voip/ucsniff ] ; then
#cd /pentest/temp && wget http://prdownloads.sourceforge.net/ucsniff/ucsniff-3.10.tar.gz
#tar xvf ucsniff-3.10.tar.gz && rm -rf ucsniff-3.10.tar.gz
#mv ucsniff-3.10 /pentest/voip/ucsniff && cd /pentest/voip/ucsniff
#libtoolize --copy --force && ./configure
#fi
#
#videosnarf pending
#
if [ ! -d /pentest/voip/sipcrack ] ; then
cd /pentest/temp && wget http://dl.packetstormsecurity.net/Crackers/SIPcrack-0.2.tar.gz
tar zxvf SIPcrack-0.2.tar.gz && rm -rf SIPcrack-0.2.tar.gz
mv SIPcrack-0.2 /pentest/voip/sipcrack && cd /pentest/voip/sipcrack 
make
fi
if [ ! -d /pentest/voip/enumiax ] ; then
cd /pentest/temp && wget http://prdownloads.sourceforge.net/enumiax/enumiax-1.0.tar.gz
tar zxvf enumiax-1.0.tar.gz && rm -rf enumiax-1.0.tar.gz
mv enumiax-1.0 /pentest/voip/enumiax && cd /pentest/voip/enumiax
make
fi
if [ ! -d /pentest/voip/rtpbreak ] ; then
cd /pentest/temp && wget http://dl.packetstormsecurity.net/sniffers/rtpbreak-1.3a.tgz
tar zxvf rtpbreak-1.3a.tgz && rm -rf rtpbreak-1.3a.tgz
mv rtpbreak-1.3a /pentest/voip/rtpbreak 
cd /pentest/voip/rtpbreak && make
fi
if [ ! -d /pentest/voip/voipong ] ; then
cd /pentest/temp && wget http://www.enderunix.org/voipong/voipong-2.0.tar.gz
tar zxvf voipong-2.0.tar.gz && rm -rf voipong-2.0.tar.gz
mv voipong-2.0/ /pentest/voip/voipong
cd /pentest/voip/voipong
mv Makefile.linux makefile && make
sudo make install
fi
if [ ! -d /pentest/enumeration/thc-ipv6 ] ; then
echo "Installing THC IPv6"
cd /pentest/temp && wget http://www.thc.org/releases/thc-ipv6-2.0.tar.gz
tar zxvf thc-ipv6-2.0.tar.gz && rm -rf thc-ipv6-2.0.tar.gz
mv thc-ipv6-2.0 /pentest/enumeration/thc-ipv6 && cd /pentest/enumeration/thc-ipv6
make all
fi
if [ ! -d /pentest/enumeration/seat ] ; then
echo "Installing SEAT"
cd /pentest/temp && wget http://midnightresearch.com/common/seat/seat-0.3.tar.bz2
bunzip2 seat-0.3.tar.bz2 &&  tar xvf seat-0.3.tar
rm -rf seat-0.3.tar && mv seat/ /pentest/enumeration
fi
if [ ! -d /pentest/voip/voiphopper ] ; then
cd /pentest/temp && wget http://prdownloads.sourceforge.net/voiphopper/voiphopper-2.0/voiphopper-2.04.tar.gz
tar zxvf voiphopper-2.04.tar.gz && rm -rf voiphopper-2.04.tar.gz
mv voiphopper-2.04 /pentest/voip/voiphopper && cd /pentest/voip/voiphopper
cd /pentest/voip/voiphopper && make
fi
if [ ! -d /pentest/enumeration/burpsuite ] ; then
echo "Installing Burp Suite"
cd /pentest/temp && wget http://portswigger.net/burp/burpsuite_v1.4.zip
unzip burpsuite_v1.4.zip && rm -rf burpsuite_v1.4.zip
mv burpsuite_v1.4 /pentest/enumeration/burpsuite
fi
if [ ! -d /pentest/enumeration/thc-pptp-bruter ] ; then
echo "Installing THC PPTP Bruteforcer"
cd /pentest/temp && wget wget http://freeworld.thc.org/releases/thc-pptp-bruter-0.1.4.tar.gz
tar zxvf thc-pptp-bruter-0.1.4.tar.gz && mv THC-pptp-bruter-0.1.4/ /pentest/enumeration/thc-pptp-bruter
rm -rf thc-pptp-bruter-0.1.4.tar.gz && cd /pentest/enumeration/thc-pptp-bruter/src
./configure && make
fi
if [ ! -d /pentest/cisco/torch ] ; then
echo "Installing Cisco Torch"
cd /pentest/temp && wget http://www.hackingciscoexposed.com/tools/cisco-torch-0.4b.tar.gz
tar zxvf cisco-torch-0.4b.tar.gz && rm -rf cisco-torch-0.4b.tar.gz
mv cisco-torch-0.4b /pentest/cisco/torch
fi
if [ ! -d /pentest/scanners/snmp/snmpenum ] ; then
echo "Installing SNMPenum"
cd /pentest/scanners/snmp && mkdir snmpenum
cd snmpenum && wget http://dl.packetstormsecurity.net/UNIX/scanners/snmpenum.zip
unzip snmpenum.zip && rm -rf snmpenum.zip
chmod 700 snmpenum.pl
fi
if [ ! -d /pentest/enumeration/admsnmp ] ; then
echo "Installing ADMsnmp"
cd /pentest/temp && wget http://adm.freelsd.net/ADM/ADMsnmp.0.1.tgz
tar zxvf ADMsnmp.0.1.tgz && rm -rf ADMsnmp.0.1.tgz
mv ADMsnmp/ /pentest/enumeration/admsnmp  && cd /pentest/enumeration/admsnmp
gcc snmp.c -o ADMsnmp && rm -rf snmp.c ADMsnmp.README
fi
if [ ! -d /pentest/enumeration/firewalk ] ; then
echo "Installing Firewalk"
cd /pentest/temp && wget http://packetfactory.openwall.net/firewalk/dist/firewalk.tar.gz
tar zxvf firewalk.tar.gz && rm -rf firewalk.tar.gz
mv Firewalk/ /pentest/enumeration/firewalk 
#cd /pentest/temp && git clone http://git.libssh.org/projects/libssh.git libssh 
#cd libssh/built && ./build_make.sh
#make && make install
#cd /pentest/temp && wget http://prdownloads.sourceforge.net/libdnet/libdnet-1.11.tar.gz
#tar zxvf libdnet-1.11.tar.gz && rm -rf libdnet-1.11.tar.gz
#cd libdnet-1.11/ && ./configure
#make && sudo make install
#sudo ln -s /usr/lib/libdumbnet.so /usr/lib/libdnet.so && sudo ln -s /usr/include/dumbnet.h /usr/include/dnet.h
cd /pentest/enumeration/firewalk
touch src/firewalk.good && touch include/firewalk.h.1
touch include/firewalk.h.2 && touch  configure.1
touch  configure.2 && touch configure.3
touch  configure.4 && touch configure.5
sed "192i\ break;" src/firewalk.c > src/firewalk.good
rm -rf src/firewalk.c && mv src/firewalk.good src/firewalk.c
cp SOURCE SOURCE.org
sed "41d" SOURCE > SOURCE.1
sed "41 i\#include <dumbnet.h>" SOURCE.1 > SOURCE.2
rm -rf SOURCE && mv SOURCE.2 SOURCE
rm -rf SOURCE.1 && rm -rf SOURCE.ORG
sed "41d" include/firewalk.h > include/firewalk.h.1
sed "41 i\#include <dumbnet.h>" include/firewalk.h.1 > include/firewalk.h.2
rm -rf include/firewalk.h && mv include/firewalk.h.2 include/firewalk.h
rm -rf include/firewalk.h.1
sed "2370d" configure > configure.1
sed '2370 i\LIBS="-ldumbnet  $LIBS"' configure.1 > configure.2
sed "2406d" configure.2 > configure.3
sed "2406 i\ac_cv_lib_dnet_arp_get=yes" configure.3 > configure.4
sed "2418d" configure.4 > configure.5
sed '2418 i\LIBS="-ldumbnet $LIBS"' configure.5 > configure.6
rm -rf configure && mv configure.6 configure
rm -rf configure.1 && rm -rf configure.2
rm -rf configure.3 && rm -rf configure.4
rm -rf configure.5 && chmod +x configure
./configure
make && sudo make install
sudo cp man/firewalk.8 /usr/local/man/man8
fi
if [ ! -d /pentest/audit/graudit ] ; then
echo "Installing Grep Auditing Utility"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/security/graudit-1.9.tar.gz
tar zxvf graudit-1.9.tar.gz && rm graudit-1.9.tar.gz
mv graudit-1.9/ /pentest/audit/graudit
fi
if [ ! -d /pentest/audit/rats ] ; then
echo "Rough Auditing Tool for Security"
cd /pentest/temp && wget https://www.fortify.com/downloads2/public/rats-2.3.tar.gz
tar zxvf rats-2.3.tar.gz && rm -rf rats-2.3.tar.gz
mv rats-2.3 /pentest/audit/rats && cd /pentest/audit/rats
./configure && make
sudo make install
fi
if [ ! -d /pentest/audit/nipper ] ; then
echo "Installing Nipper"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/cisco/nipper-0.11.7.tgz
tar zxvf nipper-0.11.7.tgz && rm -rf nipper-0.11.7.tgz
mv nipper-0.11.7/ /pentest/audit/nipper
cd /pentest/audit/nipper && make
sudo make install
fi
if [ ! -d /pentest/audit/rat ] ; then
cd /pentest/temp && wget --no-check-certificate https://community.cisecurity.org/download/?redir=/cisco/rat-2.2-dist.sh.gz -O rat.gz
gunzip rat.gz && rm -rf rat.gz 
chmod 700 rat
./rat && mv rat-2.2P/ /pentest/audit/rat
fi
if [ ! -d /pentest/audit/rips ] ; then
echo "Downloading RIPS PHP Static Source Code Analyzer"
cd /pentest/audit && mkdir rips
cd /pentest/audit/rips && wget http://sourceforge.net/projects/rips-scanner/files/rips-0.40.zip/download -O rips.zip
fi
if [ ! -d /pentest/wireless/cowpatty ] ; then
echo "Installing CowPatty"
cd /pentest/temp && wget http://www.wirelessdefence.org/Contents/Files/cowpatty-4.6.tgz
tar zxvf cowpatty-4.6.tgz && rm -rf cowpatty-4.6.tgz
mv cowpatty-4.6/ /pentest/wireless/cowpatty && cd /pentest/wireless/cowpatty
make clean && make all
sudo make install
fi
if [ ! -d /pentest/enumeration/dirbuster ] ; then
cd /pentest/temp && wget http://prdownloads.sourceforge.net/dirbuster/DirBuster-0.12.tar.bz2
bunzip2 DirBuster-0.12.tar.bz2 && tar xvf DirBuster-0.12.tar
rm -rf DirBuster-0.12.tar && mv DirBuster-0.12 /pentest/enumeration/dirbuster
cd /pentest/enumeration/dirbuster
echo "java -jar DirBuster-0.12.jar" >> start-dirbuster.sh && chmod 700 start-dirbuster.sh
fi
if [ ! -d /pentest/web/webscarab ] ; then
mkdir /pentest/web/webscarab && cd /pentest/web/webscarab
wget http://webscarab-ng.googlecode.com/files/WebScarab-ng-0.2.1.one-jar.zip && unzip WebScarab-ng-0.2.1.one-jar.zip
rm -rf WebScarab-ng-0.2.1.one-jar.zip && chmod 700 start.sh
dos2unix start.sh
fi
 if [ ! -f /pentest/database/mysqlaudit.py ] ; then
echo "Installing MySQLAudit"
cd /pentest/database && wget http://www.darkoperator.com/tools-and-scripts/mysqlaudit.py
fi
if [ ! -d /pentest/passwords/john ] ; then
echo "Installing John the Ripper"
cd /pentest/temp && wget http://www.openwall.com/john/g/john-1.7.9.tar.gz
tar zxvf john-1.7.9.tar.gz && rm -rf john-1.7.9.tar.gz
mv john-1.7.9 /pentest/passwords/john && cd /pentest/passwords/john/src
make generic
fi
if [ ! -d /pentest/passwords/cewl ] ; then
echo "Installing Cewl"
cd /pentest/temp && wget http://www.digininja.org/files/cewl_4.1.tar.bz2
bunzip2 cewl_4.1.tar.bz2 && tar xvf cewl_4.1.tar
mv cewl/ /pentest/passwords/ && rm -rf cewl_4.1.tar
fi
if [ ! -d /pentest/enumeration/bile ] ; then
echo "Installing Bile"
mkdir /pentest/enumeration/bile && cd /pentest/enumeration/bile
wget http://www.sensepost.com/cms/resources/labs/tools/misc/BiLE-suite.tgz && tar zxvf BiLE-suite.tgz
rm -rf BiLE-suite.tgz && wget http://www.sensepost.com/cms/resources/labs/tools/misc/go.pl -O proxyscan.pl
chmod 700 proxyscan.pl
fi
if [ ! -d /pentest/enumeration/httprint ] ; then
echo "Installing HTTPrint"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/scanners/httprint_linux_301.zip 
unzip httprint_linux_301.zip && rm -rf httprint_linux_301.zip
mv httprint_301/linux /pentest/enumeration/httprint
cd /pentest/temp && rm -rf httprint_301/
fi
if [ ! -d /pentest/web/xsser ] ; then
echo "Installing XSSer"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/scanners/xsser_1.5-1.tar.gz
tar zxvf xsser_1.5-1.tar.gz && rm -rf xsser_1.5-1.tar.gz
mv xsser-public/ /pentest/web/xsser && cd /pentest/web/xsser
sudo /pentest/exploits/set/set
fi
if [ ! -d /pentest/web/skipfish ] ; then
echo "Installing skipfish"
cd /pentest/web/ && wget http://skipfish.googlecode.com/files/skipfish-2.09b.tgz
tar zxvf skipfish-2.09b.tgz && rm -rf skipfish-2.09b.tgz
mv skipfish-2.09b skipfish
cd skipfish && make
cp /pentest/web/skipfish/dictionaries/complete.wl /pentest/web/skipfish/dictionaries/skipfish.wl
fi
if [ ! -d /pentest/misc/flare ] ; then
echo "Installing Flare"
cd /pentest/misc && mkdir flare
cd /pentest/misc/flare && wget http://www.nowrap.de/download/flare06linux.tgz
tar xvf flare06linux.tgz && rm -rf flare06linux.tgz
fi
if [ ! -d /pentest/passwords/hashcat ] ; then
echo "Installing Hashcat"
cd /pentest/temp && wget http://hashcat.net/files/oclHashcat-plus-0.09.7z
7za x oclHashcat-plus-0.09.7z && rm -rf oclHashcat-plus-0.09.7z
mv oclHashcat-plus-0.09 /pentest/passwords/hashcat
fi
if [ ! -d /pentest/exploits/windows-tools ] ; then
echo "Installing Windows Tools"
cd /pentest/exploits && mkdir windows-tools
cd windows-tools && wget http://download.sysinternals.com/files/PSTools.zip
unzip PSTools.zip && rm -rf PSTools.zip
wget http://dl.packetstormsecurity.net/groups/checksum/nc.exe
cd /pentest/temp && wget http://swamp.foofus.net/fizzgig/fgdump/fgdump-2.1.0-exeonly.tar.bz2
bunzip2 fgdump-2.1.0-exeonly.tar.bz2 && rm -rf fgdump-2.1.0-exeonly.tar.bz2
tar xvf fgdump-2.1.0-exeonly.tar && rm -rf fgdump-2.1.0-exeonly.tar
mv Release/fgdump.exe /pentest/exploits/windows-tools/ && rm -rf Release/
fi
if [ ! -d /pentest/enumeration/ike ] ; then
echo "Installing VPN Tools"
cd /pentest/temp && wget http://www.ernw.de/download/ikeprobe.zip --no-check-certificate
unzip ikeprobe.zip && rm -rf ikeprobe.zip
mkdir /pentest/enumeration/ike
mv ikeprobe.exe /pentest/enumeration/ike/ && mv libeay32.dll /pentest/enumeration/ike/
cd /pentest/enumeration/ike && wget http://prdownloads.sourceforge.net/project/ikecrack/ikecrack-perl/1.00/ikecrack-snarf-1.00.pl
fi
if [ ! -d /pentest/enumeration/gggooglescan ] ; then
echo "Installing gggooglescan"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/UNIX/scanners/gggooglescan-0.4.tar.gz
tar zxvf gggooglescan-0.4.tar.gz && rm -rf gggooglescan-0.4.tar.gz
mv gggooglescan-0.4 /pentest/enumeration/gggooglescan
fi
if [ ! -d /pentest/enumeration/rdp-sec-check ] ; then
echo "Installing RDP Security Checker"
cd /pentest/temp && wget http://labs.portcullis.co.uk/download/rdp-sec-check-0.8.tar.gz
tar xvf rdp-sec-check-0.8.tar.gz && rm -rf rdp-sec-check-0.8.tar.gz
mv rdp-sec-check-0.8 /pentest/enumeration/rdp-sec-check
fi
if [ ! -d /pentest/misc/dradis ] ; then
echo "Installing Dradis"
cd /pentest/temp && wget http://downloads.sourceforge.net/dradis/dradis-v2.9.0.tar.bz2
bunzip2 dradis-v2.9.0.tar.bz2 && tar xvf dradis-v2.9.0.tar
rm -rf dradis-v2.9.0.tar && mv dradis-2.9/ /pentest/misc/dradis
cd /pentest/misc/dradis/server && bundle install
cd /pentest/misc/dradis && ./reset.sh
fi
if [ ! -d /pentest/wireless/hwk ] ; then
echo "Installing HWK Wireless Auditing Tool"
cd /pentest/temp && wget http://prdownloads.sourceforge.net/project/hwk/hwk_0.3.2.tar.gz
tar xvf hwk_0.3.2.tar.gz && mv hwk_0.3.2 /pentest/wireless/hwk
cd /pentest/wireless/hwk && make
fi
if [ ! -f /pentest/cisco/cisc0wn.sh ] ; then
echo "Installing Cisco 0wn"
cd /pentest/cisco && wget http://www.commonexploits.com/tools/cisc0wn/cisc0wn.sh
chmod 755 cisc0wn.sh
fi
if [ ! -d /pentest/exploits/smbexec ] ; then
echo "Installing smbexec"
cd /pentest/temp && wget http://prdownloads.sourceforge.net/project/smbexec/smbexec-1.1.0.tar.gz
tar xvf smbexec-1.1.0.tar.gz && rm -rf smbexec-1.1.0.tar.gz
mv smbexec/ /pentest/exploits
fi
if [ ! -d /pentest/web/mantra ] ; then
echo "Installing OWASP Mantra"
cd /pentest/temp && wget http://getmantra.googlecode.com/files/Mantra%20Lexicon%20Lin32%20EN.tar.bz2 -O MantraLexicon.tar.bz2
bunzip2 MantraLexicon.tar.bz2 && tar xvf MantraLexicon.tar
rm -rf MantraLexicon.tar && mv OWASP\ Mantra\ -\ Lexicon\ -en\ 32\ bit\ Linux/ /pentest/web/mantra
fi
if [ ! -f /pentest/enumeration/mdns.py ] ; then
echo "Installing mDNS Scanner"
cd /pentest/enumeration && wget http://www.gnucitizen.org/static/blog/2008/01/mdns.py
cd /pentest/temp && wget http://pybonjour.googlecode.com/files/pybonjour-1.1.1.tar.gz
tar xvf pybonjour-1.1.1.tar.gz && rm -rf pybonjour-1.1.1.tar.gz
cd pybonjour-1.1.1/ && sudo python setup.py install
cd /pentest/temp && sudo rm -rf pybonjour-1.1.1
fi
if [ ! -d /pentest/enumeration/win-enum ] ; then
echo "Installing Windows Enum Tools"
cd /pentest/temp && wget http://labs.portcullis.co.uk/download/enum4linux-0.8.8.tar.gz
tar xvf enum4linux-0.8.8.tar.gz && rm -rf enum4linux-0.8.8.tar.gz
mv enum4linux-0.8.8 /pentest/enumeration/win-enum
cd /pentest/temp && wget http://labs.portcullis.co.uk/download/polenum-0.2.tar.bz2
bunzip2 polenum-0.2.tar.bz2 && tar xvf polenum-0.2.tar
rm -rf polenum-0.2.tar && sudo mv polenum-0.2/polenum.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/polenum.py && rm -rf rm -rf polenum-0.2/
fi
if [ ! -f /pentest/database/bsqlbf-v2.pl ] ; then
echo "Installing Blind SQL Brute Forcer"
cd /pentest/temp && wget http://labs.portcullis.co.uk/download/bsqlbfv2.zip
unzip bsqlbfv2.zip && rm -rf bsqlbfv2.zip
mv bsqlbf-v2/bsqlbf-v2.pl /pentest/database/ && rm -rf bsqlbf-v2/
fi
if [ ! -d /pentest/enumeration/apache_userdir ] ; then
echo "Installing Apache UserDir Enumerator"
cd /pentest/temp && wget http://labs.portcullis.co.uk/download/apache_users-2.1.tar.gz
tar xvf apache_users-2.1.tar.gz && rm -rf apache_users-2.1.tar.gz
mv apache_users /pentest/enumeration/apache_userdir
fi
if [ ! -d /opt/xplico ] ; then
echo "Installing Xplico"
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" >> /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
sudo service apache2 restart
echo "Xplico by default is now running on 9876 - http://localhost:9876"
fi
#if [ ! -d /pentest/enumeration/netglub ] ; then
#cd /pentest/enumeration && wget http://redmine.lab.diateam.net/attachments/download/1/netglub-1.0.tar.gz
#tar -xzvf netglub-1.0.tar.gz && rm -rf netglub-1.0.tar.gz
#mv netglub-1.0 netglub
#cd /pentest/enumeration/netglub/qng/
#qmake && make
#echo "Enter the root mysql password to create the netglub user and databases"
#mysqladmin create netglub -u root -p
#mysql -u root -p -e "grant all privileges on netglub.* to 'netglub'@'localhost' identified by 'netglub'"
#mysql -u root -p netglub < /pentest/enumeration/netglub/master/tools/sql/netglub.sql  
#cd /pentest/enumeration/netglub/master
#qmake && make
#cd tools/ && sudo ./install.sh
#cd /pentest/enumeration/netglub/slave
#qmake && make
#cd tools/ && sudo ./install.sh
#echo "When starting netglub for the first time use the code 2222-4567-89ab-cdef"
#fi
echo "Static Code installation complete"
