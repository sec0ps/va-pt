if [ ! -d /pentest/scanners/snmp ] ; then
echo "Installing OneSixtyOne & snmpcheck"
mkdir /pentest/scanners/snmp
cd /pentest/temp && wget http://freshmeat.net/urls/2a758cc469ce124b21de08a87ae1dd48 -O onesixtyone.tar.gz
tar zxvf onesixtyone.tar.gz && rm -rf onesixtyone.tar.gz
mv onesixtyone-0.3.2/ /pentest/scanners/snmp/onesixtyone
cd /pentest/scanners/snmp/onesixtyone && make
cd /pentest/scanners/snmp && wget http://dl.packetstormsecurity.net/UNIX/scanners/snmpcheck-1.6.txt -O snmpcheck.pl
chmod 700 /pentest/scanners/snmp/snmpcheck.pl
fi
if [ ! -d /pentest/cisco/cge ] ; then
echo "Installing Cisco Global Exploiter"
cd /pentest/temp && wget http://dl.packetstormsecurity.net/0405-exploits/cge-13.tar.gz
tar zxvf cge-13.tar.gz && mv cge-13/ /pentest/cisco/cge
cd /pentest/cisco/cge && chmod 700 cge.pl
rm -rf /pentest/temp/cge-13.tar.gz && dos2unix cge.pl
fi
if [ ! -d /pentest/misc/freacs ] ; then
echo "Installing Fuzzy Risk Calculator Evaluation And Calculation System"
cd /pentest/temp && wget http://www.ictsc.it/site/IT/projects/freacs/freacs.tar.gz
tar zxvf freacs.tar.gz && rm -rf freacs.tar.gz
mv freacs/ /pentest/misc/
fi
if [ ! -d /pentest/enumeration/hydra ] ; then
echo "Installing THC Hydra"
cd /pentest/temp && wget http://freeworld.thc.org/releases/hydra-7.1-src.tar.gz
tar zxvf hydra-7.1-src.tar.gz && rm -rf hydra-7.1-src.tar.gz
cd hydra-7.1-src && ./configure && make
cd hydra-gtk && ./configure
make && mv src/xhydra ../
cd /pentest/temp/ && mv hydra-7.1-src /pentest/enumeration/hydra
fi
if [ ! -d /pentest/web/stompy ] ; then
echo "Installing Stompy"
cd /pentest/temp && wget http://lcamtuf.coredump.cx/stompy.tgz
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
#if [ ! -d /pentest/voip/ace ] ; then
#cd /pentest/temp && wget http://www.protectors.cc/blog/uploads/vapt/ace.tar.gz
#tar zxvf ace.tar.gz && rm -rf ace.tar.gz
#mv ace/ /pentest/voip/ && cd /pentest/voip/ace
#make clean && make
#fi
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
cd /pentest/temp && wget http://freeworld.thc.org/releases/thc-ipv6-1.8.tar.gz
tar zxvf thc-ipv6-1.8.tar.gz && rm -rf thc-ipv6-1.8.tar.gz
cd thc-ipv6-1.8
make all && cd /pentest/temp
mv thc-ipv6-1.8/ /pentest/enumeration/thc-ipv6
fi
if [ ! -d /pentest/enumeration/seat ] ; then
echo "Installing SEAT"
cd /pentest/temp && wget http://midnightresearch.com/common/seat/seat-0.3.tar.bz2
bunzip2 seat-0.3.tar.bz2 &&  tar xvf seat-0.3.tar
rm -rf seat-0.3.tar && mv seat/ /pentest/enumeration
fi
if [ ! -d /pentest/voip/voiphopper ] ; then
cd /pentest/temp && wget http://prdownloads.sourceforge.net/voiphopper/voiphopper-1.02.tar.gz
tar zxvf voiphopper-1.02.tar.gz && rm -rf voiphopper-1.02.tar.gz
mv voiphopper-1.02 /pentest/voip/voiphopper && cd /pentest/voip/voiphopper
cd /pentest/voip/voiphopper && make
fi

if [ ! -d /pentest/wireless/cowpatty ] ; then
cd /pentest/temp && wget http://wirelessdefence.org/Contents/Files/cowpatty-4.6.tgz
tar -zxvf cowpatty-4.6.tgz && rm -rf cowpatty-4.6.tgz
mv cowpatty-4.6/ /pentest/wireless/cowpatty && cd /pentest/wireless/cowpatty
make && sudo make install
fi
if [ ! -d /pentest/enumeration/burpsuite ] ; then
echo "Installing Burp Suite"
cd /pentest/temp && wget http://portswigger.net/burp/burpsuite_v1.4.zip
unzip burpsuite_v1.4.zip && mv burpsuite_v1.4 /pentest/enumeration/burpsuite
fi
if [ ! -d /pentest/enumeration/thc-pptp-bruter ] ; then
echo "Installing THC PPTP Bruteforcer"
cd /pentest/temp && wget wget http://freeworld.thc.org/releases/thc-pptp-bruter-0.1.4.tar.gz
tar zxvf thc-pptp-bruter-0.1.4.tar.gz && mv THC-pptp-bruter-0.1.4/ /pentest/enumeration/thc-pptp-bruter
rm -rf thc-pptp-bruter-0.1.4.tar.gz && cd /pentest/enumeration/thc-pptp-bruter/src
./configure && make
cp thc-pptp-bruter ../
fi
if [ ! -d /pentest/cisco/torch ] ; then
echo "Installing Cisco Torch"
wget http://www.hackingciscoexposed.com/tools/cisco-torch-0.4b.tar.gz && tar zxvf cisco-torch-0.4b.tar.gz
mv cisco-torch-0.4b /pentest/cisco/torch && rm cisco-torch-0.4b.tar.gz
fi
if [ ! -d /pentest/scanners/halfscan6 ] ; then
echo "Installing Halfscan"
cd /pentest/temp && wget http://freshmeat.net/urls/14cf8e84c44c52c3045936e7c3d23f71 -O halfscan6-0.2.tar.gz
tar zxvf halfscan6-0.2.tar.gz && cd halfscan6-0.2
make && cd ../
mv halfscan6-0.2 /pentest/scanners/halfscan6 && rm -rf rm -rf /pentest/temp/halfscan6-0.2.tar.gz
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
#removed as it is currently not working
#if [ ! -d /pentest/enumeration/metagoofil ] ; then
#echo "Installing Metagoofil"
#cd /pentest/temp && wget http://www.edge-security.com/soft/metagoofil-1.4b.tar
#tar xvf metagoofil-1.4b.tar && rm metagoofil-1.4b.tar
#mv metagoofil/ /pentest/enumeration/
#fi
if [ ! -d /pentest/enumeration/firewalk ] ; then
echo "Installing Firewalk"
cd /pentest/temp && wget http://packetfactory.openwall.net/firewalk/dist/firewalk.tar.gz
tar zxvf firewalk.tar.gz && rm -rf firewalk.tar.gz
mv Firewalk/ /pentest/enumeration/firewalk 
#cd /pentest/temp && git clone http://git.libssh.org/projects/libssh.git libssh 
#cd libssh/built && ./build_make.sh
#make && make install
cd /pentest/temp && wget http://prdownloads.sourceforge.net/libdnet/libdnet-1.11.tar.gz
tar zxvf libdnet-1.11.tar.gz && rm -rf libdnet-1.11.tar.gz
cd libdnet-1.11/ && ./configure
make && sudo make install
sudo ln -s /usr/lib/libdumbnet.so /usr/lib/libdnet.so && sudo ln -s /usr/include/dumbnet.h /usr/include/dnet.h
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
if [ ! -d /pentest/scanners/ikescan ] ; then
echo "Installing Ike-Scan"
cd /pentest/temp && wget http://www.nta-monitor.com/tools/ike-scan/download/ike-scan-1.9.tar.gz
tar zxvf ike-scan-1.9.tar.gz && rm -rf ike-scan-1.9.tar.gz
mv ike-scan-1.9/ /pentest/scanners/ikescan && cd /pentest/scanners/ikescan
./configure --with-openssl && make
sudo make install
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
sudo apt-get install expat
mv rats-2.3 /pentest/audit/rats && cd /pentest/audit/rats
./configure && make
sudo make install
fi
#if [ ! -d /pentest/audit/nipper ] ; then
#echo "Installing Nipper"
#cd /pentest/temp && wget http://www.protectors.cc/blog/uploads/vapt/nipper-0.11.7.tgz
#tar zxvf nipper-0.11.7.tgz && rm -rf nipper-0.11.7.tgz
#mv nipper-0.11.7/ /pentest/audit/nipper
#cd /pentest/audit/nipper && make
#fi
if [ ! -d /pentest/cisco/rat ] ; then
cd /pentest/temp && wget --no-check-certificate https://community.cisecurity.org/download/?redir=/cisco/rat-2.2-dist.sh.gz -O rat.gz
gunzip rat.gz && rm -rf rat.gz 
chmod 700 rat
./rat && mv rat-2.2P/ /pentest/cisco/rat
fi
if [ ! -d /pentest/audit/rips ] ; then
echo "Downloading RIPS PHP Static Source Code Analyzer"
wget http://sourceforge.net/projects/rips-scanner/files/rips-0.40.zip/download -O rips.zip
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
if [ ! -f /pentest/enumeration/dnsrecon.rb ] ; then
echo "Installing DNS Recon"
cd /pentest/enumeration/ && wget http://www.darkoperator.com/tools-and-scripts/dnsrecon.rb
chmod 700 /pentest/enumeration/dnsrecon.rb
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
rm -rf start.bat && dos2unix start.sh
fi
if [ ! -d /pentest/web/websecurify ] ; then
echo "Installing WebSecurify"
cd  /pentest/temp && wget0 http://websecurify.googlecode.com/files/Websecurify%200.8.tgz
tar xvf Websecurify\ 0.8.tgz && rm -rf Websecurify\ 0.8.tgz
mv Websecurify\ 0.8/ /pentest/web/websecurify
fi
if [ ! -f /pentest/database/mysqlaudit.py ] ; then
echo "Installing MySQLAudit"
cd /pentest/database && wget http://www.darkoperator.com/tools-and-scripts/mysqlaudit.py
fi
if [ ! -d /pentest/passwords/john ] ; then
echo "Installing John the Ripper"
cd /pentest/temp && wget http://www.openwall.com/john/g/john-1.7.8.tar.gz
tar zxvf john-1.7.8.tar.gz && rm -rf john-1.7.8.tar.gz
mv john-1.7.8 /pentest/passwords/john && cd /pentest/passwords/john/src
make linux-x86-any
fi
if [ ! -d /pentest/passwords/cewl ] ; then
echo "Installing Cewl"
cd /pentest/temp && wget http://www.digininja.org/files/cewl_4.1.tar.bz2
bunzip2 cewl_4.1.tar.bz2 && tar xvf cewl_4.1.tar
mv cewl/ /pentest/passwords/ && rm -rf cewl*
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
cd /pentest/temp && wget http://net-square.com/httprint/httprint_linux_301.zip
unzip httprint_linux_301.zip && rm -rf httprint_linux_301.zip
mv httprint_301/linux /pentest/enumeration/httprint
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
cd /pentest/web/ && wget http://skipfish.googlecode.com/files/skipfish-2.03b.tgz
tar zxvf skipfish-2.03b.tgz && rm -rf skipfish-2.03b.tgz
mv skipfish-2.03b skipfish
cd skipfish && make
cp /pentest/web/skipfish/dictionaries/complete.wl /pentest/web/skipfish/dictionaries/skipfish.wl
fi
if [ ! -d /pentest/web/whatweb ] ; then
echo "Installing WhatWeb"
cd /pentest/temp/ && wget http://www.morningstarsecurity.com/downloads/whatweb-0.4.7.tar.gz
tar zxvf whatweb-0.4.7.tar.gz && rm -rf whatweb-0.4.7.tar.gz
mv whatweb-0.4.7 /pentest/web/whatweb
sudo gem install em-resolv-replace
sudo gem install mongo
sudo gem install rchardet
sudo gem install SystemTimer
fi
if [ ! -d /pentest/passwords/hashcat ] ; then
echo "Installing Hashcat"
cd /pentest/temp && wget http://hashcat.net/files/hashcat-0.37.7z?d=tdtp3vc5qs2a47ied8dbv5a271 -O hashcat-0.37.7z
7za x hashcat-0.37.7z && rm -rf hashcat-0.37.7z
mv hashcat-0.37/ /pentest/passwords/hashcat
fi
if [ ! -d /pentest/exploits/windows-tools ] ; then
echo "Installing Windows Tools"
cd /pentest/exploits && mkdir windows-tools
cd windows-tools && wget http://download.sysinternals.com/Files/PsTools.zip
unzip PsTools.zip && rm -rf PsTools.zip
wget http://dl.packetstormsecurity.net/groups/checksum/nc.exe
cd /pentest/temp && wget http://swamp.foofus.net/fizzgig/fgdump/fgdump-2.1.0-exeonly.tar.bz2
bunzip fgdump-2.1.0-exeonly.tar.bz2 && rm -rf fgdump-2.1.0-exeonly.tar.bz2
tar xvf fgdump-2.1.0-exeonly.tar && rm -rf fgdump-2.1.0-exeonly.tar
mv Release/fgdump.exe /pentest/exploits/windows-tools/ && rm -rf Release/
fi
#if [ ! -d /pentest/passwords/oclhashcat ] ; then
#echo "Installing oclhashcat"
#cd /pentest/temp &&  wget http://hashcat.net/files/oclHashcat-0.25.7z?d=5knt7juet7tih11fu5l28fftf2 -O oclHashcat-0.25.7z
#7za x oclHashcat-0.25.7z && rm -rf oclHashcat-0.25.7z
#mv oclHashcat-0.25/ /pentest/passwords/oclhashcat
#fi
if [ ! -d /pentest/misc/dradis ] ; then
echo "Installing Dradis"
cd /pentest/temp && wget http://sourceforge.net/projects/dradis/files/dradis/v2.8.0/dradis-v2.8.0.tar.bz2/download -O dradis-v2.8.0.tar.bz2
bunzip2 dradis-v2.8.0.tar.bz2 && tar dradis-v2.8.0.tar
rm -rf dradis-v2.8.0.tar && mv dradis-2.8/ /pentest/misc/dradis
cd /pentest/misc/dradis/server && bundle install
fi
if [ ! -d /opt/xplico ] ; then
echo "Installing Xplico"
cd /pentest/temp && wget http://prdownloads.sourceforge.net/xplico/xplico-0.6.3.tgz
tar zxvf xplico-0.6.3.tgz && rm -rf xplico-0.6.3.tgz
cd /pentest/temp/xplico-0.6.3 && make
echo "To complete the installation, sudo su then make install"
echo ""
echo "Xplico was installed for the first time"
echo "There are additional configurations needed"
echo "to Apache, visit the following URL for more info."
echo "http://wiki.xplico.org/doku.php?id=interface"
sleep 10
fi
if [ ! -d /pentest/enumeration/netglub ] ; then
sudo apt-get install build-essential python-simplejson mysql-server libmysqlclient-dev zlib1g-dev libperl-dev libnet-ip-perl libopenssl-ruby ruby-dev ruby omt php5-cli 
sudo apt-get install libnet-dns-perl libnet-ip-perl python-dev qt4-qmake qt-sdk
sudo apt-get install libglib2.0-dev libSM-dev libxrender-dev libfontconfig1-dev libxext-dev
wget http://pypi.python.org/packages/source/s/simplejson/simplejson-2.1.5.tar.gz && tar -xzvf simplejson-2.1.5.tar.gz
rm -rf simplejson-2.1.5.tar.gz && cd simplejson-2.1.5
sudo python setup.py build && sudo python setup.py install 
cd /pentest/temp
wget http://sourceforge.net/projects/pyxml/files/pyxml/0.8.4/PyXML-0.8.4.tar.gz
tar -xvzf PyXML-0.8.4.tar.gz && rm -rf PyXML-0.8.4.tar.gz
cd PyXML-0.8.4 && wget http://launchpadlibrarian.net/31786748/0001-Patch-for-Python-2.6.patch
patch -p1 < 0001-Patch-for-Python-2.6.patch && sudo python setup.py install 
cd /pentest/temp
wget http://www.graphviz.org/pub/graphviz/stable/SOURCES/graphviz-2.26.3.tar.gz
tar -xzvf graphviz-2.26.3.tar.gz
cd graphviz-2.26.3 && ./configure
make && sudo make install
cd /pentest/temp
wget http://sourceforge.net/projects/xmlrpc-c/files/Xmlrpc-c%20Super%20Stable/1.16.34/xmlrpc-c-1.16.34.tgz
tar -zxvf xmlrpc-c-1.16.34.tgz && rm -rf xmlrpc-c-1.16.34.tgz
cd xmlrpc-c-1.16.34
./configure
make && sudo make install
cd /pentest/enumeration && wget http://redmine.lab.diateam.net/attachments/download/1/netglub-1.0.tar.gz
tar -xzvf netglub-1.0.tar.gz && rm -rf netglub-1.0.tar.gz
mv netglub-1.0 netglub
cd /pentest/enumeration/netglub/qng/
qmake && make
#
mysqladmin create netglub -u root -p
mysql -u root -p -e "grant all privileges on netglub.* to 'netglub'@'localhost' identified by 'netglub'"
mysql -u root -p netglub < /pentest/enumeration/netglub/master/tools/sql/netglub.sql  
#
cd /pentest/enumeration/netglub/master
qmake && make
cd tools/ && sudo ./install.sh
cd /pentest/enumeration/netglub/slave
qmake && make
cd tools/ && sudo ./install.sh
fi
echo "Static Code Updates Complete"
