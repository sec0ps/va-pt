echo "Static software package installation beginning"

#Completed
if [ ! -f /vapt/scanners/snmpcheck-1.8.pl ] ; then
echo "Installing snmpcheck"
cd /vapt/scanners && wget http://www.nothink.org/perl/snmpcheck/downloads/snmpcheck-1.8.pl -O snmpcheck.pl
chmod 700 /vapt/scanners/snmpcheck.pl
fi
if [ ! -d /vapt/web/zap ] ; then
echo "Installing ZED Attack Proxy"
cd /vapt/web && wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz
tar xvf ZAP_2.15.0_Linux.tar.gz && rm -rf ZAP_2.15.0_Linux.tar.gz
mv ZAP* zap/
fi
#Arachni Installer
if [ ! -d /vapt/web/arachni ] ; then
cd /vapt/web && wget https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
tar xvf arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
mv arachni-1.6.1.3-0.6.1.1/ arachni/ && rm arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
fi 
#misc stuff

#Pending Review
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
#if [ ! -d /vapt/exploits/windows-tools ] ; then
#echo "Installing Windows Tools"
#cd /vapt/exploits && mkdir windows-tools
#cd windows-tools && wget http://download.sysinternals.com/files/PSTools.zip
#unzip PSTools.zip && rm -rf PSTools.zip
#cd /vapt/temp && wget http://www.foofus.net/fizzgig/fgdump/fgdump-2.1.0-exeonly.tar.bz2
#bunzip2 fgdump-2.1.0-exeonly.tar.bz2 && rm -rf fgdump-2.1.0-exeonly.tar.bz2
#tar xvf fgdump-2.1.0-exeonly.tar && rm -rf fgdump-2.1.0-exeonly.tar
#mv Release/fgdump.exe /vapt/exploits/windows-tools/ && rm -rf Release/
#fi
#if [ ! -d /vapt/exploits/armitage ] ; then
#echo "Installing Armitage"
#cd /vapt/temp && wget http://www.fastandeasyhacking.com/download/armitage150813.tgz
#tar xvf armitage150813.tgz  && mv armitage/ /vapt/exploits
#echo "Be sure to edit the database.yml file in /opt/metasploit/apps/pro/ui/config/"
#fi
