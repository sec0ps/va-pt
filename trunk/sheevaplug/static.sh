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

