#watchdog script for aws using ppp0 interface
#created by Jason Frisvold aka @XenoPhage
sudo /usr/sbin/hping3 -c 2 -p 22 -I ppp0 <hostname> > /tmp/wvdialchecker

RC=`grep "flags=RA" /tmp/wvdialchecker | wc -l`
if [ $RC -eq 0 ]
then
   sudo /usr/bin/pkill wvdial 
   sudo /usr/bin/wvdial &
fi
