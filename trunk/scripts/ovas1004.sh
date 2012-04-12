#install openvas 4 deps and software repo
sudo apt-get -y install python-software-properties
sudo add-apt-repository "deb http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_10.04/ ./"
sudo apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys BED1E87979EAFD54
sudo apt-get update
sudo apt-get -y install greenbone-security-assistant gsd openvas-cli openvas-manager openvas-scanner openvas-administrator sqlite3 xsltproc
#configure openvas 4
test -e /var/lib/openvas/CA/cacert.pem  || sudo openvas-mkcert -q
sudo openvas-nvt-sync
test -e /var/lib/openvas/users/om || sudo openvas-mkcert-client -n om -i
sudo /etc/init.d/openvas-manager stop
sudo /etc/init.d/openvas-scanner stop
sudo openvassd
sudo openvasmd --migrate
sudo openvasmd --rebuild
sudo killall openvassd
sleep 15
sudo /etc/init.d/openvas-scanner start
sudo /etc/init.d/openvas-manager start
sudo /etc/init.d/openvas-administrator restart
sudo /etc/init.d/greenbone-security-assistant restart
test -e /var/lib/openvas/users/admin || sudo openvasad -c add_user -n admin -r Admin
#start GSD
gsd &

#http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/
