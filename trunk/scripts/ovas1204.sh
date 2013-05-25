echo "Installing OpenVAS 5 for Ubuntu 12.04LTS"
echo "Configuring OBS Repository"
sudo apt-get -y install python-software-properties
sudo add-apt-repository "deb http://download.opensuse.org/repositories/security:/OpenVAS:/UNSTABLE:/v5/xUbuntu_12.04/ ./"
sudo apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys BED1E87979EAFD54
sudo apt-get update
#
echo "Installing OpenVAS 5 Packages"
sudo apt-get -y --force-yes install greenbone-security-assistant gsd openvas-cli openvas-manager openvas-scanner openvas-administrator xsltproc
#
echo "Configuring the OpenVAS Server"
test -e /var/lib/openvas/CA/cacert.pem  || sudo openvas-mkcert -q
sudo openvas-nvt-sync
test -e /var/lib/openvas/users/om || sudo openvas-mkcert-client -n om -i
sudo /etc/init.d/openvas-manager stop
sudo /etc/init.d/openvas-scanner stop
sudo openvassd && sudo openvasmd --rebuild
sudo killall openvassd
sleep 15
sudo /etc/init.d/openvas-scanner start
sudo /etc/init.d/openvas-manager start
sudo /etc/init.d/openvas-administrator restart
sudo /etc/init.d/greenbone-security-assistant restart
test -e /var/lib/openvas/users/admin || sudo openvasad -c add_user -n admin -r Admin
echo "Installation of OpenVAS-5 is complete"
echo "Open https://localhost:9392/ or start "gsd" on a command line as a regular user (not as root!)."

