wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/greenbone-security-assistant_2.0.1-1_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/gsd_1.2.1-2_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/libmicrohttpd10_0.9.19-1_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/libopenvas4_4.0.6-1_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/openvas-administrator_1.1.2-1_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/openvas-cli_1.1.4-1_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/openvas-manager_2.0.4-1_amd64.deb
wget http://download.opensuse.org/repositories/security:/OpenVAS:/STABLE:/v4/xUbuntu_11.10/amd64/openvas-scanner_3.2.5-1_amd64.deb
sudo dpkg -i libopenvas4_4.0.6-1_amd64.deb
sudo dpkg -i libmicrohttpd10_0.9.19-1_amd64.deb
sudo dpkg -i openvas-administrator_1.1.2-1_amd64.deb
sudo dpkg -i openvas-cli_1.1.4-1_amd64.deb
sudo dpkg -i openvas-manager_2.0.4-1_amd64.deb
sudo dpkg -i openvas-scanner_3.2.5-1_amd64.deb
sudo dpkg -i gsd_1.2.1-2_amd64.deb
sudo dpkg -i greenbone-security-assistant_2.0.1-1_amd64.deb
test -e /var/lib/openvas/CA/cacert.pem  || sudo openvas-mkcert -q
sudo openvas-mkcert-client -n om -i
sudo openvas-nvt-sync
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
