echo "Starting Redmine"
cd /pentest/misc/redmine && ruby script/server -e production -d
echo "Starting OpenVAS"
sudo /usr/sbin/openvasd -D -q
#echo "Starting MSFRPCD"
#/pentest/exploits/framework3/msfrpcd -U root -P vapt -a 127.0.0.1
#echo "Starting BeEF"
#cd /var/www/beef && sudo ./beef.rb &
#echo "Starting Netglub Master and Slave"
#cd /pentest/enumeration/netglub/master/ && sudo ./master &
#cd /pentest/enumeration/netglub/slave/ && sudo ./slave &
#if [ ! -f /pentest/misc/dradis/config/database.yml ] ; then
#echo "Configuring Dradis for the first time"
#cd /pentest/misc/dradis/config && echo "development:" > database.yml
#echo "  adapter: mysql" >> database.yml
#echo "  database: dradis" >> database.yml
#echo "  username: root" >> database.yml
#echo "  password: vapt" >> database.yml
#echo "  timeout: 5000" >> database.yml
#echo "" >> database.yml
#echo "production:" >> database.yml
#echo "  adapter: mysql" >> database.yml
#echo "  database: dradis" >> database.yml
#echo "  username: root" >> database.yml
#echo "  password: vapt" >> database.yml
#echo "  timeout: 5000" >> database.yml
#cd /pentest/misc/dradis && sudo mysqladmin create dradis -u root -p
#RAILS_ENV=production rake db:migrate && thor dradis:reset
#else
echo "Starting Dradis Web Interface - listening on 3004"
cd /pentest/misc/dradis/server && ruby script/rails server -b 0.0.0.0 -p 3004 -d
fi
