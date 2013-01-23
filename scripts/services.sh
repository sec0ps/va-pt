echo "Starting Redmine"
cd /pentest/misc/redmine && ruby script/rails server webrick -e production -d 
echo "Starting OpenVAS"
sudo openvassd
sudo openvasmd
sudo gsad -p 8001 --http-only
echo GSAD is running @ http://localhost:8001
#
#echo "Starting MSFRPCD"
#/pentest/exploits/framework3/msfrpcd -U root -P vapt -a 127.0.0.1
#echo "Starting BeEF"
#cd /var/www/beef && sudo ./beef.rb &
#echo "Starting Netglub Master and Slave"
#cd /pentest/enumeration/netglub/master/ && sudo ./master &
#cd /pentest/enumeration/netglub/slave/ && sudo ./slave &
echo "Starting Dradis Web Interface - listening on 3004"
cd /pentest/misc/dradis/server && ruby script/rails server -b 0.0.0.0 -p 3004 -d
fi
