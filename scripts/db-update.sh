#!/bin/bash
clear
#echo "Enter your vapt database username: "
#read dbuser
#echo "Enter your vapt database password: "
#read dbpass
echo "Enter the root mysql password"
read mrpass
cd /pentest/misc/va-pt/scripts/
mysql -u root --password=$mrpass -e 'show databases' | grep exploitdb
if [ $? -eq 1 ] ; then
mysqladmin -u root --password=$mrpass create exploitdb
mysql -u root --password=$mrpass exploitdb < exploitdb.sql
mysql -u root --password=$mrpass -e "grant all privileges on exploitdb.* to 'vapt'@'localhost' identified by 'vapt';"
fi

mysql -u root --password=$mrpass -e "show databases" | grep nvd
if [ $? -eq 1 ] ; then
mysqladmin -u root --password=$mrpass create nvd
mysql -u root --password=$mrpass nvd < nvd.sql
mysql -u root --password=$mrpass -e "grant all privileges on nvd.* to 'vapt'@'localhost' identified by 'vapt';"
fi

#mysql -u root --password=$mrpass -e "show databases" | grep osvdb
#if [ $? -eq 1 ] ; then
#mysqladmin -u root --password=$mrpass create osvdb
#mysql -u root --password=$mrpass -e "grant all privileges on osvdb.* to 'vapt'@'localhost' identified by 'vapt';"
#fi

#cd /pentest/temp
#echo "Updating the OSVDB Database"
#wget http://osvdb.org/file/get_latest_mysql/UaBc6bGFQZgJHYEvZhQ3kg2Pak/osvdb-mysql.latest.tar.gz
#gunzip osvdb-mysql.latest.tar.gz && sudo chown mysql osvdb-mysql.latest.tar
#mysql -u root --password=$mrpass --compress osvdb < osvdb-mysql.latest.tar && rm -rf /pentest/temp/osvdb-mysql.latest.tar
#rm -rf /pentest/temp/osvdb-mysql.latest.tar
#
# exploitdb update
echo "Updating the ExploitDB Database"
sudo cp /pentest/exploits/exploitdb/files.csv /tmp/exploits.csv && sudo chown mysql /tmp/exploits.csv
sudo chmod 666 /tmp/exploits.csv && mysqlimport --compress --columns=id,file,description,date,author,platform,type,port --delete --ignore --ignore-lines=1 --fields-terminated-by=, --fields-optionally-enclosed-by="\"" exploitdb /tmp/exploits.csv -u root --password=$mrpass
sudo rm -rf /tmp/exploits.csv
#
#NVD
cd /pentest/temp
echo "Updating the NVD Database"
wget http://cve.mitre.org/data/downloads/allitems.csv -O nvd.csv && sudo mv nvd.csv /tmp/
sudo chown mysql /tmp/nvd.csv && mysqlimport --compress --delete --columns=name,status,description,reference,phase,votes,comments --ignore-lines=8 --replace --fields-terminated-by=, nvd /tmp/nvd.csv -u root --password=$mrpass
sudo rm -rf /tmp/nvd.csv
#
