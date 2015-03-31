echo "Enter the root mysql password"
read mrpass
#create the application database
mysqladmin create application -u root --password=$mrpass
#create the user table
mysql -u root --password=$mrpass < sqlschema/users.sql application
#create the application account
mysql -u root --password=$mrpass -e "grant all privileges on application.* to 'vapt'@'localhost' identified by 'vapt';"
#Launch firefox to add the first user account
firefox setup-user.php
#delete the setup-user page
#rm -rf setup-user.php
#create customer project table
mysql -u root --password=$mrpass < sqlschema/createproject.sql application
