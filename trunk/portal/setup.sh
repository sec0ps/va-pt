echo "Enter the root mysql password"
read mrpass
echo "Enter the application user password"
read apppass
#create the application database
mysqladmin create application -u root --password=$mrpass
#create the user table
mysql -u root --password=$mrpass < sqlschema/users.sql application
#create the application account
mysql -u root --password=$mrpass -e "grant all privileges on application.* to 'vapt'@'localhost' identified by 'vapt';"
# Create the default user account
#mysql -u root --password=$mrpass -e "insert into users (username, password, email, status) values ('vapt','269358d235f932225280eb0e9f77bb9c727eba97','enforce570@gmail.com','0')" application
#Launch firefox to add the first user account
firefox setup-user.php
#delete the setup-user page
#rm -rf setup-user.php