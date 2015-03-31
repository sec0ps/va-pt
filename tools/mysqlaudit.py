
#!/usr/bin/env python
#=========================================================================
#
# NAME: mysqlaudit.py 
# VERSION: 1.0
# AUTHOR: Carlos Perez 
# DATE  : 6/4/2008
# EMAIL: Carlos_perez[at]darkoperator.com
#
# COMMENT: This script is to do basic security assesment of MySQL. 
# 		   It requieres that the MySQLdb module be installed in python
#          http://sourceforge.net/projects/mysql-python
#	
#=========================================================================
# import MySQL module
import MySQLdb
import sys
import time

high = 0
medium = 0
low = 0
date = time.strftime('%X %x')

if len(sys.argv) < 4:
    
    print \
    """
MySQL Security Assesment Script Version 1.0
    """
    print "By: Carlos Perez, carlos_perez[at]darkoperator.com"
    print "USAGE:"
    print "python ", sys.argv [0], " <Targer IP> <User> <Password> <Report> \n"
    print \
    """
Target : The system you whant to do the assement on, port 3306 should be open.
User : User account with DBA privelages on the server to use for the assesment.
Password : password for the user account.
Report : Name of text file to wich to write the report.
            
    """

    exit 
else:
    conn_target = sys.argv [1]
    conn_user = sys.argv [2]
    conn_pass = sys.argv [3]
    report = sys.argv [4]

    #connect
    db = MySQLdb.connect(host= conn_target, user= conn_user, passwd= conn_pass,db="mysql")
    
    cursor = db.cursor()
    
    report_file = open (report, "w")
    
    
    
    #Anonymous user check
    cursor.execute("SELECT User, Host FROM user where user = ''")
    result = cursor.fetchall()
    
    if result == None: 
        print "";
    else:
        high = high + 1
        lines = [
        "Severity: High \n\n",
        "Description:\n\n",
        "MySQL authentication is based on usernames and passwords stored in a table \n\n", 
        "called mysql.user. To create a user, a row is added to this table. MySQL \n", 
        "also supports wildcards and blank values in the USERNAME and HOST fields of \n",
        "the table. By indicating a blank username and a blank password, you allow \n", 
        "anonymous access to the MySQL database. \n",
        "Solution:\n\n",
        "To remove the anonymous user, run the following commands: \n",
        "shell> mysql -u root [password] \n",
        "mysql> DELETE FROM mysql.user WHERE User = ''; \n\n"]
                
        lines += "Anonymous user was found \n \n"
        lines +="   User       Connection Location\n"
        for record in result:
            
            lines += "anonymous " , "---->", record[1], "\n"
     
    #Empty password check
    cursor.execute("SELECT User, Host FROM user WHERE Password=''")
    result = cursor.fetchall()
    
    if result == None: 
        print "";
    else:
        high = high + 1
        lines += [ 
        "\n\n\nSeverity: High \n\n",
        "Description: \n \n",
        "If a blank password is set for a MySQL database account, an attacker can \n", 
        "easily access the MySQL database using the user name. \n\n",
        "Solution: \n\n",
        "To reset a password, run the following commands: \n",
        "shell> mysql -u root [password] \n",
        "mysql> UPDATE user SET Password=PASSWORD('[new_password]') WHERE user='[username]'; \n",
        "mysql> FLUSH PRIVILEGES; \n\n",
        "The following users have and empty password: \n\n"
        ]
        lines +="   User       Connection Location\n"
        for record in result:
            if record[0] == '':
                lines += "anonymous " , "---->  ", record[1], "\n"
            else:
                lines += " ", record[0] , "---->  ", record[1], "\n"
            
               
    #Connection restriction check
    cursor.execute("SELECT User, Host FROM user WHERE FILE_priv = 'Y' AND User != 'root'")
    result = cursor.fetchall()
    
    if result == None: 
        print "";
    else:
        medium = medium + 1
        lines +=[
        "\n\n\nSeverity: Medium \n\n",
    
        "Description: \n\n",
    
        "The FILE privilege allows a user to create files on the operating system \n",
        "using the SELECT [value] INTO OUTFILE statement. Files will be created \n",
        "under the context of the MySQL database. These privilege can be used to \n",
        "manipulate to take control of the MySQL database and possible the system. \n\n",
    
        "Solution: \n\n",
    
        "To prevent users from reading from or writing to the file system, you \n",
        "should revoke the FILE privilege.\n\n",
    
        "shell> mysql -u root [password]\n",
        "mysql>REVOKE FILE ON *.* FROM [username];\n",
        "mysql> FLUSH PRIVILEGES; \n\n\n",
        "The following users have the FILE_PRIV permission: \n"]
        for record in result:
            lines += [record[0] , "     ", record[1], "\n"]
    
    
    #Connection Process Privilege check
    cursor.execute("SELECT User, Host, Process_priv, Super_priv FROM user WHERE Process_priv = 'Y' OR Super_priv = 'Y' AND User!='root'")
    result = cursor.fetchall()
    
    if result == None: 
        print "";
    else:
        medium = medium + 1
        lines += [
        "\n\n\nSeverity: Medium\n\n",
    
        "Description:\n\n",
    
        "The PROCESS privilege allows a user to view information about threads and \n",
        "kill threads with the KILL statement if they have the SUPER privilege. This \n",
        "privilege can be used to gather information about other users on a MySQL \n",
        "database.\n\n",
    
        "Solution:\n\n",
    
        "To prevent users from viewing process information, you should revoke the \n",
        "privilege PROCESS abd SUPER.\n\n",
    
        "shell> mysql -u root [password]\n",
        "mysql>REVOKE PROCESS ON *.* FROM [username];\n",
        "mysql>REVOKE PROCESS ON *.* FROM [username];\n",
        "mysql> FLUSH PRIVILEGES;\n\n", 
        "The Following users where found to have the privileges: \n\n"
        ]
        for record in result:
            lines += ["User: ",record[0] , " Connection Location: ", record[1],
             " Process Privilege: ", record[2]," Super Privilege: ", record[3], "\n"]
    
    
    # Old_passwords check
    cursor.execute("show variables like 'old_passwords'")
    result = cursor.fetchall()
    for record in result:
        if record [1] == 'ON':
            medium = medium + 1
            lines += [
        "\n\n\nSeverity: Medium\n\n",
    
        "Description:\n\n",
    
        "Old password hashing algorithm that can provide an attacker that is able \n",
        "to sniff network traffic tha week password hash that can be bruteforced \n",
        "with ease. \n\n",
    
        "Solution: \n\n",
    
        "Start MySQL with out the --old-passwords optionn",
    
    
            ]    
    
    
    # local_infile check
    cursor.execute("show variables like 'local_infile'")
    result = cursor.fetchall()
    for record in result:
        if record [1] == 'ON':
            medium = medium + 1
            lines += [
        "\n\n\nSeverity: Medium\n\n",
            
        "Description:\n\n",
    
        "The LOAD DATA statement can load a file that is located on the server host, \n",
        "or it can load a file that is located on the client host when the LOCAL  \n",
        "keyword is specified.\n\n",
    
        "There are two potential security issues with supporting the LOCAL version \n",
        "of LOAD DATA statements:\n\n",
    
        "* The transfer of the file from the client host to the server host is \n",
        "initiated by the MySQL server. In theory, a patched server could be built \n",
        "that would tell the client program to transfer a file of the server's \n",
        "choosing rather than the file named by the client in the LOAD DATA statement. \n",
        "Such a server could access any file on the client host to which the client \n",
        "user has read access.\n",
        "* In a Web environment where the clients are connecting from a Web server, \n",
        "a user could use LOAD DATA LOCAL to read any files that the Web server \n",
        "process has read access to (assuming that a user could run any command \n",
        "against the SQL server). In this environment, the client with respect to \n",
        "the MySQL server actually is the Web server, not the remote program being \n",
        "run by the user who connects to the Web server.\n\n",
    
        "Solution:\n\n",
    
        "To disable all LOAD DATA LOCAL  commands from the server side by starting \n",
        "mysqld with the --local-infile=0 option.\n\n",
    
        "Note: Great care should be taken when disabling this feature since many \n",
        "applications relly on this feature.\n\n",
        ]
    
    
            
                
    # logging check
    cursor.execute("show variables like 'log'")
    result = cursor.fetchall()
    for record in result:
        if record [1] == 'OFF':
            medium = medium + 1
            lines += [
        "\n\n\nSeverity: Medium\n\n",
    
        "Description:\n\n",
    
        "Loggin not enabled. The MySQL server, if configured properly, logs \n",
        "connection attempts, queries, and other miscellaneous events to a log file. \n",
        "By logging these events, MySQL provides a way of auditing use of the \n",
        "database and detecting attacks.\n\n",
    
        "Solution:\n\n",
    
        "To enable general logging in MySQL, you must restart the mysqld with the \n",
        "--log option. You can also specify the option in the [mysqld] group in the \n",
        "options file.\n\n",
    
        "The log file is created by starting the msqld using the following option:\n",
        "-l, --log[=file] \n\n",
        ]
    
           
                
    # Openssl check
    cursor.execute("show variables like 'have_openssl'")
    result = cursor.fetchall()
    
    for record in result:
        if record [1] == 'DISABLED':
            medium = medium + 1
            lines += [
        "\n\n\nSeverity: Medium\n\n",
    
        "Description:\n\n",
    
        "Secure Socket Layer (SSL) is a security protocol that provides communications \n",
        "privacy over the network. SSL allows client/server applications to communicate \n",
        "in a way that is designed to prevent eavesdropping, tampering, or message forgery.\n\n",
    
        "Solution:\n\n",
    
        "To enable SSL support in MySQL perform the following steps:\n\n",
    
        "1) Download and install the OpenSSL library from http://www.openssl.org/.\n",
        "2) Compile MySQL with the option '--with-vio --with-openssl'.\n",
        "3) If you are running an older version of MySQL, run the mysql_fix_privilege_tables.sh \n",
        "script to update the mysql.user table.\n\n",
    
        "You can then verify that you have properly compiled the MySQL daemon with \n",
        "OpenSSL by checking the SHOW VARIABLES LIKE 'have_openssl' and ensuring it \n",
        "is set to YES.\n\n",
        
                   ]
                
    # skip show_databases check
    cursor.execute("show variables like 'skip_show_database'")
    result = cursor.fetchall()
    for record in result:
        if record [1] == 'OFF':
            low = low + 1
            lines += [
        "\n\n\nSeverity: Low\n\n",
    
        "Description:\n\n",
    
        "This prevents people from using the SHOW DATABASES statement if they do not\n",
        "have the SHOW DATABASES privilege. This can improve security if you have \n",
        "concerns about users being able to see databases belonging to other users. \n",
        "Its effect depends on the SHOW DATABASES  privilege: If the variable value \n",
        "is ON, the SHOW DATABASES statement is allowed only to users who have the \n",
        "SHOW DATABASES privilege, and the statement displays all database names. \n",
        "If the value is OFF, SHOW DATABASES  is allowed to all users, but displays \n",
        "the names of only those databases for which the user has the SHOW DATABASES \n",
        "or other privilege.\n\n",
    
        "Solution:\n\n",
    
        "Start MySQL with out the --skip-show-database.\n\n",
        
        ]
    # Grant_priv check
    #Connection restriction check
    cursor.execute("SELECT User, Host FROM user WHERE GRANT_priv = 'Y' AND User != 'root'")
    result = cursor.fetchall()
    
    if result == None: 
        print "";
    else:
        high = high + 1
        lines += [
        "\n\n\nSeverity: High\n\n",
    
        "Description:\n\n",
    
        "The GRANT privilege enables the user to give to other users those privileges \n",
        "that he himself possess. It can be used for databases, tables, and stored \n",
        "routines. This privilege can be used for privilage scalation attack.\n\n",
    
        "Solution:\n\n",
    
        "To prevent users from granting privelages, you should revoke the privilege \n",
        "GRANT.\n\n",
    
        "shell> mysql -u root [password]\n",
        "mysql>REVOKE GRANT ON *.* FROM [username];\n",
        "mysql> FLUSH PRIVILEGES;\n\n\n\n",
        ]
        
    cursor.execute("show variables like 'Version'")
    result = cursor.fetchall()
    for record in result:
        lines += "############################################## \n"
        lines += "Date:" + date + "\n"
        lines += "MySQL Version:" + str(record[1]) + "\n"
        lines += str(high) + " High Risk issues where found \n" 
        lines += str(medium) + " Medium Risk issues where found \n"
        lines += str(low) + " Low Risk issues where found \n" 
        lines += "############################################## \n"
    report_file.writelines (lines)
    report_file.close()
    db.close()    
