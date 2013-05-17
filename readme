The set of scripts included in this package will create a Backtrack/SamuraiWTF type environment for the performing of
Vulnerability Assessments and Penetration Testing.

The goal of this project was to allow a portable set of tools to be easily installed onto Ubuntu at a
moments notice, allowing the tester to be free of distribution release specific constraints.

These scripts were designed specifically for Ubuntu 12.04 LTS.

Contents of Files
-----------------
deps.sh - Contains the necessary software dependencies for the tools within the kit to function.
exploits.sh - Contains the scripts to download various exploit code from public sources
services.sh - Starts the various integrated services of the kit such as msfrpcd, OpenVAS, Dradis, etc
static.sh - Downloads static applications which are not svn capable
svn.sh - SVN repository scripts to checkout and update the various tools
wordlists.sh - Contains the scripts to download the various wordlists from public sources
update.sh - The script that makes it all happen
readme - You're looking at it
search/ - the PHP Files for the local vulnerability and exploitdb search interface

How To
------
To start, run the installer: sudo ./install.sh
Install the dependencies first via option 1) Install/Check Dependencies

--Setup for postgres DB 
sudo su postgres
psql
create user <username with password 'password' createdb;
create database msf owner <your username>;
\q
./msfconsole
db_connect <username>:<password>@localhost/msf

Add the db_connect statement into the msfconsole file for simplicity
-- .msf4/msfconsole.rc
-- db_connect username:password@localhost:port/msf

If you are running, or are planning on running, Nexpose on the same system. You will need to change the listening port on the postgresql database.

/etc/postgresql/8.4/main/postgresql.conf



All tools are loaded into the /pentest directory.

Future Major Release to include
-------------------------
Security Assessment Management Portal
-- PCI-DSS Assessment
-- ISO Assessment
-- NIST 800-53a Assessment
-- Vulnerability Assessment & Penetration Testing Management

Keith Pachulski
Security Consultant
keithp@protectors.cc
