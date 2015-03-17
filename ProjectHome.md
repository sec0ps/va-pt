This project aims to offer a portable set of tools used during the course of vulnerability assessment and penetration tests. The tool set and vulnerability database are based on the Ubuntu Linux distribution. This will create a Backtrack (now Kali)/Samurai WTF type environment on your Ubuntu system.

Included in the SVN checkout is the PHP based vulnerability search portal which will allow you to search for vulnerabilities through common databases such as Exploit-DB and the NVD. All of the noted databases are loaded into the local database during kit installation.

It is highly recommended you use the SVN repo over installing from the tar.gz, updates to the static installer scripts are not as frequent.

All scripts have been revised/recreated to function specifically on Ubuntu 12.04LTS.

An installer for the Raspberry PI has been added. The installer was created specifically for the Raspbian distro. All Pi scripts can be found in va-pt/rasp-pi directory. I would strongly recommend installing the PI kit to a single PI then dd'ing the card to an image. After that, use the image to write the additional PI's.

e.g.: sudo dd if=/dev/sdc bs=4M | pv -s 8G | sudo dd of=penpi.img bs=4M

Then use either dd to write the new PI or something like win32diskimager

Any problems, comments or requests, feel free to contact me here or on twitter. It is recommended to use SVN over installing the scripts over the tar files as I do not update the tar files frequently.

Future versions will offer a PHP based interface for the documentation of assessments efforts, generation of reports as well as the generation of common deliverable items such as rules of engagement, findings and technical/executive reports.

-Keith

Twitter: @sec0ps