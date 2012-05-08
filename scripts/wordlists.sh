if [ ! -d /pentest/passwords/wordlists ]; then
mkdir /pentest/passwords/wordlists && cd /pentest/passwords/wordlists
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.org/Crackers/wordlists/dictionaries"| grep -o '<a href="/files/download/[^"]*"' |sed 's/<a href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/dictionaries/;s/"$//'|cut -d "/" -f 1-6,8 >file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.org/Crackers/wordlists/names"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/names/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.org/Crackers/wordlists/computing"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/computing/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.org/Crackers/wordlists/dates"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/dates/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.org/Crackers/wordlists/language"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/language/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.org/Crackers/wordlists/literature"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/literature/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/sports"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/sports/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/science"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/science/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/religion"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/religion/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/misc"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/misc/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/music"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/music/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/movies_tv"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/movies_tv/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -q -U "Mozilla/5.0 (Linux; U; Android 2.1; en-us; Nexus One Build/ERD62) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Mobile Safari/530.17" -O- "http://packetstormsecurity.net/Crackers/wordlists/utilities"| grep -o 'href="/files/download/[^"]*"' |sed 's/href="\/files\/download/http:\/\/dl.packetstormsecurity.org\/Crackers\/wordlists\/utilities/;s/"$//'|cut -d "/" -f 1-6,8 >>file.txt
wget -nc -q -i file.txt && rm -rf file.txt
#Get/Process remote stuff
mv wordlist50.pl /pentest/passwords/
cd /pentest/passwords/wordlists && wget http://erikmusick.com/content/dl/WholeLottaPasswords.7z
7za e WholeLottaPasswords.7z && rm -rf WholeLottaPasswords.hash WholeLottaPasswords.7z*
#
gunzip *.gz && tar xvf fixed-length.tar
rm -rf fixed-length.tar && rm -rf *.zip
rm -rf *.tgz && rm -rf *.c
rm -rf *.tar
#Get local stuff
cat /pentest/exploits/framework3/data/wordlists/namelist.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/db2_default_pass.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/http_default_pass.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/postgres_default_pass.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/sid.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/snmp_default_pass.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/tomcat_mgr_default_pass.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/unix_passwords.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/vnc_passwords.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/exploits/framework3/data/wordlists/unix_users.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/enumeration/fierce2/hosts.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/enumeration/dnsmap/wordlist_TLAs.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/enumeration/dnsenum/dns.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/enumeration/dnsenum/dnsbig.txt >> /pentest/passwords/wordlists/merged.txt
cat /pentest/passwords/john/run/password.lst >> /pentest/passwords/wordlists/merged.txt
#
cd /pentest/passwords
cat *  >> /pentest/passwords/mass1 && strings /pentest/passwords/mass1 >> /pentest/passwords/strings
rm -rf mass1 && cat /pentest/passwords/strings | sort -bi | uniq >> /pentest/passwords/combinedwordlist
rm -rf strings && rm -rf /pentest/passwords/wordlists/merged.txt
#
fi
if [ ! -d /pentest/passwords/vendor ] ; then
mkdir /pentest/passwords/vendor && cd /pentest/passwords/vendor
wget -nc -q http://vulnerabilityassessment.co.uk/default_oracle_passwords.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsNO.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsA.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsB.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsB.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsD.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsE.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsF.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsG.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsH.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsI.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsJ.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsK.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsL.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsM.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsN.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsO.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsP.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsQ.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsR.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsS.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsT.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsU.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsV.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsW.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsX.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsY.htm
wget -nc -q http://vulnerabilityassessment.co.uk/passwordsZ.htm
wget -nc -q http://www.phenoelit-us.org/dpl/dpl.html
fi
