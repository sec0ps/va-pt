[ ! -d /pentest/passwords/wordlists ] && mkdir /pentest/passwords/wordlists
cd /pentest/passwords/wordlists
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
cp /pentest/exploits/framework3/data/wordlists/namelist.txt /pentest/passwords/wordlists/dns1.txt
cp /pentest/enumeration/fierce2/hosts.txt /pentest/passwords/wordlists/dns2.txt
cp /pentest/enumeration/dnsmap/wordlist_TLAs.txt /pentest/passwords/wordlists/dns3.txt
cp /pentest/enumeration/dnsenum/dns.txt /pentest/passwords/wordlists/dns4.txt
cp /pentest/enumeration/dnsenum/dnsbig.txt /pentest/passwords/wordlists/dns4.txt
cp /pentest/passwords/john/run/password.lst /pentest/passwords/wordlists/
#
gunzip *.gz && tar xvf fixed-length.tar
rm -rf fixed-length.tar && rm -rf *.zip
rm -rf *.tgz && rm -rf *.c
rm -rf *.tar
mv wordlist50.pl /pentest/passwords/
cp /pentest/passwords/oclhashcat/example.dict /pentest/passwords/wordlists/
cat * | grep -v "#" | grep -v ":" | sort -b | uniq >> /pentest/passwords/combinedwordlist
#rm -rf *
#
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
