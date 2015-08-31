echo "Creating new wordlist and mutating the wordlist"
echo "What is the URL we are generating the wordlist from?"
read url
echo "What is the name of the file you want to save the wordlist to?"
read wordlist
cd /pentest/passwords/cewl && ruby cewl.rb -w tempwordlist $url
echo "Taking the wordlist and mutating it with John the Ripper"
/pentest/passwords/john/run/john --wordlist=tempwordlist --rules --stdout > mutatedwordlist
echo "Merging, sorting and removing duplicates into the final wordlist"
cat mutatedwordlist > merged && cat tempwordlist >> merged
cat merged | sort | uniq > $wordlist && rm mutatedwordlist tempwordlist merged
