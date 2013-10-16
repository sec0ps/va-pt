netstat -an --inet | grep <yoursystemhere>:24
if [ $? -lt 1 ] ; then
echo "the reverse shell is working on port 24"
else
echo "the reverse shell is not working on port 24 - restartng"
ssh -fN -R 19999:localhost:22 <yourusernamehere>@<yoursystemhere> -p 24
fi
netstat -an --inet | grep <yoursystemhere>:81
if [ $? -lt 1 ] ; then
echo "the reverse shell is working on port 81"
else
echo "the reverse shell is not working on port 81 - restarting"
ssh -fN -R 20000:localhost:22 <yourusernamehere>@<yoursystemhere> -p 81
fi
