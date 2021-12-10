#!/bin/bash
if [ ! -f /vapt/passwords/weakpass_2 ] ; then
echo "Downloading the weakpass archive"
cd /vapt/passwords && curl https://download.weakpass.com/wordlists/1948/weakpass_3a.7z > weakpass_3a.gz
fi
