#!/bin/bash
if [ ! -f /vapt/passwords/weakpass_2 ] ; then
echo "Downloading the weakpass archive"
cd /vapt/passwords && curl https://download.weakpass.com/wordlists/1863/weakpass_2.gz > weakpass_2.gz
fi
