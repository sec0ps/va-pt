#!/bin/bash
if [ ! -f /vapt/passwords/weakpass_3a ] ; then
echo "Downloading the weakpass archive"
cd /vapt/passwords && wget https://download.weakpass.com/wordlists/1948/weakpass_3a.7z
7z e weakpass_3a.7z
fi
