#!/bin/bash
if [ ! -f /pentest/passwords/weakpass_2 ] ; then
echo "Downloading the weakpass archive"
cd /pentest/passwords && wget http://download656.mediafire.com/366bpvy2xzvg/x5ci9iv66x54e6v/weakpass_2.7z 
7z e weakpass_2.7z && rm -rf weakpass_2.7z 
fi
