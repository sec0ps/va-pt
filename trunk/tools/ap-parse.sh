#!/bin/bash
clear
echo "Enter the Customer ESSID"
read essid
sqlite3 -csv -separator '|' wireless.dbl "select NetworkID,ESSID,BSSID,Encryption,GPSMinLat,GPSMinLon from wireless;">all-aps.txt
sqlite3 -csv -separator '|' wireless.dbl "select NetworkID,ESSID,BSSID,Encryption,GPSMinLat,GPSMinLon from wireless where ESSID='$essid';">$essid.txt
sqlite3 -csv -separator '|' wireless.dbl "select NetworkID,ESSID,BSSID,Encryption,GPSMinLat,GPSMinLon from wireless where Encryption='None'">open-aps.txt
sqlite3 -csv -separator '|' wireless.dbl "select NetworkID,ESSID,BSSID,Encryption,GPSMinLat,GPSMinLon from wireless where ESSID!='$essid';">all-less-$essid.txt
sqlite3 -csv -separator '|' wireless.dbl "select NetworkID,ESSID,BSSID,Encryption,GPSMinLat,GPSMinLon from wireless where ESSID!='$essid' and Encryption!='None'">rogue-aps.txt

