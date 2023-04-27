#!/bin.sh
service NetworkManager stop
airmon-ng check kill
pkill -9 hostapd
pkill -9 python3
pkill -9 python3
pkill -9 dnsmasq