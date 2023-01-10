# airodump-beacon
airodump-ng </br>
capture beacon packet and print BSSID, PWR, BEACONS, ESSID

# compile option
$ gcc airodump.c -o airodump -lpcap

# usage
$ sudo ./airodump <interface_name> </br>
ex) sudo ./airodump wlan0
