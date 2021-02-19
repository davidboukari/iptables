# iptables


## Configure network
### static old method
```
cat /etc/network/interfaces
auto eth0
iface eth0 inet static
  address 192.168.0.54
  netmask 255.255.255.0
  gateway  192.168.0.254
  dns-nameserver 8.8.8.8

auto eth0:1
iface eth0:1 inet static
  address 192.168.0.56
  netmask 255.255.255.0
```

### with netplan
```
cat  /etc/netplan/00-installer-config.yaml
# This is the network config written by 'subiquity'
network:
  ethernets:
    ens3:
      dhcp4: no
      addresses:
        - 192.168.0.54/24
      gateway4: 192.168.0.254
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1, 127.0.0.53]
  version: 2
```

____________________________________________________________________________
## Add Or Insert rules
* -I: Insert at the begining (default number is 1)
* -A: Append the rule at the end

____________________________________________________________________________
## Remove a rule at line
* iptables -nvL --line-numbers
* iptables -D INPUT 1
* iptables -D OUTPUT 1
____________________________________________________________________________
## Modules
* https://ipset.netfilter.org/iptables-extensions.man.html

### Conntrack 
* apt-get install conntrack

* conntrackd https://conntrack-tools.netfilter.org/manual.html 
```bash
apt-get install conntrackd
tail -f /var/log/conntrackd-stats.log
```

```
CLIENT                      HOST
       -----------------------------------------
                                               -
               SYN                             -
       ===================>                    -
                                               -
       -----------------------                 -  STATE NEW
            SYN / ACK        -                 -
       <===================  -                 -
                             - STATE RELATED   -
             ACK             -                 -
       ===================>  -                 -
                             -                 -
       -----------------------                 -
                                               -
       -----------------------------------------

       <=== ESTABLISHED =====>  STATE ESTABLISHED

       ======== CLOSE ====>
       <======= CLOSE =====
```
____________________________________________________________________________
## ICMP
* https://www.linuxtopia.org/Linux_Firewall_iptables/a6283.html

|TYPE   |CODE   |Description    |Query  Error   |Reference |
| ---   | ---   | ---           |  ---          | ---      |
|0      |0      |Echo Reply     |x              |RFC792    |
|8      |0      |Echo request   |x              |RFC792    |

```
CLIENT                            HOST
     ICMP echo Reply (8)  ---> NEW, RELATED, ESTABLISHED ------> ICMP echo Request (0)
```

### States
* -m state --state NEW,RELATED,ESTABLISHED
* -m conntrack --ctstate NEW,RELATED,ESTABLISHED
 
____________________________________________________________________________
## Backup & Restore rules
```bash
iptables-save > /etc/iptables/rules.v9
iptables-restore < /etc/iptables/rules.v9
```
____________________________________________________________________________
## Table filter - Restricting host traffic
### Firewall DIAG
### Connexion to the host sshd, httpd
| INPUT                                                |       HOST       |       OUTPUT |
| -------------------                                  | ------           | ---          |
| proto=tcp, dport=22, state=NEW,RELATED,ESTABLISHED   |  -> Listen 22 -> |       proto=tcp, sport=22, state=RELATED,ESTABLISHED |
| proto=tcp, dport=80, state=NEW,RELATED,ESTABLISHED   |  -> Listen 80 -> |       proto=tcp, sport=80, state=RELATED,ESTABLISHED |
| proto=tcp, dport=8080, state=NEW,RELATED,ESTABLISHED |  -> Listen 8080 -> |       proto=tcp, sport=8080, state=RELATED,ESTABLISHED |

### HOST out connexion tcp 22,80,443 - udp 53, icmp
| INPUT                                                 |    HOST       |       OUTPUT |
| ---                                                   | ------------- | ---          | 
| proto=tcp, --sports=22, state=RELATED,ESTABLISHED     |               |       proto=tcp, --dports=22, state=NEW,RELATED,ESTABLISHED |
| proto=tcp, --sports=80,443, state=RELATED,ESTABLISHED |               |       proto=tcp, --dports=80,443, state=NEW,RELATED,ESTABLISHED |
| proto=udp, --sport=53, state=RELATED,ESTABLISHED      |               |       proto=udp, --dport=53, state=NEW,RELATED,ESTABLISHED |
| proto=icmp, state=RELATED,ESTABLISHED                 |               |       proto=icmp, state=NEW,RELATED,ESTABLISHED |

```bash
### Flush the CHAINS
iptables -F

## Restricting host traffic
### connexion to the host service sshd,httpd
iptables -t filter -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p tcp --dport 8080 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p tcp  -m multiport --sports 22,80 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --sport 8080 -m state --state RELATED,ESTABLISHED -j ACCEPT


### Authorized host out request tcp 80,443 - udp 53 -  icmp
iptables -t filter -A INPUT -p tcp -m multiport --sports 80,443 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p udp --sport 53 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p icmp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -I INPUT -p tcp --sport 22 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -j DROP

iptables -t filter -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -I OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -j DROP
```

____________________________________________________________________________
# Table nat
| PREROUTING | INPUT   |  OUTPUT |  POSTROUTING  |
| ---        | ---     | ---     |  ---          |
| DNAT cannot update source | SNAT local proc dest=127.0.0.1 cannot update dest | DNAT local proc source=127.0.0.1 cannot update source | SNAT cannot update DEST |

### PREROUTING DNAT
PREROUTING dport 2222 -> DNAT -> dport=22
```
iptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT ip:22
iptables -t nat PREROUTING -p tcp -m tcp --dport 2222 -j DNAT --to-destination 192.168.0.54:22
```

____________________________________________________________________________
### INPUT SNAT
```
iptables -t nat -A INPUT -p tcp -s IP --dport 22 -j SNAT --to-source IP
iptables -t nat -A INPUT -s 192.168.0.118/32 -p tcp -j SNAT --to-source 192.168.0.120
```
____________________________________________________________________________
### OUTPUT DNAT
```
iptables -t nat -I OUTPUT -p tcp --dport 2222 -j DNAT --to :22
iptables -t nat -I OUTPUT -p tcp -d 192.168.0.222 --dport 2223 -j DNAT --to 192.168.0.135:22
```
____________________________________________________________________________
### POSTROUTING SNAT
```
iptables -t nat -I POSTROUTING -p tcp --dport 22 -j SNAT --to 192.168.0.56
```
____________________________________________________________________________
### Table raw - PREROUTING & OUTPUT - reduce the connexion tracking size
```
iptables -t filter -I INPUT -p icmp --icmp-type 8  -j ACCEPT
iptables -t filter -I OUTPUT -p icmp --icmp-type 0 -j ACCEPT

iptables -t raw -I PREROUTING -p icmp --icmp-type 8 -j NOTRACK
iptables -t raw -I OUTPUT -p icmp --icmp-type 0 -j NOTRACK
```
____________________________________________________________________________
## Module connlimit to reduce Limit Ddos Attack

* Limit 2 ssh sessions by host, if you try 3 ssh sessions the 3rd does not work
```
iptables -t filter -I INPUT -p tcp --dport 22 -m connlimit --connlimit-saddr --connlimit-mask 32 --connlimit-above 2 -j REJECT
```

____________________________________________________________________________
## LOG
```
iptables -t filter -nvL --line-numbers
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 #conn src/32 > 3 reject-with icmp-port-unreachable
...
10       0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
11    1952  303K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

# Insert a rule at the position 11
iptables -t filter -I INPUT 11  -j LOG --log-prefix "iptables dropped at INPUT "
iptables -t filter -nvL --line-numbers
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1       78 13764 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 #conn src/32 > 3 reject-with icmp-port-unreachable
...
11       5   260 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            LOG flags 0 level 4 prefix "iptables DROP INPUT"
12    1957  304K DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

tail -f /var/log/syslog
Feb 19 07:59:38 linuxrtr kernel: [41371.170465] iptables DROP INPUTIN=eth0 ...

# Log in OUTPUT
iptables -t filter -I OUTPUT 5 -j LOG --log-prefix "iptables dropped OUTPUT "
curl http://1.1.1.1:5000
tail -f /var/log/syslog
Feb 19 08:12:55 linuxrtr kernel: [42168.040789] iptables dropped OUTPUTIN= OUT=eth0 ...
```







