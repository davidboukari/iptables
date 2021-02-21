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
## iptables diag
```
PREROUTING ===========================> FORWARD ============================> POSTROUTING ==========>
  raw: tracking ?                                           /\                  mangle: headers (TTL,QoS,...)
  mangle: change headers (TTL, QoS, ...)                    ||                  nat: SNAT (because DEST is knew)
  nat:  DNAT (because source is knew)                       ||
   ||                                                       ||
   ||                                                       ||                             
   =============> INPUT                                   OUTPUT
                    mangle: headers (TTL,QoS,...)           raw: tracking  
                    nat: SNAT (dest=localhost).             mangle: headers (TTL,QoS,...)
                    filter: firewalling                     nat: DNAT (because source=localhost)
                    ||                                      filter: firewalling ====> | -t filter -A OUTPUT ...    
                    ||                                      ||                  RULES | -t filter -A OUTPUT ...
                    ||                                      ||                        | -t filter -A OUTPUT ...  
                    \/                                      ||                        | -t filter -A OUTPUT ...         
                    =============> LOCAL PROCESS =============>                       | -t filter -A OUTPUT ...         
                                                                                            ======> |  ACCEPT                                
                                                                                           TARGETS  | Targets DROP                              
                                                                                                    | Targets REJECT                           
                                                                                                    | Targets LOG                       
                                                                                                    | Targets SNAT                          
                                                                                                    | Targets DNAT                            
                                                                                                    | Targets NOTRACK                            
                                                                                                                                
                    
                    
                    
```

____________________________________________________________________________
## Modules
* https://ipset.netfilter.org/iptables-extensions.man.html

### iptables states - Conntrack 
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
____________________________________________________________________________
## Log to a file & log rotate
* rsyslog
```
ls /etc/rsyslog.d/
20-ufw.conf  21-cloudinit.conf  50-default.conf
vim /var/log/10-iptables.conf
if ( $msg contains 'iptables' )
then {
  /var/log/iptables.log
  stop
}
systemctl restart rsyslog
tail -n 2  /var/log/iptables.log
Feb 19 10:04:08 linuxrtr kernel: [48841.790463] iptables DROP INPUTIN=eth0 OUT=..
```

* logrotate
```
cd /etc/logrotate.d/
ls
alternatives  apache2  apport  apt  bootlog  btmp  conntrackd  dpkg  rsyslog  ubuntu-advantage-tools  ufw  unattended-upgrades  wtmp
cp ufw iptables
vim iptables
cat iptables
/var/log/iptables.log
{
        rotate 7
        weekly
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
        endscript
}
systemctl restart logrotat
```

____________________________________________________________________________
## CUSTOM CHAINS
* iptables -N newChain
* iptables -t nat -N newChain
```
iptables -N ALLOWEDMGMT
iptables -t filter -I INPUT -s 192.168.0.70 -j ALLOWEDMGMT
iptables -nvL
iptables -t filter -I ALLOWEDMGMT -m multiport --dports 22,80 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -nvL
...
Chain ALLOWEDMGMT (2 references)
 pkts bytes target     prot opt in     out     source               destination
  319 19904 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 22,80 ctstate NEW,RELATED,ESTABLISHED
```

____________________________________________________________________________
## Module connlimit to reduce Limit Ddos Attack
* Limit 2 ssh sessions by host, if you try 3 ssh sessions the 3rd does not work
```
iptables -t filter -I INPUT -p tcp --dport 22 -m connlimit --connlimit-saddr --connlimit-mask 32 --connlimit-above 2 -j REJECT
```
____________________________________________________________________________
## hashlimit
```
# Create a custrom chain to log and drop
iptables -N LOGDROP
iptables -t filter -A LOGDROP -j LOG --log-prefix "iptables: drop log "
iptables -t filter -A LOGDROP -j DROP

# Limit 10 ping / minute
iptables -t filter -I INPUT -p icmp -m hashlimit --hashlimit-above 10/minute --hashlimit-mode srcip \
                                                 --hashlimit-srcmask 32 --hashlimit-name ping-restrict \
                                                 -m conntrack --ctstate NEW,RELATED,ESTABLISHED  -j LOGDROP

# hashlimit bandwidth limiter
apt-get install speedtest-cli
# Download
iptables -t filter -I INPUT -p tcp -m multiport --sports 80,443,8080 \ 
                                                -m hashlimit --hashlimit-name hashlimit-download-max  --hashlimit-mode srcip \
                                                --hashlimit-srcmask 32 --hashlimit-above 512kb/s -j LOGDROP

# Upload
iptables -t filter -I OUTPUT -p tcp -m multiport --dports 80,443,8080 \
                                                 -m hashlimit --hashlimit-name hashlimit-upload-max  --hashlimit-mode dstip \
                                                 --hashlimit-dstmask 32 --hashlimit-above 512kb/s -j LOGDROP

```

____________________________________________________________________________
## user / group traffic restriction
```
# By user
iptables -t filter -I OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m owner --uid-owner user1 -j DROP
iptables -t filter -I OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m owner --uid-owner user1 -j LOG --log-uid --log-prefix "iptables: user1 tcp/22 deny "

# By Group
groupadd restrictedusers
useradd -m -g restrictedusers user2

iptables -t filter -I OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m owner --gid-owner restrictedusers -j DROP
iptables -t filter -I OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m owner --gid-owner restrictedusers -j LOG --log-uid --log-prefix 'iptables: restrictedueser tcp/22 deny '
```


____________________________________________________________________________
## ipset to group ips & ports
```
apt-get install ipset

ipset create ALlOWEDMGMTPORTS bitmap:port range 0-65535
ipset add ALLOWEDMGMT 192.168.0.0/24
ipset add ALLOWEDMGMT 192.168.101.1
ipset list

ipset create aLLOWEDMGMT hash:net
ipset add ALLOWEDMGMTPORTS tcp:22
ipset add ALLOWEDMGMTPORTS tcp:80
ipset add ALLOWEDMGMTPORTS tcp:8080
ipset add ALLOWEDMGMTPORTS udp:53
ipset list

iptables -t filter -I INPUT -m set --match-set ALLOWEDMGMT src -m set --match-set. ALLOWEDMGMTPORTS dst -m contrack -ctstate NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t filter -I INPUT -m match --match-set ALLOWEDMGMTPORTS dst j LOGDROP

ipset del ALLOWEDMGMT 192.168.101.1
ipset del ALLOWEDMGMTPORTS 53
ipset del ALLOWEDMGMTPORTS 80
ipset del ALLOWEDMGMTPORTS 8080
ipset list

```
