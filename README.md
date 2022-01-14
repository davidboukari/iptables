# iptables

## Docs
* https://linux.developpez.com/iptables/?page=traversees

## Modules
* https://ipset.netfilter.org/iptables-extensions.man.html

## Create an eve-ng lab 
* https://github.com/davidboukari/eve-ng/blob/main/README.md

## firewalld
* https://github.com/davidboukari/firewalld

## Configure DNS resolver

### DNS
```
mv /etc/resolv.conf /etc/resolv.conf.ini
ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
```
### Add vnc access
```
iptables -t filter -I INPUT -p tcp  --dport 5901  -j ACCEPT
```
____________________________________________________________________________
## Log to a file & log rotate

* https://www.opensourcerers.org/2016/05/27/how-to-trace-iptables-in-rhel7-centos7/
* https://qastack.fr/server/385937/how-to-enable-iptables-trace-target-on-debian-squeeze-6
* https://sleeplessbeastie.eu/2020/11/13/how-to-trace-packets-as-they-pass-through-the-firewall/

```
modprobe nf_log_ipv4
sysctl net.netfilter.nf_log.2=nf_log_ipv4
systemctl restart rsyslog

# Log some packet
iptables -t raw -j TRACE -p tcp --dport 80 -I PREROUTING 1
iptables -t raw -j TRACE -p tcp --dport 80 -I OUTPUT 1   

iptables -t raw -j TRACE -p tcp --dport 53 -I PREROUTING 1
iptables -t raw -j TRACE -p tcp --dport 53 -I OUTPUT 1


# To show
iptables -L -v -t raw

# To delete rule
iptables -t raw -D PREROUTING 2
iptables -t raw -D OUTPUT 1



# Trace DNS call and back
iptables -t raw -A PREROUTING -p udp --sport 53 -j TRACE
iptables -t raw -A PREROUTING -p udp --dport 53 -j TRACE

iptables -t raw -A OUTPUT -p udp --sport 53 -j TRACE
iptables -t raw -A OUTPUT -p udp --dport 53 -j TRACE
```

## kernel print
* https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/getting-started-with-kernel-logging_managing-monitoring-and-updating-the-kernel

```
$ sysctl kernel.printk
kernel.printk = 7	4	1	7


```


## kernel restriction
* https://www.stigviewer.com/stig/red_hat_enterprise_linux_8/2020-11-25/finding/V-230269

```
kernel.dmesg_restrict = 1
sudo grep -r kernel.dmesg_restrict /etc/sysctl.conf /etc/sysctl.d/*.conf

```
----------------

    Load the (IPv4) netfilter log kernel module:
    # modprobe nf_log_ipv4
    Enable logging for the IPv4 (AF Family 2):
    # sysctl net.netfilter.nf_log.2=nf_log_ipv4
  

    reconfigure rsyslogd to log kernel messages (kern.*) to /var/log/messages:

# cat /etc/rsyslog.conf | grep -e "^kern"
kern.*;*.info;mail.none;authpriv.none;cron.none                /var/log/messages

    restart rsyslogd:
    # systemctl restart rsyslog

iptables -t raw -L

iptables -t raw -j TRACE -p tcp --dport 80 -I PREROUTING 1
iptables -t raw -j TRACE -p tcp --dport 80 -I OUTPUT 1
```

* Log everythings
```
iptables -I INPUT 1 -j LOG
iptables -I FORWARD 1 -j LOG
iptables -I OUTPUT 1 -j LOG

iptables -t nat -I PREROUTING 1 -j LOG
iptables -t nat -I POSTROUTING 1 -j LOG
iptables -t nat -I OUTPUT 1 -j LOG
```

* rsyslog
```
ls /etc/rsyslog.d/
20-ufw.conf  21-cloudinit.conf  50-default.conf
tee /etc/rsyslog.d/10-iptables.conf<<EOF
if ( \$msg contains 'iptables' )
then {
  /var/log/iptables.log
  stop
}
EOF
systemctl restart rsyslog
systemctl restart firewalld.service
tail -n 2  /var/log/iptables.log
Feb 19 10:04:08 linuxrtr kernel: [48841.790463] iptables DROP INPUTIN=eth0 OUT=..
```

* logrotate
```
cd /etc/logrotate.d/
ls
alternatives  apache2  apport  apt  bootlog  btmp  conntrackd  dpkg  rsyslog  ubuntu-advantage-tools  ufw  unattended-upgrades  wtmp
cp ufw iptables

tee /etc/logrotate.d/iptables<<EOF
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
EOF
systemctl restart logrotat
```

____________________________________________________________________________


## Configure network
* https://github.com/davidboukari/network

```
ip a
ip addr show
ip route show
ip addr flush dev eth1
ip addr add 192.168.1.1/24 dev eth1
ip link set eth1 up
ip route add default via 192.168.1.1
```

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
                                          mangle: headers
                                          filter: firewalling
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
                                                                                            ======> | ACCEPT                                
                                                                                           TARGETS  | DROP                              
                                                                                                    | REJECT                           
                                                                                                    | LOG                       
                                                                                                    | SNAT                          
                                                                                                    | DNAT                            
                                                                                                    | NOTRACK                            
                                                                                                                                
                    
                    
                    
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
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 2222 -j DNAT --to-destination 192.168.0.54:22
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination :5601
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
## FORWARD - 2 interfaces -  Masquerading or SNAT with output interface IP
```
# Activate forwarding echo
echo 1 > /proc/sys/net/ipv4/ip_forward
# or sysctl
vim /etc/sysctl.conf
sysctl --system

# Accept packet from 2nd interface
iptables -t filter -I INPUT -i eth1 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# MASQUERADE
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# OR
iptables -t nat -I POSTROUTING  -o eth0 -j SNAT --to 192.168.0.54


# Filtering FORWARD Chain
iptables -t filter -I FORWARD -p tcp --dport 12345 -i eth2 -o eth0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j LOG --log-prefix "iptables: Dropped eth2 tcp/12345"
iptables -t filter -I FORWARD -p tcp --dport 12345 -i eth2 -o eth0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j DROP
```

## Filtering FORWARD Chain
```
# Drop all FORWARD packet from eth2 -> eth1
iptables -t filter -A FORWARD  -i eth2 -o eth0  -j LOGDROP

# Insert before ACCEPT FORWARD packet -A FORWARD tcp/12345  -i eth2 -o eth0
iptables -t filter -I FORWARD -p tcp --dport 12345 -i eth2 -o eth0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT

# Insert before before LOG FORWARD packet -A FORWARD tcp/12345  -i eth2 -o eth0
iptables -t filter -I FORWARD -p tcp --dport 12345 -i eth2 -o eth0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j LOG "iptables: OK eth2 tcp/12345"

iptables -t filter -nvL --line-numbers
Chain FORWARD (policy ACCEPT 132 packets, 13567 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        6   331 LOG        tcp  --  eth2   eth0    0.0.0.0/0            0.0.0.0/0            tcp dpt:12345 ctstate NEW,RELATED,ESTABLISHED LOG flags 0 level 4 prefix "iptables: ACCEPT eth2 tcp/123"
2       12   669 ACCEPT     tcp  --  eth2   eth0    0.0.0.0/0            0.0.0.0/0            tcp dpt:12345 ctstate NEW,RELATED,ESTABLISHED
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

ipset  list |grep -i name
ipset create ALLOWEDMGMT hash:net
ipset add ALLOWEDMGMT 192.168.0.0/24
ipset add ALLOWEDMGMT 192.168.101.1
ipset list

ipset create ALLOWEDMGMTPORTS bitmap:port range 0-65535
ipset add ALLOWEDMGMTPORTS tcp:22
ipset add ALLOWEDMGMTPORTS tcp:80
ipset add ALLOWEDMGMTPORTS tcp:8080
ipset add ALLOWEDMGMTPORTS udp:53
ipset list

iptables -t filter -I INPUT -m set --match-set ALLOWEDMGMT src -m set --match-set ALLOWEDMGMTPORTS dst -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -I INPUT -m set --match-set ALLOWEDMGMTPORTS dst -j LOGDROP

ipset del ALLOWEDMGMT 192.168.101.1
ipset del ALLOWEDMGMTPORTS 53
ipset del ALLOWEDMGMTPORTS 80
ipset del ALLOWEDMGMTPORTS 8080
ipset list
```

### ipset block ips
* https://github.com/trick77/ipset-blacklist
```
# get the source
apt-get install -y git
git clone https://github.com/trick77/ipset-blacklist.git
mkdir -p /etc/ipset-blacklist

# Tunning
cat ipset-blacklist.conf
MAXELEN=264000
HASHSIZE=32768

# build the blacklist
./update-blacklist.sh ipset-blacklist.conf
.........
Blacklisted addresses found: 46121
ipset list
iptables -t filter -nvL --line-numbers
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blacklist src

# Add to drop list ipset-blacklist.conf - see: https://rules.emergingthreats.net/fwrules/
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
./update-blacklist.sh ipset-blacklist.conf
..........
Blacklisted addresses found: 55193

# destroy the blacklist
ipset destroy blacklist
# Remove the input listcreate the blacklist:
ipset create blacklist -exist hash:net family inet hashsize 32768 maxelem 264000
iptables -I INPUT 1 -m set --match-set blacklist src -j DROP
iptables -I OUTPUT -m set --match-set blacklist dst -j LOGDROP
```

#### Set persitant ipset
```
ipset save > /etc/ipset.conf
cd /usr/share/netfillter-persistent/plugins.d/
cat /usr/share/netfilter-persistant/plugins.d/10-ipset
#!/bin/bash
/sbin/ipset restore -! < /etc/ipset.conf

# Can reboot to check that all rules have been loaded
```

_____________________________________
## FQDN
```
apt-get install -y dnsmasq
 cat  /etc/dnsmasq.d/confperso
max-cache-ttl=120
server=8.8.8.8
ipset=/test.iptablesexpert.com/specialaccess,allowedincoming
listen-address=127.0.0.1
no-dhcp-interface=
bind-interfaces
```

### set DNS to 127.0.0.1
* Edit DNS in  /etc/netplan/01-installer-config.yaml
* Edit DNS in /etc/systemd/resolved.conf

```
iptables -t filter -I INPUT -s 127.0.0.1 -d 127.0.0.1 -p udp --dport 53 -j ACCEPT
iptables -t filter -I OUTPUT -s 127.0.0.1 -d 127.0.0.1 -p udp --sport 53 -j ACCE
nslookup google.com
Server:         127.0.0.1
Address:        127.0.0.1#53

Non-authoritative answer:
Name:   google.com
Address: 216.58.201.238
Name:   google.com
Address: 2a00:1450:4007:806::200e
```

### ipset specialaccess,  allowedincoming  list are automatically updated
```
ipset create specialaccess hash:net timeout 600
root@linuxrtr:/home/ubuntu# ipset create allowedincoming hash:net timeout 600
root@linuxrtr:/home/ubuntu# ipset list allowedincoming
Name: allowedincoming
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536 timeout 600
Size in memory: 448
References: 0
Number of entries: 0
Members:
root@linuxrtr:/home/ubuntu# nslookup test.iptablesexpert.com
Server:         127.0.0.1
Address:        127.0.0.1#53

Non-authoritative answer:
Name:   test.iptablesexpert.com
Address: 192.168.0.70

root@linuxrtr:/home/ubuntu# ipset list allowedincoming
Name: allowedincoming
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536 timeout 600
Size in memory: 544
References: 0
Number of entries: 1
Members:
192.168.0.70 timeout 593
root@linuxrtr:/home/ubuntu# ipset list specialaccess
Name: specialaccess
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536 timeout 600
Size in memory: 544
References: 0
Number of entries: 1
Members:
192.168.0.70 timeout 570
```

### backup the ipset list
```
ipset save|grep allowedincoming > /etc/ipset.conf
```

```
cat /etc/apache2/ports.conf
# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 80
Listen 8080
Listen 8095
Listen 8096

ipset add ALLOWEDMGMTPORTS tcp:8095
ipset add ALLOWEDMGMTPORTS tcp:8096

ipset list ALLOWEDMGMTPORTS
22
53
80
8080
8095
8096

iptables -t filter -I INPUT -m set --match-set specialaccess src -m set --match-set ALLOWEDMGMTPORTS dst -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT

iptables -t filter -I OUTPUT -m set --match-set ALLOWEDMGMTPORTS src  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```


## Geoloc
```
sudo apt-get install -y  xtables-addons-common xtables-addons-dkms
sudo apt-get install libtext-csv-xs-perl

sudo mkdir /usr/share/xt_geoip
# download the geoip
/usr/lib/xtables-addons/xt_geoip_dl

# create the generator file
cat xtgeoipupdate.sh
#!/bin/bash

tmpdir=$(mktemp -d)
csv_files="${tmpdir}/dbip-country-lite.csv"
current_folder=$PWD
cd "${tmpdir}"
/usr/lib/xtables-addons/xt_geoip_dl
/usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip "${csv_files}°
cd $current_folder
rm -r ${tmpdir}
exit 0

./xtgeoipupdate.sh

ls /usr/share/xt_geoip
apt-get install geoip-database
apt-get install geoipupdate
apt-get install geoip-bin
```

## vnc redirect to localhost
* https://serverfault.com/questions/211536/iptables-port-redirect-not-working-for-localhost
```
#!/bin/bash

iptables -t nat -I PREROUTING -p tcp --dport 5909 -j REDIRECT --to-ports 5901
iptables -t nat -I OUTPUT -p tcp -o lo --dport 5901 -j REDIRECT --to-ports 5909
```

## Forward to localhost is a redirect
```
iptables -t nat -I PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 5901
iptables -t nat -I OUTPUT -p tcp -o lo --dport 5901 -j REDIRECT --to-ports 443
```


## NFT
```
nft list ruleset
table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		meta l4proto tcp tcp dport 22 counter packets 11140 bytes 1189608 jump f2b-sshd
	}

	chain FORWARD {
		type filter hook forward priority filter; policy accept;
		meta l4proto tcp ip saddr 172.17.0.0/16 ip daddr 172.17.0.0/16 tcp dport 13306 counter packets 0 bytes 0 accept
		meta l4proto tcp ip daddr 172.17.0.0/16 tcp dport 3306 counter packets 0 bytes 0 drop
		meta l4proto tcp ip saddr 172.17.0.0/16 ip daddr 172.17.0.0/16 tcp dport 13306 counter packets 0 bytes 0 accept
		meta l4proto tcp ip daddr 172.17.0.0/16 tcp dport 3306 counter packets 0 bytes 0 drop
		meta l4proto tcp ip saddr 172.17.0.0/16 ip daddr 172.17.0.0/16 tcp dport 13306 counter packets 0 bytes 0 accept
		meta l4proto tcp ip daddr 172.17.0.0/16 tcp dport 13306 counter packets 0 bytes 0 drop
		meta l4proto tcp ip daddr 172.17.0.0/16 tcp dport 3306 counter packets 0 bytes 0 drop
	}

	chain OUTPUT {
		type filter hook output priority filter; policy accept;
	}

	chain f2b-sshd {
		counter packets 11032 bytes 1173296 return
	}
}
table ip raw {
	chain PREROUTING {
		type filter hook prerouting priority raw; policy accept;
		meta l4proto tcp tcp dport 13306 counter packets 501 bytes 26027 meta nftrace set 1
		meta l4proto tcp tcp dport 13306 counter packets 525 bytes 27809 meta nftrace set 1
		meta l4proto tcp tcp dport 13306 counter packets 533 bytes 28734 meta nftrace set 1
		meta l4proto tcp tcp dport 13306 counter packets 561 bytes 30250 meta nftrace set 1
	}



```
