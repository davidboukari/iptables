# iptables

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
apt-get install conntrack

### States
* -m state --state NEW,RELATED,ESTABLISHED
* -m conntrack --ctstate NEW,RELATED,ESTABLISHED
 
____________________________________________________________________________
## Backup & Restore rules
```
iptables-save > /etc/iptables/rules.v9
iptables-restore < /etc/iptables/rules.v9
```
____________________________________________________________________________
## Restricting host traffic
### Firewall DIAG
### Connexion to the host sshd, httpd
| INPUT                                              |       HOST       |       OUTPUT |
| -------------------                                | ------           | --- |
| proto=tcp, dport=22, state=NEW,RELATED,ESTABLISHED |  -> Listen 22 -> |       proto=tcp, sport=22, state=RELATED,ESTABLISHED |
| proto=tcp, dport=80, state=NEW,RELATED,ESTABLISHED |  -> Listen 80 -> |       proto=tcp, sport=80, state=RELATED,ESTABLISHED |
| proto=tcp, dport=8080, state=NEW,RELATED,ESTABLISHED |  -> Listen 8080 -> |       proto=tcp, sport=8080, state=RELATED,ESTABLISHED |

### HOST out connexion tcp 80,443 - udp 53, icmp
| INPUT                                                 |    HOST       |       OUTPUT |
| ---                                                   | ------------- | ---         | 
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
iptables -t filter -A INPUT -j DROP

iptables -t filter -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p icmp -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -j DROP
```

____________________________________________________________________________
# table nat
| PREROUTING | INPUT   |  OUTPUT |  POSTROUTING  |
| ---        | ---     | ---     |  ---          |
| DNAT cannot update source | SNAT local proc dest=127.0.0.1 cannot update dest | DNAT local proc source=127.0.0.1 cannot update source | SNAT cannot update DEST |

## PREROUTING DNAT
PREROUTING dport 2222 -> DNAT -> dport=22
```
iptables -t nat -A PREROUTING -p tcp --dport 2222 -j DNAT ip:22
```

____________________________________________________________________________
### INPUT SNAT
```
iptables -t nat -A INPUT -p tcp -s IP --dport 22 -j SNAT --to-source IP
```
















