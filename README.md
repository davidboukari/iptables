# iptables


____________________________________________________________________________
## Restricting host traffic
### Firewall DIAG
### Connexion to the host sshd, httpd
| INPUT                                              |       HOST       |       OUTPUT |
| -------------------                                | ------           | --- |
| proto=tcp, dport=22, state=NEW,RELATED,ESTABLISHED |  -> Listen 22 -> |       proto=tcp, sport=22, state=RELATED,ESTABLISHED |
| proto=tcp, dport=80, state=NEW,RELATED,ESTABLISHED |  -> Listen 80 -> |       proto=tcp, sport=80, state=RELATED,ESTABLISHED |

### HOST out connexion tcp 80,443 - udp 53, icmp
| INPUT                                                |               |       OUTPUT |
| ---                                                   | ----          | ---         | 
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
iptables -t filter -A OUTPUT -p tcp  -m multiport --sports 22,80 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

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
















## Open port 80

```bash
iptables -I INPUT  -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
```

## Open port http & https use multiport

```bash
iptables -I INPUT -p tcp  --match multiport --dport http,https -m state --state NEW,ESTABLISHED -j ACCEPT
```
