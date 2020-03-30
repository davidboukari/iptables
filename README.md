# iptables


## Open port 80

```bash
iptables -I INPUT  -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
```
