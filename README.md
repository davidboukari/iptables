# iptables


## Open port 80

```bash
iptables -I INPUT  -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
```

## Open port http & https use multiport

```bash
iptables -I INPUT -p tcp  --match multiport --dport http,https -m state --state NEW,ESTABLISHED -j ACCEPT
```
