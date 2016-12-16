# dns_zone_transfer

dns zone transfer detection tools


# USAGE

```bash
$ python dns_zone_transfer.py www.google.com
[*] `nslookup -type=ns google.com`
[*] Name Server: ['ns4.google.com.', 'ns2.google.com.', 'ns3.google.com.', 'ns1.google.com.']
```

```bash
$ python dns_zone_transfer.py -f domain.txt -o -s 114.114.114.114
[*] `nslookup -type=ns xxx.edu.cn 114.114.114.114`
[*] Name Server: ['dnsserverbak.xxx.edu.cn.', 'dnsserver.xxx.edu.cn.']
[+] 🍺 🍺 🍺  Discover vulnerability. NS:[dnsserverbak.xxx.edu.cn.], DOMAIN:[xxx.edu.cn]
[*] The resulting file xxx.edu.cn_result.txt succeeds.
```

# REFERENCE

[https://github.com/lijiejie/edu-dns-zone-transfer](https://github.com/lijiejie/edu-dns-zone-transfer)