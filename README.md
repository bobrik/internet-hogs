# Netflow (IPFIX, [RFC7011]) collector

[RFC7011]: https://datatracker.ietf.org/doc/html/rfc7011

This is a collector I run for my home network. It allows me to see
who's talking to whom over the Internet connection.

## Configuring EdgeRouter X

My internet is plugged into `eth1` and I have the following to send
the netflow packets towards `192.168.1.50` where the collector runs:

```
ivan@erx# show system flow-accounting
 ingress-capture post-dnat
 interface eth1
 netflow {
     engine-id 1
     server 192.168.1.50 {
         port 2055
     }
     timeout {
         expiry-interval 60
         flow-generic 60
         icmp 60
         max-active-life 60
         tcp-fin 60
         tcp-generic 60
         tcp-rst 60
         udp 60
     }
     version 10
 }
```

Unfortunately, Ubiquity does not support IPv6 for the server IP here.
What's more, it also doesn't support IPv6 flow collection, but that part
can be remedied by copy-pasting `iptables` rules into `ip6tables`:

```
ivan@erx# cat /config/scripts/post-config.d/ipv6-ipfix.sh
#!/bin/bash

set -euo pipefail

# Remove old rules if present

ip6tables -D VYATTA_POST_FW_FWD_HOOK -o eth1 -j NFLOG --nflog-group 5 --nflog-size 64 --nflog-threshold 20 || true
ip6tables -D VYATTA_POST_FW_FWD_HOOK -i eth1 -j NFLOG --nflog-group 2 --nflog-size 64 --nflog-threshold 20 || true

ip6tables -D VYATTA_POST_FW_IN_HOOK -o eth1 -j NFLOG --nflog-group 5 --nflog-size 64 --nflog-threshold 20 || true
ip6tables -D VYATTA_POST_FW_IN_HOOK -i eth1 -j NFLOG --nflog-group 2 --nflog-size 64 --nflog-threshold 20 || true

ip6tables -D VYATTA_POST_FW_OUT_HOOK -o eth1 -j NFLOG --nflog-group 5 --nflog-size 64 --nflog-threshold 20 || true

# Insert new rules

ip6tables -I VYATTA_POST_FW_FWD_HOOK -i eth1 -j NFLOG --nflog-group 2 --nflog-size 64 --nflog-threshold 20
ip6tables -I VYATTA_POST_FW_FWD_HOOK -o eth1 -j NFLOG --nflog-group 5 --nflog-size 64 --nflog-threshold 20

ip6tables -I VYATTA_POST_FW_IN_HOOK -i eth1 -j NFLOG --nflog-group 2 --nflog-size 64 --nflog-threshold 20
ip6tables -I VYATTA_POST_FW_IN_HOOK -o eth1 -j NFLOG --nflog-group 5 --nflog-size 64 --nflog-threshold 20

ip6tables -I VYATTA_POST_FW_OUT_HOOK -o eth1 -j NFLOG --nflog-group 5 --nflog-size 64 --nflog-threshold 20
```

## The collector

The collector does three things:

1. It prints flow information to `stderr` as it receives it.
2. It exports a metric with the number of bytes received per local IP.
3. It exports all flows into a Clickhouse table for future analysis.

### Flow information in stderr

It looks like this:

```
E8:FF:1E:D5:F4:16 | 192.168.1.50:51118                                 -> 104.18.185.54:443                                  : [0x06]         27 packets,       2245 bytes
E8:FF:1E:D5:F4:16 | 192.168.1.50:51118                                 <- 104.18.185.54:443                                  : [0x06]         36 packets,      32032 bytes
```

Here a local IP `192.168.1.50` requested some data from `104.18.185.54` and you
can see how many bytes were exchanged. Neat, but kind of hard to analyze.

### Prometheus metric

To be able to plot who's downloading the most, the following metric is exported:

```
$ curl -s http://ip6-localhost:3434/metrics | grep 192.168.1.50
ipfix_bytes_received_total_total{local_ip="192.168.1.50"} 10198779
```

### Clickhouse table

The table I have in a local Clickhouse:

```
(
    `insertionTime` DateTime64(0),
    `clientMac` UInt64,
    `clientIPv4` IPv4,
    `clientIPv6` IPv6,
    `clientPort` UInt16,
    `serverIPv4` IPv4,
    `serverIPv6` IPv6,
    `serverPort` UInt16,
    `protocol` UInt8,
    `packets` UInt32,
    `bytes` UInt32,
    `is_download` Bool
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(insertionTime)
ORDER BY (insertionTime, clientIPv4, clientIPv6)
SETTINGS index_granularity = 8192
```

It is useful for higher cardinality analysis.
