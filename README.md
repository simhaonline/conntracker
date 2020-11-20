Connection Tracker / Firewall Rules Indicator

## Problem

So you are currently thinking about creating a set of firewall rules, perhaps setting REJECT as a default policy to your chains, but you don't have a clear picture of what is the traffic that you currently have. If you block too much you might end up having lots of complains about services that used to work and does not work anymore. If you don't block enough you end up having an insecure environment.

## Solutions

There are multiple ways you can understand the traffic passing through your firewall.

 1. One of the most common ways, that pops up to our head immediatly, is to match some flows in our firewall and target them to the LOG target plugin. It will dump characteristics or matched packets into the syslog and you can further analyse it.

 2. Another way of doing it would be to use better targets, such as NFLOG... and gain some more flexibility using ulogd2 userland daemon. Just like the LOG target, you can get characteristics of matched packets into NFLOG kernel backend and have those delivered to ulogd2 userland daemon. With ulogd2 you can even write those logs into a database, or capture it in libpcap dump format.

 3. Of course... if you're on fire you might even chose to tcpdump your firewall. You would have to filter for packets initializing streams, sort them, filter garbage, etc.

## Making conntrack to do the dirt job

Those already familiar with netfilter and conntrack might already have thought about using it to discover all conntrack events. So, instead of reinventing the whell, we call tell the kernel to track all the flows for us - at least for a certain time - and get all the events out of it.

One way of doing it would be doing:

```
$ sudo conntrack -E -e NEW
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=53798 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=53798
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=34.71.14.52 sport=40414 dport=443 [UNREPLIED] src=34.71.14.52 dst=192.168.200.2 sport=443 dport=40414
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=33914 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=33914
    [NEW] udp      17 30 src=192.168.100.251 dst=8.8.8.8 sport=41433 dport=53 [UNREPLIED] src=8.8.8.8 dst=192.168.200.2 sport=53 dport=41433
    [NEW] tcp      6 120 SYN_SENT src=192.168.100.118 dst=130.44.215.56 sport=40752 dport=80 [UNREPLIED] src=130.44.215.56 dst=192.168.200.2 sport=80 dport=40752
```
You can wrap all that information using a script, and extract all the relevant data - to knowing needed flows for your network - or you can use this tool. What this tool basically does is:

 * To rely on kernel conntrack mechanism to report all flows happening (you need to add a conntrack rule to your firewall).
 * Maintain an in-memory sorted/balanced btree of all flows (tcpv4/udpv4/icmpv4/tcpv6/udpv6/icmpv6) that happened during monitoring time.
 * Dump this list of all monitored flows in a consumable (sorted) way so you can understand what are the rules your firewall will need.
 
## Compiling it
 
In order to compile it you will need the following Debian/Ubuntu packages installed:
 
 * libnetfilter-conntrack-dev
 * libglib2.0-dev
 * pkg-config
 
In order to run it in another host you will need at least packages:
 
 * libnetfilter-conntrack3
 * libglib2.0-0
 
installed.
 
## Using it

After compiling the tool you only need to run it on your firewall for the time you want to monitor it. At the end you press [ctrl+c] and it will dump a list of all the flows that it has observed during that period. The list is dumped in a sorted way, with prefixes that tell you the type of protocol and the number of the flow.

Example:
 
```
 $ sudo ./conntracker 
 TCPv4 [           0] src = 192.168.100.111 (port=1024) to dst = 157.240.12.54 (port=443) (confirmed)
 TCPv4 [           1] src = 192.168.100.118 (port=1024) to dst = 65.8.205.11 (port=443) (confirmed)
 TCPv4 [           2] src = 192.168.100.118 (port=1024) to dst = 192.48.236.11 (port=443) (confirmed)
 TCPv4 [           3] src = 192.168.100.118 (port=1024) to dst = 65.8.205.28 (port=443) (confirmed)
 TCPv4 [           4] src = 192.168.100.118 (port=1024) to dst = 65.8.205.49 (port=80) (confirmed)
 TCPv4 [           5] src = 192.168.100.118 (port=1024) to dst = 34.69.16.85 (port=443) (confirmed)
 TCPv4 [           6] src = 192.168.100.118 (port=1024) to dst = 65.8.205.93 (port=80) (confirmed)
 TCPv4 [           7] src = 192.168.100.118 (port=1024) to dst = 44.236.32.117 (port=443) (confirmed)
 TCPv4 [           8] src = 192.168.100.118 (port=1024) to dst = 35.202.243.141 (port=443) (confirmed)
 TCPv4 [           9] src = 192.168.100.118 (port=1024) to dst = 52.89.160.221 (port=443) (confirmed)
 TCPv4 [          10] src = 192.168.100.119 (port=1024) to dst = 172.217.162.196 (port=443) (confirmed)
 TCPv4 [          11] src = 192.168.100.203 (port=1024) to dst = 104.244.42.8 (port=443) (confirmed)
 TCPv4 [          12] src = 192.168.100.203 (port=1024) to dst = 172.217.29.10 (port=443) (confirmed)
 TCPv4 [          13] src = 192.168.100.203 (port=1024) to dst = 172.217.28.14 (port=443) (confirmed)
 TCPv4 [          14] src = 192.168.100.203 (port=1024) to dst = 216.58.202.14 (port=443) (confirmed)
 TCPv4 [          15] src = 192.168.100.203 (port=1024) to dst = 192.16.58.25 (port=443) (confirmed)
 TCPv4 [          16] src = 192.168.100.203 (port=1024) to dst = 13.227.108.31 (port=443) (confirmed)
 TCPv4 [          17] src = 192.168.100.203 (port=1024) to dst = 18.205.40.43 (port=443) (confirmed)
 TCPv4 [          18] src = 192.168.100.203 (port=1024) to dst = 157.240.12.53 (port=443) (confirmed)
 TCPv4 [          19] src = 192.168.100.203 (port=1024) to dst = 65.8.205.61 (port=443) (confirmed)
 TCPv4 [          20] src = 192.168.100.203 (port=1024) to dst = 172.67.18.66 (port=443) (confirmed)
 TCPv4 [          21] src = 192.168.100.203 (port=1024) to dst = 172.217.173.78 (port=443) (confirmed)
 TCPv4 [          22] src = 192.168.100.203 (port=1024) to dst = 18.229.250.79 (port=443) (confirmed)
 TCPv4 [          23] src = 192.168.100.203 (port=1024) to dst = 18.229.94.96 (port=443) (confirmed)
 TCPv4 [          24] src = 192.168.100.203 (port=1024) to dst = 151.101.194.109 (port=443) (confirmed)
 TCPv4 [          25] src = 192.168.100.203 (port=1024) to dst = 172.217.30.110 (port=443) (confirmed)
 TCPv4 [          26] src = 192.168.100.203 (port=1024) to dst = 172.217.162.110 (port=443) (confirmed)
 TCPv4 [          27] src = 192.168.100.203 (port=1024) to dst = 104.20.63.113 (port=443) (confirmed)
 TCPv4 [          28] src = 192.168.100.203 (port=1024) to dst = 162.213.33.134 (port=443) (confirmed)
 TCPv4 [          29] src = 192.168.100.203 (port=1024) to dst = 172.217.162.138 (port=443) (confirmed)
 TCPv4 [          30] src = 192.168.100.203 (port=1024) to dst = 172.217.29.142 (port=443) (confirmed)
 TCPv4 [          31] src = 192.168.100.203 (port=1024) to dst = 216.58.202.161 (port=443) (confirmed)
 TCPv4 [          32] src = 192.168.100.203 (port=1024) to dst = 172.217.30.170 (port=443) (confirmed)
 TCPv4 [          33] src = 192.168.100.203 (port=1024) to dst = 151.101.192.176 (port=443) (confirmed)
 TCPv4 [          34] src = 192.168.100.203 (port=1024) to dst = 172.217.172.195 (port=443) (confirmed)
 TCPv4 [          35] src = 192.168.100.203 (port=1024) to dst = 172.217.162.202 (port=443) (confirmed)
 TCPv4 [          36] src = 192.168.100.203 (port=1024) to dst = 172.217.172.202 (port=443) (confirmed)
 TCPv4 [          37] src = 192.168.100.203 (port=1024) to dst = 216.58.202.205 (port=443) (confirmed)
 TCPv4 [          38] src = 192.168.100.203 (port=1024) to dst = 172.217.172.206 (port=443) (confirmed)
 TCPv4 [          39] src = 192.168.100.203 (port=1024) to dst = 52.45.124.230 (port=443) (confirmed)
 TCPv4 [          40] src = 192.168.100.203 (port=1024) to dst = 172.217.28.234 (port=443) (confirmed)
 TCPv4 [          41] src = 192.168.100.203 (port=1024) to dst = 34.211.99.245 (port=443) (confirmed)
 TCPv4 [          42] src = 192.168.100.203 (port=1024) to dst = 18.231.0.250 (port=443) (confirmed)
 UDPv4 [           0] src = 0.0.0.0 (port=68) to dst = 255.255.255.255 (port=67)
 UDPv4 [           1] src = 192.168.100.123 (port=500) to dst = 200.169.116.51 (port=500) (confirmed)
 UDPv4 [           2] src = 192.168.100.152 (port=1024) to dst = 50.23.190.219 (port=50101) (confirmed)
 UDPv4 [           3] src = 192.168.100.203 (port=1024) to dst = 8.8.8.8 (port=53) (confirmed)
 UDPv4 [           4] src = 192.168.100.203 (port=1024) to dst = 172.217.29.10 (port=443) (confirmed)
 UDPv4 [           5] src = 192.168.100.203 (port=1024) to dst = 172.217.28.14 (port=443) (confirmed)
 UDPv4 [           6] src = 192.168.100.203 (port=1024) to dst = 216.58.202.14 (port=443) (confirmed)
 UDPv4 [           7] src = 192.168.100.203 (port=1024) to dst = 157.240.12.16 (port=443) (confirmed)
 UDPv4 [           8] src = 192.168.100.203 (port=1024) to dst = 172.217.173.78 (port=443) (confirmed)
 UDPv4 [           9] src = 192.168.100.203 (port=1024) to dst = 172.217.162.99 (port=443) (confirmed)
 UDPv4 [          10] src = 192.168.100.203 (port=1024) to dst = 172.217.30.110 (port=443) (confirmed)
 UDPv4 [          11] src = 192.168.100.203 (port=1024) to dst = 172.217.162.110 (port=443) (confirmed)
 UDPv4 [          12] src = 192.168.100.203 (port=1024) to dst = 65.8.205.125 (port=44446)
 UDPv4 [          13] src = 192.168.100.203 (port=1024) to dst = 65.8.205.125 (port=44447)
 UDPv4 [          14] src = 192.168.100.203 (port=1024) to dst = 65.8.205.125 (port=44448)
 UDPv4 [          15] src = 192.168.100.203 (port=1024) to dst = 65.8.205.125 (port=44449)
 UDPv4 [          16] src = 192.168.100.203 (port=1024) to dst = 65.8.205.125 (port=44450)
 UDPv4 [          17] src = 192.168.100.203 (port=1024) to dst = 172.217.28.131 (port=443) (confirmed)
 UDPv4 [          18] src = 192.168.100.203 (port=1024) to dst = 172.217.162.138 (port=443) (confirmed)
 UDPv4 [          19] src = 192.168.100.203 (port=1024) to dst = 172.217.29.142 (port=443) (confirmed)
 UDPv4 [          20] src = 192.168.100.203 (port=1024) to dst = 216.58.202.161 (port=443) (confirmed)
 UDPv4 [          21] src = 192.168.100.203 (port=1024) to dst = 172.217.30.170 (port=443) (confirmed)
 UDPv4 [          22] src = 192.168.100.203 (port=1024) to dst = 172.217.172.195 (port=443) (confirmed)
 UDPv4 [          23] src = 192.168.100.203 (port=1024) to dst = 172.217.162.202 (port=443) (confirmed)
 UDPv4 [          24] src = 192.168.100.203 (port=1024) to dst = 172.217.172.202 (port=443) (confirmed)
 UDPv4 [          25] src = 192.168.100.203 (port=1024) to dst = 216.58.202.205 (port=443) (confirmed)
 UDPv4 [          26] src = 192.168.100.203 (port=1024) to dst = 172.217.172.206 (port=443) (confirmed)
 UDPv4 [          27] src = 192.168.100.203 (port=1024) to dst = 172.217.28.234 (port=443) (confirmed)
 UDPv4 [          28] src = 192.168.100.251 (port=1024) to dst = 8.8.4.4 (port=53) (confirmed)
 UDPv4 [          29] src = 192.168.100.251 (port=1024) to dst = 8.8.8.8 (port=53) (confirmed)
 UDPv4 [          30] src = 192.168.100.252 (port=1024) to dst = 192.168.100.255 (port=17500)
 UDPv4 [          31] src = 192.168.100.252 (port=1024) to dst = 255.255.255.255 (port=17500)
ICMPv4 [           0] src = 192.168.100.152 to dst = 172.217.162.196 (type=0 | code=0) (confirmed)
```
Some things to notice:

  * All insecure ports (higher than 1024) are logged as 1024 so there aren't many duplicates of flows (as its really common for many different source ports to be used in same connections).
  
  * At the end you may find a "(confirmed)" flag. This means that the flow was confirmed, meaning that both sides have communicated in that flow (and not only one side, that could mean a connection attempt, for example).
  
  * This tool is a work-in-progress and there are many possible TODOs (convert to a daemon, dump tables w/ SIGUSER, etc).
