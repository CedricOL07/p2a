# PCAP - TCP packets Analyser

This project aims at building an easy-to-use tool that will parse a `pcap` file to return any ambiguity found in the TCP packets.

__Outline:__
* [Documentation](#documentation)
  * [Launching our script](#launch)
  * [TTL Expiry Attack](#ttl)
* [Contributors](#Contributors)
* [References and external documentation](#references)

## <a name="documentation"></a>Documentation

### <a name="launch"></a>Launching our script

```sh
make

./main.out ./pcap_files/some_pcap_file.pcapng
```

> We purposely name our executables as `.out` files so that we do not push them onto GitHub thanks to the `.gitignore`.

### <a name="ttl"></a>TTL Expiry Attack

The **Time To Live** (TTL) field for an IP packet corresponds to how long is that packet 'allowed' to travel around the network before being dropped by routers. It is a 8-bit value that is usually reduced by one on every hop.

According to [Cisco's page on the TTL Expiry Attack](https://www.cisco.com/c/en/us/about/security-center/ttl-expiry-attack.html):

> "When an IOS device receives a packet with a TTL value of less than or equal to one, an **ICMPv4 Type 11, Code 0** message is sent by an IOS device, resulting in a **corresponding impact on the CPU**.  This impact occurs because more CPU processing is required to respond (using TTL-exceeded packets) to packets with TTL values of less than one than to simply forward a packet with a TTL value greater than one."

> "The TTL expiry behavior creates a **denial of service (DoS) attack vector** against network equipment. Network devices are purpose-built to forward ordinary packets as quickly as possible. When exception packets are encountered, such as those with expiring TTL values, varying amounts of effort are expended by a router to respond appropriately."

In `utils.c`, we defined a `TTL_THRESHOLD` (=10 for now). If the TTL for a packet is lower than this value, a flag is raised to indicate that the TTL is low. If too many such flags are raised, it could be a TTL Expiry Attack.

The [sample pcap file](https://github.com/CedricOL07/pcap_tcp_analyser/blob/master/pcap_files/low_ttl_sample.pcapng) (containing a packet with a low TTL) was captured using the scripts located in the [low_ttl directory](https://github.com/CedricOL07/pcap_tcp_analyser/tree/master/low_ttl).

## <a name="Contributors"></a>Contributors
* [Cedric Olivero](https://github.com/CedricOL07)
* [JB Durville](https://github.com/jbdrvl)

## <a name="references"></a>References and external documentation

### `libpcap`

* [Proramming with pcap](http://www.tcpdump.org/pcap.html)
* [Programming with Libpcap - Sniffing the Network From Your Own Application](http://recursos.aldabaknocking.com/libpcapHakin9LuisMartinGarcia.pdf)
* [`pcap` apps](http://www.stearns.org/doc/pcap-apps.html)
    * `pcap` sample files at the end of the web page
* [The BSD Packet Filter: A New Architecture for User-level Packet Capture](http://www.tcpdump.org//papers/bpf-usenix93.pdf)
* [`tcpdump` filters](http://alumni.cs.ucr.edu/~marios/ethereal-tcpdump.pdf)
* [`libpcap` tutorial](http://yuba.stanford.edu/~casado/pcap)
* [Using `libpcap` in C](https://www.devdungeon.com/content/using-libpcap-c)
* [`pcap.h` manual page](http://www.manpagez.com/man/3/pcap/)

### TTL Expiry Attack
* [TTL - Wikipedia](https://en.wikipedia.org/wiki/Time_to_live)
* [TTL Expiry Attack Identification and Mitigation - CISCO](https://www.cisco.com/c/en/us/about/security-center/ttl-expiry-attack.html)
