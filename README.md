# p2a - Parse PCAP for Anomalies

This project aims at building an easy-to-use tool that will parse a `pcap` file to return any ambiguity found in the TCP packets.

__Outline:__
* [Documentation](#documentation)
  * [Launching our script](#launch)
  * [Anomalies](#anomalies)
    * [TTL Expiry Attack](#ttl)
    * [ARP Spoofing](#arp-spoofing)
* [Contributors](#Contributors)
* [References and external documentation](#references)

## <a name="documentation"></a>Documentation

### <a name="launch"></a>Launching our script

```sh
make

./p2a ./pcap_files/some_pcap_file.pcapng
```

### <a name="anomalies"></a>Anomalies

#### <a name="ttl"></a>TTL Expiry Attack

The **Time To Live** (TTL) field for an IP packet corresponds to how long is that packet 'allowed' to travel around the network before being dropped by routers. It is a 8-bit value that is usually reduced by one on every hop.

According to [Cisco's page on the TTL Expiry Attack](https://www.cisco.com/c/en/us/about/security-center/ttl-expiry-attack.html):

> "When an IOS device receives a packet with a TTL value of less than or equal to one, an **ICMPv4 Type 11, Code 0** message is sent by an IOS device, resulting in a **corresponding impact on the CPU**.  This impact occurs because more CPU processing is required to respond (using TTL-exceeded packets) to packets with TTL values of less than one than to simply forward a packet with a TTL value greater than one."

> "The TTL expiry behavior creates a **denial of service (DoS) attack vector** against network equipment. Network devices are purpose-built to forward ordinary packets as quickly as possible. When exception packets are encountered, such as those with expiring TTL values, varying amounts of effort are expended by a router to respond appropriately."

In `utils.c`, we defined a `TTL_THRESHOLD` (=10 for now). If the TTL for a packet is lower than this value, a flag is raised to indicate that the TTL is low. If too many such flags are raised, it could be a TTL Expiry Attack.

The [sample pcap file](https://github.com/CedricOL07/pcap_tcp_analyser/blob/master/pcap_files/low_ttl_sample.pcapng) (containing a packet with a low TTL) was captured using the scripts located in the [low_ttl directory](https://github.com/CedricOL07/pcap_tcp_analyser/tree/master/low_ttl).

#### <a name="arp-spoofing"></a>ARP Spoofing

ARP Spoofing consists in fooling a host in believing we are the *default gateway*. The victim regularly asks the *default gateway* its MAC address (ARP protocol). But an attack can send the victim packets saying that the *default gateway* is at another MAC address (the attack's MAC address for example). The attacker just needs to send those packets "regularly enough" so that the victim "discards" the real messages from the *default gateway*.

This can allow the attack to proceed to attack the victim in many ways: man-in-the-midde, DoS, black-hole, ...
* MitM: the attacker redirects the traffic from the victim to the real *default gateway* and vice-versa. That way it can sniff the victim's traffic. It can also modify the packets (active man-in-the-middle).
* Black-hole: the attacker does not process the packets it gets from the victim: the victim cannot connect to the Internet anymore.

**Example:**

The victim's IP address is `192.168.10.2` and the *default gateway* is at `192.168.1.1`:

```sh
sudo arpspoofing -i wlan0 -t 192.168.10.2 192.169.1.1
```

The attacker will keep on sending the victim ARP packets telling that `192.168.1.1` is at the attacker's MAC address. That way the victim will send its packets (aiming for the Internet) to the attacker, who does not redirect them (`-r` option to redirect them).

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
