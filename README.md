# p2a - Parse PCAP for Anomalies

This project aims at building an easy-to-use tool that will parse a `pcap` file to return any ambiguity found in the TCP packets. We are currently working on implementing UDP and ARP analysis as well.

__Outline:__
* [Contributors](#contributors)
* [Documentation](#documentation)
  * [Launching our script](#launch)
  * [Anomalies](#anomalies)
    1. [TTL Expiry Attack](#ttl)
    2. [ARP Poisoning](#arp-poisoning)
    3. [TCP Retransmission](#tcp-retransmission)
    4. [Overlapping Fragments](#overlapping-fragments)
    5. [Multiple TTL values](#multiple-ttl)
  * [Project directories](#dir)
* [References and external documentation](#references)

## <a name="contributors"></a>Contributors

* [Cedric Olivero](https://github.com/CedricOL07)
* [JB Durville](https://github.com/jbdrvl)

> Contributing: any comment/idea/contribution is welcome.

## <a name="documentation"></a>Documentation

### <a name="launch"></a>Launching our script

```sh
make

./p2a -v ./pcap_files/some_pcap_file.pcap -s results.json
```

#### Usage

```
$ ./p2a -h
Usage: ./p2a [OPTIONS] FILE
	-h,--help:		display this help message
	-v,--verbose:		verbose option
	-d,--debug:		debug option
	-x,--exclude OPTIONS:	exclude some possible ambiguities from analysis
		--exclude ret,mac,ttl
			ret: exclude retransmission analysis
			mac: exclude MAC addresses analysis
			ttl: exclude TTL analysis
	-s,--save FILENAME:	saves results to file FILENAME
		JSON format - FILENAME should contain the JSON extension
Examples:
	./p2a -v ./pcap_files/some_pcap_file.pcapng
	./p2a --exclude mac,ttl --verbose my-pcap-file.pcap -s results.json
```

I just added the option to save all results to a JSON file. To do so, one can use the `--save file.json` option. It saves all sessions in this file, whether ambiguities were found in them or not. I am currently working on a way to render the JSON file nicely in an HTML file (using some JavaScript)..

#### Other scripts

__`SHA(IP, Port)`__

We made the `sha` script available for debug purposes. It takes as argument an IP address and a port number and returns the SHA1 hash of (IP|Port). This value is used as *session identifier* in the `p2a` script.

```sh
make sha

./sha -h
Usage:
./sha IP PORT

./sha 127.0.0.1 12345
IP:   127.0.0.1
Port: 12345
SHA1: 21bf549a8095063f49cff573e689b6b10365f4c8
```

__IP addresses and `whois`__

If one session is suspicious, it can be useful to know what it relates to. To do so, one can use Wireshark and apply a display filter to only display the given session.

A simpler approach can be to use [`whois`](https://whois.icann.org/en) to know who owns the IP address.

To use `whois` with all of the IP addresses from the capture file:

```sh
for ip in $(tshark -r file.pcapng -T fields -e ip.dst -e ip.src | egrep -o "[0-9]+.[0-9]+.[0-9]+.[0-9]+" | sort | uniq); do whois $ip | egrep "^[Oo]rgani[sz]ation"; done
```

> If `tshark` does not work, [here's a C script](https://gist.github.com/jbdrvl/eb8d8623714c60384b241ae8068a407d) that will do the same thing.

### <a name="anomalies"></a>Anomalies

#### <a name="ttl"></a>1 - TTL Expiry Attack

The **Time To Live** (TTL) field for an IP packet corresponds to how long is that packet 'allowed' to travel around the network before being dropped by routers. It is a 8-bit value that is usually reduced by one on every hop.

According to [Cisco's page on the TTL Expiry Attack](https://www.cisco.com/c/en/us/about/security-center/ttl-expiry-attack.html):

> "When an IOS device receives a packet with a TTL value of less than or equal to one, an **ICMPv4 Type 11, Code 0** message is sent by an IOS device, resulting in a **corresponding impact on the CPU**.  This impact occurs because more CPU processing is required to respond (using TTL-exceeded packets) to packets with TTL values of less than one than to simply forward a packet with a TTL value greater than one."

> "The TTL expiry behavior creates a **denial of service (DoS) attack vector** against network equipment. Network devices are purpose-built to forward ordinary packets as quickly as possible. When exception packets are encountered, such as those with expiring TTL values, varying amounts of effort are expended by a router to respond appropriately."

__Analysis/Code:__

In `utils.c`, we defined a `TTL_THRESHOLD` (=10 for now). If the TTL for a packet is lower than this value, a flag is raised to indicate that the TTL is low. If too many such flags are raised, it could be a TTL Expiry Attack.

The [sample pcap file](https://github.com/CedricOL07/pcap_tcp_analyser/blob/master/pcap_files/low_ttl_sample.pcapng) (containing a packet with a low TTL) was captured using the scripts located in the `./attack_scripts/low_ttl` directory.

#### <a name="arp-poisoning"></a>2 - ARP Poisoning

ARP Poisoning consists in fooling a host in believing we are the *default gateway*. The victim regularly asks the *default gateway* its MAC address (ARP protocol). But an attacker can send the victim packets saying that the *default gateway* is at another MAC address (the attack's MAC address for example). The attacker just needs to send those packets "regularly enough" so that the victim "discards" the real messages from the *default gateway*.

This can allow the attacker to proceed and attack the victim in many ways: man-in-the-midde, DoS, black-hole, ...
* MitM: the attacker redirects the traffic from the victim to the real *default gateway* and vice-versa. That way it can sniff the victim's traffic. It can also modify the packets (active man-in-the-middle).
* Black-hole: the attacker does not process the packets it gets from the victim: the victim cannot connect to the Internet anymore.

**Example:**

The victim's IP address is `192.168.10.2` and the *default gateway* is at `192.168.1.1`:

```sh
sudo arpspoofing -i wlan0 -t 192.168.10.2 192.169.1.1
```

The attacker will keep on sending the victim ARP packets telling that `192.168.1.1` is at the attacker's MAC address. That way the victim will send its packets (aiming for the Internet) to the attacker, who does not redirect them (`-r` option to redirect them).

__Analysis/Code:__

For the analysis, since we are only looking at IP packets (for now), `p2a` saves in a *linked list* all pairs `(MAC address, IP address)` that it encounters. When checking a new given pair, it goes through the linked list and returns an error if the IP address is already associated to another MAC address.

For the example above, our script would detect that `192.168.1.1` (*default gateway*) is associated to two different MAC addresses: the real one, until the attacker comes in and tell the victim that it is the *default gateway* and that its MAC address gets associated to the *default gateway* (from the victim's point of vue).

#### <a name="tcp-retransmission"></a>3 - TCP Retransmission

Each byte of data sent in a TCP connection has an associated *sequence number*. This is indicated on the sequence number field of the *TCP header*.

When the receiving socket detects an incoming segment of data, it uses the *acknowledgement number* in the TCP header to indicate receipt. After sending a packet of data, the sender will start a retransmission timer of variable length. If it does not receive an acknowledgment before the timer expires, the sender will assume the segment has been lost and will retransmit it.

We can see **TCP retransmission** when another packet owns the same acknowledgment and sequence numbers as the current packet.

> TCP Retransmissions are quite common and can be totally normal (if one packet is retransmitted because it was legitimately lost), but can also be the sign of an issue on the network or on a communication.

#### <a name="overlapping-fragments"></a>4 - Overlapping Fragments

The **IP fragment overlapped** exploit occurs when two fragments contained within the *same IP packet* have offsets that indicate that they **overlap** each other in positioning within the packet. This could mean that either fragment A is being *completely* overwritten by fragment B, or that fragment A is *partially* being overwritten by fragment B. Some operating systems do not properly handle fragments that overlap in this manner and may throw exceptions or behave in other undesirable ways upon receipt of overlapping fragments. This is the basis for the **teardrop attack**. (*from Wikipedia*)

Overlapping fragments may also be used in an attempt to **bypass Intrusion Detection Systems**. In this exploit, part of an attack is sent in fragments along with additional random data; future fragments may overwrite the random data with the remainder of the attack. If the completed packet is not properly reassembled at the IDS, the attack will go undetected.

> __Teardrop attack:__ involves sending mangled IP fragments with overlapping, oversized payloads to the target machine.

> NOT IMPLEMENTED YET

#### <a name="multiple-ttl"></a>5 - Multiple TTL values

If we observe multiple TTL values for a given session, it could mean that the route has changed, meaning that the packets do not follow the same path as the end of the connection as they did at the beginning. This could be due to outside genuine changes but could also mean an attacker changes the route the packets take (to do a MiTM attack for example).

However, most of the time, one session has two or three different TTL values throughout the whole connection: most of the time, the client and the server do not use the same initial TTL values.

The script returns an error if there are more than two different TTL values for a given session.


### <a name="dir"></a>Project directories

| Directory | Description/content  |
| :------------- | :------------- |
| `./attack_scripts` | Simple scripts to test and record some TCP ambiguities (spoofing, low TTL) |
| `./pcap_files` | PCAP files to test `p2a` |
| `./tests_libpcap` | Two scripts to test and start using `libpcap` |

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

### TCP Analysis
* [Packet Reassembly - Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html#ChAdvReassemblyTcp)
* [TCP Analysis - Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)

### TTL Expiry Attack
* [TTL - Wikipedia](https://en.wikipedia.org/wiki/Time_to_live)
* [TTL Expiry Attack Identification and Mitigation - CISCO](https://www.cisco.com/c/en/us/about/security-center/ttl-expiry-attack.html)

### TCP Retransmission

* [TCP - Retransmission](https://www.performancevision.com/blog/network-packet-loss-retransmissions-and-duplicate-acknowledgements/)

### Teardrop
* [IP fragment overlapped- Wikipedia](https://en.wikipedia.org/wiki/IP_fragmentation_attack)
* [Tear Drop Attack - Wikipedia](https://en.wikipedia.org/wiki/Denial-of-service_attack#Teardrop_attacks)
