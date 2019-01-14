# Capturing a low TTL packet

* [Setup](#setup)
* [Code](#code)
* [Using netcat](#netcat)

The goal here is to capture a simple TCP communication with at least one packet with an abnormally low TTL value.

TCP packets with low TTL values can be used in [TTL Expiry Attacks](https://github.com/CedricOL07/pcap_tcp_analyser#ttl).

## <a name="setup"></a>Setup

There is a server running on port 7777, which sends back the messages it gets after switching all letters to uppercase. So if the client sends in `"Hello"`, the server sends back `"HELLO"`.

The whole setup is done to have an attacker send in a packet with a low TTL value. To do so, we chose to use a *TCP spoofing* technique to have the attacker use the client's information (source port, seq/ack numbers...) to send a packet to the server.

> We recorded the whole exchange in the `low_ttl_sample.pcapng` file.

```
[Client] Sent: Hello, this is the client!
[Server] Received: b'Hello, this is the client!'
[Server] Sent: b'HELLO, THIS IS THE CLIENT!'
[Client] Received: HELLO, THIS IS THE CLIENT!
[Atcker] Sent packet with low TTL to server.
[Server] Received: b'This is an attack, look at my TTL!'
[Server] Sent: b'THIS IS AN ATTACK, LOOK AT MY TTL!'
```

## <a name="code"></a>Code

The client and the server are simple scripts that we coded using Python `sockets`. For the attacker, we used `scapy`. On top of these three Python scripts, we added a shell script `main.sh` to manage them all (and to use `tshark` to get the client's source port, seq/ack numbers..).

To run:

```sh
sudo ./main.sh
```

> `scapy` requires the script to run with `sudo`.

### scapy

The attacker's script requires the latest `scapy` package (`scapy3k`). To get it:

```sh
sudo pip3 install scapy-python3
```

## <a name="netcat"></a>Using `netcat`

Some versions of `netcat` have an option to specify the TTL we want our packets to have, in which case we can easily simplify our whole setup:

* Server:

```sh
nc -l -M 5 5555
```

* Client:

```sh
nc -M 5 127.0.0.1 5555
```

The `-M` option is only on the OpenBSD version of `netcat`. To get it: `apt-get install netcat-openbsd`
