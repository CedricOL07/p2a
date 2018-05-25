# Simple tests on `libpcap`

Those are just simple tests we found to get used to coding with `libpcap` (or `pcapplusplus`).

## Test 1 - `ldev.c`

Just importing and testing the `libpcap` library:

```sh
make ldev
```

* [Source](http://yuba.stanford.edu/~casado/pcap/section1.html)

## Test 2 - `open_file.cpp`

Opens and processes a `pcap` file:

```sh
make open.out
./open.out ../pcap_files/test_pcap_file.pcapng
```

* [Source](http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/)
