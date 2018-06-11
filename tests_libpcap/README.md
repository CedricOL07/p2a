# Simple tests on `libpcap`

Those are just simple tests we found to get used to coding with `libpcap` (or `pcapplusplus`). They are not used in our project but can be interesting to anyone willing to get started with `libpcap`/`pcapplusplus`.

## Importing and testing the `libpcap` library

```sh
make ldev
```

* [Source](http://yuba.stanford.edu/~casado/pcap/section1.html)

## Opening and processing a `pcap` file

```sh
make open.out
./open.out ../pcap_files/some_pcap_file.pcapng
```

* [Source](http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/)
