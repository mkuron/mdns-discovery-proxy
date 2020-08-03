This is a **Discovery Proxy for Multicast DNS-Based Service Discovery**, written in pure Python. It makes use of [zeroconf](https://pypi.org/project/zeroconf/) to obtain mDNS advertisements on the local network and [Twisted](https://pypi.org/project/Twisted/) to re-publish them as a unicast DNS service.

This kind of proxy is specified by [RFC 8766](https://tools.ietf.org/html/rfc8766). I did not actually follow the standard in implementing it, which means that it doesn't abide by many of the finder details. Nevertheless, it works fine with clients like macOS 10.15 and iOS 13. Any violations of the standard are to be considered bugs and should be fixed over time.

Other implementations of discovery proxies are [ohybridproxy](https://github.com/sbyx/ohybridproxy) and [included with mDNSResponder](https://opensource.apple.com/source/mDNSResponder/mDNSResponder-1096.60.2/ServiceRegistration/dnssd-proxy.c.auto.html). Since the former only runs on OpenWRT and mDNSResponder is not readily available on Linux, I decided to put together my own implementation in Python. Its dependencies are pure Python, so it should be possible to run it pretty much anywhere.

To use the discovery proxy, run it while specifying a domain to use and a port number to listen on:

```bash
python3 proxy.py home.arpa 35353
```

Then, delegate that domain to the machine the proxy is running on (_192.0.2.2_ in the example below) and advertise it by adding the necessary records to your network's DNS search domain (_example.com_ in the example below). If you are using dnsmasq, this can be done using

```
server=/home.arpa/192.0.2.2#35353
ptr-record=b._dns-sd._udp.example.com,home.arpa
ptr-record=lb._dns-sd._udp.example.com,home.arpa
ptr-record=db._dns-sd._udp.example.com,home.arpa
```

To check whether it is working, you can try some of the following queries (assuming your computer is named _yourcomputer_ and advertises an SSH service):
```bash
dig yourcomputer.home.arpa
dig _ssh._tcp.home.arpa ptr
dig yourcomputer._ssh._tcp.home.arpa srv
```
