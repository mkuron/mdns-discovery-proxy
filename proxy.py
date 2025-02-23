#!/usr/bin/env python3

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange, ServiceInfo, DNSQuestion, DNSOutgoing, RecordUpdateListener, IPVersion
from zeroconf.const import _TYPE_A, _TYPE_AAAA, _CLASS_IN, _FLAGS_QR_QUERY
import sys
import time
from twisted.internet import reactor, defer, threads
from twisted.names import client, dns, error, server
from twisted.python import log
import socket
import ipaddress

if len(sys.argv) < 3:
    sys.exit("Usage: {} <domain> <port> [filter cidr...]".format(sys.argv[0]))

domain = sys.argv[1]
port = int(sys.argv[2])

ip_range_filters = [ipaddress.ip_network(cidr) for cidr in sys.argv[3:]]
filters_v4 = [ip for ip in ip_range_filters if ip.version == 4]
filters_v6 = [ip for ip in ip_range_filters if ip.version == 6]

# if some filters are provided, only IPs in those ranges will be returned

if filters_v4:
    print("IPv4 filter:", filters_v4)
if filters_v6:
    print("IPv6 filter:", filters_v6)

ttl = 60
timeout = 2

class DynamicResolver(object):
    def __init__(self):
        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
    
    def _dynamicResponseRequired(self, query):
        if str(query.name).endswith(domain):
            return True

        return False

    def _doDynamicResponse(self, query):
        if query.type == dns.SOA:
            return defer.succeed(([], [], []))
        
        localname = str(query.name)[:-len(domain)] + "local."
        
        def browse(localname):
            services = []
            def handler(zeroconf, service_type, name, state_change):
                if state_change is ServiceStateChange.Added:
                    services.append(name)
            
            sb = ServiceBrowser(self.zeroconf, localname, [handler])
            time.sleep(timeout)
            sb.cancel()
            
            answers, additional = [], []
            for service in services:
                answers.append(dns.RRHeader(name=localname[:-6] + domain, ttl=ttl, type=dns.PTR, payload=dns.Record_PTR(
                    name=service[:-6] + domain
                )))
                #txt_ans, _, _ = txt(service)
                #srv_ans, _, a_ans = srv(service)
                #additional += a_ans + txt_ans + srv_ans
            return answers, [], additional

        def txt(localname):
            if localname.endswith('._device-info._tcp.local.'):
                info = ServiceInfo(localname, localname)
                info.request(self.zeroconf, timeout*1000)
                if not info.text:
                    return [], [], []
            else:
                info = self.zeroconf.get_service_info(localname, localname, timeout*1000)
                if info is None:
                    return [], [], []
            
            order = []
            i = 0
            while i < len(info.text):
                length = info.text[i]
                i += 1
                kv = info.text[i : i + length].split(b'=')
                order.append(kv[0])
                i += length
            
            data = [b"%s=%s" % (p, info.properties[p] if info.properties[p] is not None else b"") for p in sorted(info.properties, key=lambda k: order.index(k) if k in order else 1000)]
            answers = [dns.RRHeader(name=localname[:-6] + domain, ttl=ttl, type=dns.TXT, payload=dns.Record_TXT(
                   *data
                ))]
            return answers, [], []
        
        def srv(localname):
            info = self.zeroconf.get_service_info(localname, localname, timeout*1000)
            if info is None:
                return [], [], []
            
            answers = [dns.RRHeader(name=localname[:-6] + domain, ttl=ttl, type=dns.SRV, payload=dns.Record_SRV(
                    info.priority, info.weight, info.port, info.server[:-6] + domain
                ))]
            additional = [dns.RRHeader(name=info.server[:-6] + domain, ttl=ttl, type=dns.A, payload=dns.Record_A(
                    socket.inet_ntop(socket.AF_INET, addr)
                )) for addr in info.addresses_by_version(IPVersion.V4Only)]
            additional += [dns.RRHeader(name=info.server[:-6] + domain, ttl=ttl, type=dns.AAAA, payload=dns.Record_AAAA(
                    socket.inet_ntop(socket.AF_INET6, addr)
                )) for addr in info.addresses_by_version(IPVersion.V6Only)]
            return answers, [], additional

        class listener(RecordUpdateListener):
            def __init__(self):
                self.addr4s = set()
                self.addr6s = set()
                self.time = time.time()
            def update_record(self, zc, now, record):
                if record.type == _TYPE_A and len(record.address) == 4:
                    self.addr4s.add(socket.inet_ntop(socket.AF_INET, record.address))
                if record.type == _TYPE_AAAA and len(record.address) == 16:
                    self.addr6s.add(socket.inet_ntop(socket.AF_INET6, record.address))
            @property
            def ipv4_addresses(self) -> list[str]:
                ips = [ip for ip in map(ipaddress.ip_address, self.addr4s) if not ip.is_loopback]
                if filters_v4:
                    ips = [ip for ip in ips if any(ip in net for net in filters_v4)]
                return [str(ip) for ip in ips]
            @property
            def ipv6_addresses(self) -> list[str]:
                ips = [ip for ip in map(ipaddress.ip_address, self.addr6s) if not ip.is_loopback]
                if filters_v6:
                    ips = [ip for ip in ips if any(ip in net for net in filters_v6)]
                return [str(ip) for ip in ips]

        def host(localname):
            l = listener()
            q = DNSQuestion(localname, _TYPE_A, _CLASS_IN)
            self.zeroconf.add_listener(l, q)
            out = DNSOutgoing(_FLAGS_QR_QUERY)
            out.add_question(q)
            self.zeroconf.send(out)
            while len(l.addr4s) == 0 and time.time() - l.time < timeout:
                time.sleep(0.1)
            self.zeroconf.remove_listener(l)

            answers = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.A, payload=dns.Record_A(
                    addr
                )) for addr in l.ipv4_addresses]

            extra = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.AAAA, payload=dns.Record_AAAA(
                    addr
                )) for addr in l.ipv6_addresses]

            return answers, [], extra

        def host6(localname):
            l = listener()
            q = DNSQuestion(localname, _TYPE_AAAA, _CLASS_IN)
            self.zeroconf.add_listener(l, q)
            out = DNSOutgoing(_FLAGS_QR_QUERY)
            out.add_question(q)
            self.zeroconf.send(out)
            while len(l.addr6s) == 0 and time.time() - l.time < timeout:
                time.sleep(0.1)
            self.zeroconf.remove_listener(l)

            answers = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.AAAA, payload=dns.Record_AAAA(
                    addr
                )) for addr in l.ipv6_addresses]

            extra = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.A, payload=dns.Record_A(
                    addr
                )) for addr in l.ipv4_addresses]

            return answers, [], extra
        
        d = defer.Deferred()
        
        if query.type == dns.PTR:
            d = threads.deferToThread(browse, localname)
            return d
        elif query.type == dns.TXT:
            d = threads.deferToThread(txt, localname)
            return d
        elif query.type == dns.SRV:
            d = threads.deferToThread(srv, localname)
            return d
        elif query.type == dns.A:
            d = threads.deferToThread(host, localname)
            return d
        elif query.type == dns.AAAA:
            d = threads.deferToThread(host6, localname)
            return d
        else:
            print("Unsupported request", query)
        d.callback(([], [], []))
        return d

    def query(self, query, timeout=None):
        if self._dynamicResponseRequired(query):
            return self._doDynamicResponse(query)
        else:
            return defer.fail(error.DomainError())

class TruncatingDNSDatagramProtocol(dns.DNSDatagramProtocol):
    def writeMessage(self, message, address):
        if type(message) is dns.Message and len(message.toStr()) > 512:
            message.additional = []
            if len(message.toStr()) > 512:
                message.trunc = 1
                message.answers = []
        dns.DNSDatagramProtocol.writeMessage(self, message, address)

def main():
    factory = server.DNSServerFactory(
        clients=[DynamicResolver()],
        verbose=1
    )

    protocol = TruncatingDNSDatagramProtocol(controller=factory)

    reactor.listenUDP(port, protocol)
    reactor.listenTCP(port, factory)

    log.startLogging(sys.stdout)
    reactor.run()

if __name__ == '__main__':
    raise SystemExit(main())
