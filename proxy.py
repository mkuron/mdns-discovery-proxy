#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import sys
import time
from twisted.internet import reactor, defer, threads
from twisted.names import client, dns, error, server
from twisted.python import log
from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange, ServiceInfo, DNSQuestion, DNSOutgoing, RecordUpdateListener, IPVersion
from zeroconf.const import _TYPE_A, _TYPE_AAAA, _CLASS_IN, _FLAGS_QR_QUERY

parser = argparse.ArgumentParser(description='mDNS Discovery Proxy')
parser.add_argument('domain', type=str, help='Domain name to handle')
parser.add_argument('port', type=int, nargs='?', default=35353, help='Port number to listen on (default: 35353)')

parser.add_argument('--ttl', type=int, default=10, help='DNS TTL (default: 10)')
parser.add_argument('--timeout', type=int, default=2, help='Timeout (default: 2)')
parser.add_argument('--allow-ranges', nargs='*', type=ipaddress.ip_network, default=[], help='Allow only IPs in these ranges')
parser.add_argument('--log-level', type=int, choices=[0, 1, 2], default=1, help='Log level')

parser.add_argument('--suppress-loopback', default=True, action=argparse.BooleanOptionalAction, help='Suppress loopback addresses (default: True)')
parser.add_argument('--suppress-link-local', default=True, action=argparse.BooleanOptionalAction, help='Suppress link-local addresses (default: True)')

args = parser.parse_args()

filters_v4 = [ip for ip in args.allow_ranges if ip.version == 4]
filters_v6 = [ip for ip in args.allow_ranges if ip.version == 6]

def print_args():
    print(f"Starting mDNS Discovery Proxy for {args.domain} on port {args.port}")
    print(f"DNS TTL: {args.ttl}, Query Timeout: {args.timeout}")

    suppress = []
    if args.suppress_loopback:
        suppress.append("loopback")
    if args.suppress_link_local:
        suppress.append("link-local")
    if suppress:
        print(f"Suppressing {' and '.join(suppress)} addresses from responses")

    if filters_v4:
        print("Only returning IPv4 addresses in ranges:", ', '.join(map(str, filters_v4)))
    elif filters_v6:
        print("Returning all IPv4 addresses (unless suppressed by other options)")
    if filters_v6:
        print("Only returning IPv6 addresses in ranges:", ', '.join(map(str, filters_v6)))
    elif filters_v4:
        print("Returning all IPv6 addresses (unless suppressed by other options)")
    
    print()

print_args()

class DynamicResolver(object):
    def __init__(self):
        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
    
    def _dynamicResponseRequired(self, query):
        if str(query.name).endswith(args.domain):
            return True

        return False

    def _doDynamicResponse(self, query):
        if query.type == dns.SOA:
            return defer.succeed(([], [], []))
        
        localname = str(query.name)[:-len(args.domain)] + "local."
        
        def browse(localname):
            services = []
            def handler(zeroconf, service_type, name, state_change):
                if state_change is ServiceStateChange.Added:
                    services.append(name)
            
            sb = ServiceBrowser(self.zeroconf, localname, [handler])
            time.sleep(args.timeout)
            sb.cancel()
            
            answers, additional = [], []
            for service in services:
                answers.append(dns.RRHeader(name=localname[:-6] + args.domain, ttl=args.ttl, type=dns.PTR, payload=dns.Record_PTR(
                    name=service[:-6] + args.domain
                )))
                #txt_ans, _, _ = txt(service)
                #srv_ans, _, a_ans = srv(service)
                #additional += a_ans + txt_ans + srv_ans
            return answers, [], additional

        def txt(localname):
            if localname.endswith('._device-info._tcp.local.'):
                info = ServiceInfo(localname, localname)
                info.request(self.zeroconf, args.timeout*1000)
                if not info.text:
                    return [], [], []
            else:
                info = self.zeroconf.get_service_info(localname, localname, args.timeout*1000)
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
            answers = [dns.RRHeader(name=localname[:-6] + args.domain, ttl=args.ttl, type=dns.TXT, payload=dns.Record_TXT(
                   *data
                ))]
            return answers, [], []
        
        def srv(localname):
            info = self.zeroconf.get_service_info(localname, localname, args.timeout*1000)
            if info is None:
                return [], [], []
            
            answers = [dns.RRHeader(name=localname[:-6] + args.domain, ttl=args.ttl, type=dns.SRV, payload=dns.Record_SRV(
                    info.priority, info.weight, info.port, info.server[:-6] + args.domain
                ))]
            additional = [dns.RRHeader(name=info.server[:-6] + args.domain, ttl=args.ttl, type=dns.A, payload=dns.Record_A(
                    socket.inet_ntop(socket.AF_INET, addr)
                )) for addr in info.addresses_by_version(IPVersion.V4Only)]
            additional += [dns.RRHeader(name=info.server[:-6] + args.domain, ttl=args.ttl, type=dns.AAAA, payload=dns.Record_AAAA(
                    socket.inet_ntop(socket.AF_INET6, addr)
                )) for addr in info.addresses_by_version(IPVersion.V6Only)]
            return answers, [], additional

        class listener(RecordUpdateListener):
            def __init__(self):
                self.raw_addr4s = set()
                self.raw_addr6s = set()
                self.time = time.time()
            def update_record(self, zc, now, record):
                if record.type == _TYPE_A and len(record.address) == 4:
                    self.raw_addr4s.add(socket.inet_ntop(socket.AF_INET, record.address))
                if record.type == _TYPE_AAAA and len(record.address) == 16:
                    self.raw_addr6s.add(socket.inet_ntop(socket.AF_INET6, record.address))

            @staticmethod
            def _is_suppressed(ip: (ipaddress.IPv4Address | ipaddress.IPv6Address)) -> bool:
                if ip.is_loopback and args.suppress_loopback:
                    return True
                if ip.is_link_local and args.suppress_link_local:
                    return True
                return False

            @property
            def ipv4_addresses(self) -> list[str]:
                ips = [ip for ip in map(ipaddress.ip_address, self.raw_addr4s) if not self._is_suppressed(ip)]
                if filters_v4:
                    ips = [ip for ip in ips if any(ip in net for net in filters_v4)]
                return [str(ip) for ip in ips]
            @property
            def ipv6_addresses(self) -> list[str]:
                ips = [ip for ip in map(ipaddress.ip_address, self.raw_addr6s) if not self._is_suppressed(ip)]
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
            while len(l.raw_addr4s) == 0 and time.time() - l.time < args.timeout:
                time.sleep(0.1)
            self.zeroconf.remove_listener(l)

            answers = [dns.RRHeader(name=query.name.name, ttl=args.ttl, type=dns.A, payload=dns.Record_A(
                    addr
                )) for addr in l.ipv4_addresses]

            extra = [dns.RRHeader(name=query.name.name, ttl=args.ttl, type=dns.AAAA, payload=dns.Record_AAAA(
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
            while len(l.raw_addr6s) == 0 and time.time() - l.time < args.timeout:
                time.sleep(0.1)
            self.zeroconf.remove_listener(l)

            answers = [dns.RRHeader(name=query.name.name, ttl=args.ttl, type=dns.AAAA, payload=dns.Record_AAAA(
                    addr
                )) for addr in l.ipv6_addresses]

            extra = [dns.RRHeader(name=query.name.name, ttl=args.ttl, type=dns.A, payload=dns.Record_A(
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
        verbose=args.log_level
    )

    protocol = TruncatingDNSDatagramProtocol(controller=factory)

    reactor.listenUDP(args.port, protocol)
    reactor.listenTCP(args.port, factory)

    log.startLogging(sys.stdout)
    reactor.run()

if __name__ == '__main__':
    raise SystemExit(main())
