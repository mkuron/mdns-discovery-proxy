#!/usr/bin/env python3

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange, DNSQuestion, DNSOutgoing, RecordUpdateListener, _TYPE_A, _CLASS_IN, _FLAGS_QR_QUERY
import sys
import time
from twisted.internet import reactor, defer, threads
from twisted.names import client, dns, error, server
from twisted.python import log
import socket

domain = sys.argv[1]
port = int(sys.argv[2])
ttl = 120
timeout = 2

class DynamicResolver(object):
    def __init__(self):
        self.zeroconf = Zeroconf(ip_version=4)
    
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
            
            answers = []
            for service in services:
                answers.append(dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.PTR, payload=dns.Record_PTR(
                    name=service[:-6] + domain
                )))
            return answers, [], []
        
        def txt(localname):
            info = self.zeroconf.get_service_info(localname, localname)
            
            data = [b"%s=%s" % (p, info.properties[p]) for p in info.properties]
            answers = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.TXT, payload=dns.Record_TXT(
                   *data
                ))]
            return answers, [], []
        
        def srv(localname):
            info = self.zeroconf.get_service_info(localname, localname)
            
            answers = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.SRV, payload=dns.Record_SRV(
                    info.priority, info.weight, info.port, info.server[:-6] + domain
                ))]
            additional = [dns.RRHeader(name=info.server[:-6] + domain, ttl=ttl, type=dns.A, payload=dns.Record_A(
                    socket.inet_ntop(socket.AF_INET, addr)
                )) for addr in info.addresses]
            
            return answers, [], additional
        
        def host(localname):
            class listener(RecordUpdateListener):
                def __init__(self):
                    self.addrs = []
                    self.time = time.time()
                def update_record(self, zc, now, record):
                    if record.type == _TYPE_A and len(record.address) == 4:
                        self.addrs.append(socket.inet_ntop(socket.AF_INET, record.address))
            
            l = listener()
            q = DNSQuestion(localname, _TYPE_A, _CLASS_IN)
            self.zeroconf.add_listener(l, q)
            out = DNSOutgoing(_FLAGS_QR_QUERY)
            out.add_question(q)
            self.zeroconf.send(out)
            while len(l.addrs) == 0 and time.time() - l.time < timeout:
                time.sleep(0.1)
            self.zeroconf.remove_listener(l)
            
            answers = [dns.RRHeader(name=query.name.name, ttl=ttl, type=dns.A, payload=dns.Record_A(
                    addr
                )) for addr in l.addrs]
            
            return answers, [], []
        
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
        elif query.type != dns.AAAA:
            print("Unsupported request", query)
        d.callback(([], [], []))
        return d

    def query(self, query, timeout=None):
        if self._dynamicResponseRequired(query):
            return self._doDynamicResponse(query)
        else:
            return defer.fail(error.DomainError())

def main():
    factory = server.DNSServerFactory(
        clients=[DynamicResolver()],
        verbose=0
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(port, protocol)
    reactor.listenTCP(port, factory)

    log.startLogging(sys.stdout)
    reactor.run()

if __name__ == '__main__':
    raise SystemExit(main())
