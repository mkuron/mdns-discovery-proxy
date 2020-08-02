#!/usr/bin/env python3

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
import sys
import time
from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server
from twisted.python import log

domain = sys.argv[1]
port = int(sys.argv[2])

class DynamicResolver(object):
    def _dynamicResponseRequired(self, query):
        if str(query.name).endswith(domain):
            return True

        return False

    def _doDynamicResponse(self, query):
        if query.type == dns.SOA:
            return [], [], []
        
        localname = str(query.name)[:-len(domain)] + "local."
        
        services = []
        def handler(zeroconf, service_type, name, state_change):
            if state_change is ServiceStateChange.Added:
                services.append(name)
        
        answers = []
        if query.type == dns.PTR:
            zeroconf = Zeroconf(ip_version=4)
            sb = ServiceBrowser(zeroconf, localname, [handler])
            time.sleep(2) # TODO: non-blocking
            sb.cancel()
            for service in services:
                answers.append(dns.RRHeader(name=query.name.name, type=query.type, payload=dns.Record_PTR(
                    name=service[:-6] + domain
                )))
        else:
            # TODO: other types
            print(query)
        
        return answers, [], []

    def query(self, query, timeout=None):
        if self._dynamicResponseRequired(query):
            return defer.succeed(self._doDynamicResponse(query))
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
