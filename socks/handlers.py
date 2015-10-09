"""
SocksiPy + urllib.request handler

This module provides a Handler which you can use with urllib.request
to allow it to tunnel your connection through a socks.sockssocket socket,
with out monkey patching the original socket...
"""

import ssl
import base64
import http.client
import urllib.request

from . import socks


class ProxyHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, chain=(), **kw):
        super().__init__(*args, **kw)

        routes = socks.RoutingTable.from_default()

        for hop in chain:
            routes.append_proxy(self.host, *socks.parse_proxy(hop))

        self.routes = routes

    def connect(self):
        sock = socks.socksocket(routes=self.routes)

        if type(self.timeout) in (int, float):
            sock.settimeout(self.timeout)

        sock.connect((self.host, self.port))

        self.sock = sock


class ProxyHTTPSConnection(ProxyHTTPConnection, http.client.HTTPSConnection):
    def connect(self):
        super().connect()
        self.sock = ssl.wrap_socket(self.sock, self.key_file, self.cert_file)


class ChainProxyHandler(urllib.request.HTTPHandler, urllib.request.HTTPSHandler, urllib.request.ProxyHandler):
    def __init__(self, chain=()):
        super().__init__()

        last_hop = chain and socks.parse_proxy(chain[-1]) or None

        self.chain = chain
        self._last_hop = last_hop  # cache last hop info for internal checks

    def is_chain_http_end(self):
        return self._last_hop.type == socks.PROXY_TYPE_HTTP

    def _create_http_conn(self, *args, **kw):
        return ProxyHTTPConnection(*args, chain=self.chain, **kw)

    def _create_https_conn(self, *args, **kw):
        return ProxyHTTPSConnection(*args, chain=self.chain, **kw)

    @staticmethod
    def install_http_proxy(req, proxy):
        if proxy.username and proxy.password:
            user_pass = '%s:%s' % (proxy.username, proxy.password)
            creds = base64.b64encode(user_pass.encode()).decode("ascii")
            req.add_header('Proxy-authorization', 'Basic ' + creds)

        host_port = '%s:%s' % (proxy.addr, proxy.port)
        proxy_type = socks.PRINTABLE_PROXY_TYPES[proxy.type]

        req.set_proxy(host_port, proxy_type)

    def http_open(self, req):
        if self.is_chain_http_end():
            self.install_http_proxy(req, self._last_hop)
        return self.do_open(self._create_http_conn, req)

    def https_open(self, req):
        if self.is_chain_http_end():
            self.install_http_proxy(req, self._last_hop)
        return self.do_open(self._create_https_conn, req)


if __name__ == "__main__":
    chain = [
        'tor://localhost/',
    ]

    opener = urllib.request.build_opener(ChainProxyHandler(chain=chain))
    print("HTTP: " + opener.open("http://httpbin.org/ip").read().decode())
    print("HTTPS: " + opener.open("https://httpbin.org/ip").read().decode())
