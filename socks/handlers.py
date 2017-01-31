"""
SocksiPy + urllib.request handler

This module provides a Handler which you can use with urllib.request
to allow it to tunnel your connection through a socks.sockssocket socket,
with out monkey patching the original socket...
"""

import base64
import urllib.request

from . import socks

try:
    from requests.packages.urllib3.connection import HTTPConnection, HTTPSConnection

except ImportError:
    import ssl
    import socket
    import http.client


    class HTTPConnection(http.client.HTTPConnection):
        def __init__(self, *args, **kw):
            kw.pop('strict')  # works only in Python2, removed from Py3.4
            super().__init__(*args, **kw)

        def _new_conn(self):
            raise NotImplementedError

        def connect(self):
            self.sock = self._new_conn()


    class HTTPSConnection(HTTPConnection, http.client.HTTPSConnection):
        def connect(self):
            """Connect to a host on a given (SSL) port.

            Note: Whole copy of original method, except initial socket creation
            """

            sock = self._new_conn()

            if self._tunnel_host:
                self.sock = sock
                self._tunnel()

            server_hostname = self.host if ssl.HAS_SNI else None
            self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)
            try:
                if self._check_hostname:
                    ssl.match_hostname(self.sock.getpeercert(), self.host)
            except Exception:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
                raise


class ProxyHTTPConnection(HTTPConnection):
    def __init__(self, *args, chain=(), **kw):
        super().__init__(*args, **kw)
        self.routes = socks.RoutingTable.from_addresses(chain, dst=self.host)

    def _new_conn(self):
        sock = socks.socksocket(routes=self.routes)

        if type(self.timeout) in (int, float):
            sock.settimeout(self.timeout)

        sock.connect((self.host, self.port))

        return sock


class ProxyHTTPSConnection(ProxyHTTPConnection, HTTPSConnection):
    pass


class ChainProxyHandler(urllib.request.HTTPHandler, urllib.request.HTTPSHandler, urllib.request.ProxyHandler):
    def __init__(self, chain=()):
        super().__init__()

        last_hop = chain and socks.parse_proxy(chain[-1]) or None

        self.chain = chain
        self._last_hop = last_hop  # cache last hop info for internal checks

    def is_chain_http_end(self):
        if self._last_hop is None:
            return False
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
