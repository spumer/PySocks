import urllib.parse

import requests.auth
import requests.utils

from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from requests.packages.urllib3.poolmanager import PoolManager, SSL_KEYWORDS
from requests.packages.urllib3.connection import HTTPConnection
from requests.packages.urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from . import socks
from . import handlers


class ProxyHTTPConnection(handlers.ProxyHTTPConnection, HTTPConnection):
    pass


class ProxyHTTPSConnection(handlers.ProxyHTTPSConnection, HTTPConnection):
    pass


class ProxyHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = ProxyHTTPConnection


class ProxyHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = ProxyHTTPSConnection


class ProxyConnectionPool(PoolManager):
    pool_classes_by_scheme = {
        'http': ProxyHTTPConnectionPool,
        'https': ProxyHTTPSConnectionPool,
    }

    def _new_pool(self, scheme, host, port):
        pool_cls = self.pool_classes_by_scheme[scheme]

        kwargs = self.connection_pool_kw
        if scheme == 'http':
            kwargs = self.connection_pool_kw.copy()
            for kw in SSL_KEYWORDS:
                kwargs.pop(kw, None)

        return pool_cls(host, port, **kwargs)


class ChainedProxyHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, chain=(), **kw):
        last_hop = chain and socks.parse_proxy(chain[-1]) or None

        self.chain = chain
        self._last_hop = last_hop  # cache last hop info for internal checks

        super().__init__(*args, **kw)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        # save these values for pickling
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = ProxyConnectionPool(
            num_pools=connections, maxsize=maxsize,
            block=block, strict=True, chain=self.chain, **pool_kwargs
        )

    def is_chain_http_end(self):
        return self._last_hop.type == socks.PROXY_TYPE_HTTP

    def add_headers(self, request, **kwargs):
        super().add_headers(request, **kwargs)

        if self.is_chain_http_end():
            parsed = urllib.parse.urlparse(request.url)

            request.headers['Accept'] = '*/*'
            request.headers['Host'] = parsed.netloc

            last_hop = self._last_hop
            if last_hop.username and last_hop.password:
                requests.auth.HTTPProxyAuth(
                    last_hop.username, last_hop.password
                )(request)

    def request_url(self, request, proxies):
        if self.is_chain_http_end():
            url = requests.utils.urldefragauth(request.url)
        else:
            url = request.path_url

        return url

    def get_connection(self, url, proxies=None):
        if proxies:
            raise NotImplementedError

        parsed = urllib.parse.urlparse(url)
        url = parsed.geturl()
        return self.poolmanager.connection_from_url(url)


def main():
    chain = [
        'tor://localhost/',
        'http://31.7.232.102:3128',
    ]

    session = requests.Session()
    session.mount('http://', ChainedProxyHTTPAdapter(chain=chain))
    session.mount('https://', ChainedProxyHTTPAdapter(chain=chain))

    resp = session.get('http://httpbin.org/ip')
    print("HTTP" + resp.text)

    resp = session.get('https://httpbin.org/ip')
    print("HTTPS" + resp.text)


if __name__ == '__main__':
    main()
