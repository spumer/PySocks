import socket
import struct
import base64
import collections
import urllib.parse


PROXY_TYPE_DEFAULT = -1
PROXY_TYPE_NONE = 0
PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3
PROXY_TYPE_SSL = 4
PROXY_TYPE_SSL_WEAK = 5
PROXY_TYPE_SSL_ANON = 6
PROXY_TYPE_TOR = 7
PROXY_TYPE_HTTPS = 8
PROXY_TYPE_HTTP_CONNECT = 9
PROXY_TYPE_HTTPS_CONNECT = 10


PROXY_TYPES = {
    'none': PROXY_TYPE_NONE,
    'default': PROXY_TYPE_DEFAULT,
    'defaults': PROXY_TYPE_DEFAULT,
    'http': PROXY_TYPE_HTTP,
    'httpc': PROXY_TYPE_HTTP_CONNECT,
    'socks': PROXY_TYPE_SOCKS5,
    'socks4': PROXY_TYPE_SOCKS4,
    'socks4a': PROXY_TYPE_SOCKS4,
    'socks5': PROXY_TYPE_SOCKS5,
    'tor': PROXY_TYPE_TOR,
}

PRINTABLE_PROXY_TYPES = dict(zip(PROXY_TYPES.values(), PROXY_TYPES.keys()))


# Protection of "monkey-patching". Used for right constructor calling
_orig_socket = socket.socket


class ProxyError(IOError):
    """
    socket_err contains original socket.error exception.
    """
    def __init__(self, msg, socket_err=None):
        self.msg = msg
        self.socket_err = socket_err

        if socket_err:
            self.msg += ": {0}".format(socket_err)

    def __str__(self):
        return self.msg


class GeneralProxyError(ProxyError):
    pass


class ProxyConnectionError(ProxyError):
    pass


class SOCKS5AuthError(ProxyError):
    pass


class SOCKS5Error(ProxyError):
    pass


class SOCKS4Error(ProxyError):
    pass


class HTTPError(ProxyError):
    pass


SOCKS4_ERRORS = {
    0x5B: "Request rejected or failed",
    0x5C: "Request rejected because SOCKS server cannot connect to identd on the client",
    0x5D: "Request rejected because the client program and identd report different user-ids"
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

DEFAULT_PORTS = {
    PROXY_TYPE_SOCKS4: 1080,
    PROXY_TYPE_SOCKS5: 1080,
    PROXY_TYPE_HTTP: 8080,
    PROXY_TYPE_TOR: 9050,
}

class Proxy(
    collections.namedtuple('Proxy', (
        'type', 'addr', 'port', 'rdns', 'username', 'password'
    ))
):
    def __new__(cls, type_=PROXY_TYPE_NONE, addr=None, port=None, rdns=False, username=None, password=None):
        return super().__new__(cls, type_, addr, int(port or DEFAULT_PORTS[type_]), rdns, username, password)


DEFAULT_DST = '*'


class RoutingTable:
    def __init__(self, table=None):
        if isinstance(table, RoutingTable):
            table = table.table

        if table is not None:
            table = table.copy()
        else:
            table = {
                DEFAULT_DST: [],
            }

        self.table = table

    def append_proxy(
        self, dst, proxytype=None, addr=None,
        port=None, rdns=True, username=None, password=None
    ):
        dst = dst.lower()

        if dst == DEFAULT_DST and proxytype == PROXY_TYPE_DEFAULT:
            raise ValueError("Circular reference to default proxy")

        route = self.table.get(dst, None)
        if route is None:
            # use default route as start point for any new route
            route = self.table[DEFAULT_DST].copy()

        proxy = Proxy(proxytype, addr, port, rdns, username, password)
        route.append(proxy)

        self.table[dst] = route

    def append_default_proxy(self, *args, **kwargs):
        return self.append_proxy(DEFAULT_DST, *args, **kwargs)

    def get_route(self, dst, default=DEFAULT_DST):
        dst = dst.lower()

        route = self.table.get(dst)
        if route is None:
            route = self.table[default]

        return route

    @classmethod
    def from_addresses(cls, addresses, dst=DEFAULT_DST, parent_table=DEFAULT_ROUTING_TABLE):
        obj = cls(table=parent_table)
        for addr in addresses:
            obj.append_proxy(dst, *parse_proxy(addr))
        return obj

    @classmethod
    def from_default(cls):
        return cls(table=DEFAULT_ROUTING_TABLE)


DEFAULT_ROUTING_TABLE = RoutingTable()


def parse_proxy(url, rdns=False):
    """Split url into args for `RoutingTable.add_proxy` method

    :param url: url, contains all information about proxy server see the format below
    :param rdns: True - resolve dns, False - resolve locally, just passed to return, not used here
    :return: (proxytype, addr, port, rnds, username, password)

    E.g: basic scheme is 'type://user:password@address:port/'
    'http://simple-proxy.com/' -> (3, simple-proxy.com, 8080, False, None, None)
    'SOCKS5://user:passwd@simple-proxy.com:3128/' -> (2, simple-proxy.com, 3128, False, 'user', 'passwd')
    For more examples see the types definition
    """

    if '://' not in url and not url.startswith('//'):
        # small trick to guarantee correct url parsing without scheme
        # e.g: 'simple-proxy.com:3128'
        url = '//' + url

    url_parts = urllib.parse.urlsplit(url)
    scheme, username, password, hostname, port = (
        url_parts.scheme or 'http',
        url_parts.username or None,
        url_parts.password or None,
        url_parts.hostname,
        url_parts.port,
    )

    if not scheme.islower():
        scheme = scheme.lower()

    return Proxy(PROXY_TYPES[scheme], hostname, port, rdns, username, password)



class _BaseSocket(socket.socket):
    """Allows Python 2's "delegated" methods such as send() to be overridden
    """
    def __init__(self, *pos, **kw):
        _orig_socket.__init__(self, *pos, **kw)

        self._savedmethods = dict()
        for name in self._savenames:
            self._savedmethods[name] = getattr(self, name)
            delattr(self, name)  # Allows normal overriding mechanism to work

    _savenames = list()


def _makemethod(name):
    return lambda self, *pos, **kw: self._savedmethods[name](*pos, **kw)


for name in ("sendto", "send", "recvfrom", "recv"):
    method = getattr(_BaseSocket, name, None)

    # Determine if the method is not defined the usual way
    # as a function in the class.
    # Python 2 uses __slots__, so there are descriptors for each method,
    # but they are not functions.
    if not isinstance(method, collections.Callable):
        _BaseSocket._savenames.append(name)
        setattr(_BaseSocket, name, _makemethod(name))


class socksocket(_BaseSocket):
    """socksocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET and proto=0.
    The "type" argument must be either SOCK_STREAM or SOCK_DGRAM.
    """

    def __init__(
        self, family=socket.AF_INET, type_=socket.SOCK_STREAM, proto=0, _sock=None,
        routes=None, *args, **kw
    ):

        if type_ not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            msg = "Socket type must be stream or datagram, not {!r}"
            raise ValueError(msg.format(type_))

        _BaseSocket.__init__(self, family, type_, proto, _sock, *args, **kw)

        if routes is None:
            routes = RoutingTable.from_default()

        self.routes = routes
        self.proxy_sockname = None
        self.proxy_peername = None

    def _readall(self, file, count):
        """
        Receive EXACTLY the number of bytes requested from the file object.
        Blocks until the required number of bytes have been received.
        """
        data = b""
        while len(data) < count:
            d = file.read(count - len(data))
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data

    def get_proxy_sockname(self):
        """
        Returns the bound IP address and port number at the proxy.
        """
        return self.proxy_sockname

    getproxysockname = get_proxy_sockname

    def get_proxy_peername(self):
        """
        Returns the IP and port number of the proxy.
        """
        return _BaseSocket.getpeername(self)

    getproxypeername = get_proxy_peername

    def get_peername(self):
        """
        Returns the IP address and port number of the destination
        machine (note: get_proxy_peername returns the proxy)
        """
        return self.proxy_peername

    def _get_proxy_auth_header(self, username=None, password=None):
        if username and password:
            auth = ':'.join(map(urllib.parse.unquote, (username, password)))
            return 'Proxy-Authorization: Basic %s' % base64.b64encode(auth)

        return ''

    getpeername = get_peername

    def _negotiate_SOCKS5(self, dst_addr, dst_port, proxy):
        """
        Negotiates a stream connection through a SOCKS5 server.
        """
        CONNECT = b"\x01"
        self.proxy_peername, self.proxy_sockname = self._SOCKS5_request(self,
            CONNECT, (dst_addr, dst_port), proxy)

    def _SOCKS5_request(self, conn, cmd, dst, proxy):
        """
        Send SOCKS5 request with given command (CMD field) and
        address (DST field). Returns resolved DST address that was used.
        """
        proxy_type, addr, port, rdns, username, password = proxy

        writer = conn.makefile("wb")
        reader = conn.makefile("rb", 0)  # buffering=0 renamed in Python 3
        try:
            # First we'll send the authentication packages we support.
            if username and password:
                # The username/password details were supplied to the
                # set_proxy method so we support the USERNAME/PASSWORD
                # authentication (in addition to the standard none).
                writer.write(b"\x05\x02\x00\x02")
            else:
                # No username/password were entered, therefore we
                # only support connections with no authentication.
                writer.write(b"\x05\x01\x00")

            # We'll receive the server's response to determine which
            # method was selected
            writer.flush()
            chosen_auth = self._readall(reader, 2)

            if chosen_auth[0:1] != b"\x05":
                # Note: string[i:i+1] is used because indexing of a bytestring
                # via bytestring[i] yields an integer in Python 3
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            # Check the chosen authentication method

            if chosen_auth[1:2] == b"\x02":
                # Okay, we need to perform a basic username/password
                # authentication.
                writer.write(b"\x01" + chr(len(username)).encode()
                             + username
                             + chr(len(password)).encode()
                             + password)
                writer.flush()
                auth_status = self._readall(reader, 2)
                if auth_status[0:1] != b"\x01":
                    # Bad response
                    raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
                if auth_status[1:2] != b"\x00":
                    # Authentication failed
                    raise SOCKS5AuthError("SOCKS5 authentication failed")

                # Otherwise, authentication succeeded

            # No authentication is required if 0x00
            elif chosen_auth[1:2] != b"\x00":
                # Reaching here is always bad
                if chosen_auth[1:2] == b"\xFF":
                    raise SOCKS5AuthError("All offered SOCKS5 authentication methods were rejected")
                else:
                    raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            # Now we can request the actual connection
            writer.write(b"\x05" + cmd + b"\x00")
            resolved = self._write_SOCKS5_address(dst, writer, proxy)
            writer.flush()

            # Get the response
            resp = self._readall(reader, 3)
            if resp[0:1] != b"\x05":
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            status = ord(resp[1:2])
            if status != 0x00:
                # Connection failed: server returned an error
                error = SOCKS5_ERRORS.get(status, "Unknown error")
                raise SOCKS5Error("{0:#04x}: {1}".format(status, error))

            # Get the bound address/port
            bnd = self._read_SOCKS5_address(reader)
            return (resolved, bnd)
        finally:
            reader.close()
            writer.close()

    def _write_SOCKS5_address(self, addr, file, proxy):
        """
        Return the host and port packed for the SOCKS5 protocol,
        and the resolved address as a tuple object.
        """
        host, port = addr
        proxy_type, _, _, rdns, username, password = proxy

        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            addr_bytes = socket.inet_aton(host)
            file.write(b"\x01" + addr_bytes)
            host = socket.inet_ntoa(addr_bytes)
        except socket.error:
            # Well it's not an IP number, so it's probably a DNS name.
            if rdns:
                # Resolve remotely
                host_bytes = host.encode('idna')
                file.write(b"\x03" + chr(len(host_bytes)).encode() + host_bytes)
            else:
                # Resolve locally
                addr_bytes = socket.inet_aton(socket.gethostbyname(host))
                file.write(b"\x01" + addr_bytes)
                host = socket.inet_ntoa(addr_bytes)

        file.write(struct.pack(">H", port))
        return host, port

    def _read_SOCKS5_address(self, file):
        atyp = self._readall(file, 1)
        if atyp == b"\x01":
            addr = socket.inet_ntoa(self._readall(file, 4))
        elif atyp == b"\x03":
            length = self._readall(file, 1)
            addr = self._readall(file, ord(length))
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

        port = struct.unpack(">H", self._readall(file, 2))[0]
        return addr, port

    def _negotiate_SOCKS4(self, dst_addr, dst_port, proxy):
        """
        Negotiates a connection through a SOCKS4 server.
        """
        proxy_type, addr, port, rdns, username, password = proxy

        writer = self.makefile("wb")
        reader = self.makefile("rb", 0)  # buffering=0 renamed in Python 3
        try:
            # Check if the destination address provided is an IP address
            remote_resolve = False
            try:
                addr_bytes = socket.inet_aton(dst_addr)
            except socket.error:
                # It's a DNS name. Check where it should be resolved.
                if rdns:
                    addr_bytes = b"\x00\x00\x00\x01"
                    remote_resolve = True
                else:
                    addr_bytes = socket.inet_aton(socket.gethostbyname(dst_addr))

            # Construct the request packet
            writer.write(struct.pack(">BBH", 0x04, 0x01, dst_port))
            writer.write(addr_bytes)

            # The username parameter is considered userid for SOCKS4
            if username:
                writer.write(username)
            writer.write(b"\x00")

            # DNS name if remote resolving is required
            # NOTE: This is actually an extension to the SOCKS4 protocol
            # called SOCKS4A and may not be supported in all cases.
            if remote_resolve:
                writer.write(dst_addr.encode('idna') + b"\x00")
            writer.flush()

            # Get the response from the server
            resp = self._readall(reader, 8)
            if resp[0:1] != b"\x00":
                # Bad data
                raise GeneralProxyError("SOCKS4 proxy server sent invalid data")

            status = ord(resp[1:2])
            if status != 0x5A:
                # Connection failed: server returned an error
                error = SOCKS4_ERRORS.get(status, "Unknown error")
                raise SOCKS4Error("{0:#04x}: {1}".format(status, error))

            # Get the bound address/port
            self.proxy_sockname = (socket.inet_ntoa(resp[4:]), struct.unpack(">H", resp[2:4])[0])
            if remote_resolve:
                self.proxy_peername = socket.inet_ntoa(addr_bytes), dst_port
            else:
                self.proxy_peername = dst_addr, dst_port
        finally:
            reader.close()
            writer.close()

    def _negotiate_tunnel_HTTP(self, dst_addr, dst_port, proxy):
        """
        Negotiates a connection through an HTTP server.
        NOTE: This currently only supports HTTP CONNECT-style proxies.
        For more about HTTP CONNECT read the https://www.ietf.org/rfc/rfc2817.txt
        """
        proxy_type, _, _, rdns, username, password = proxy

        # If we need to resolve locally, we do this now
        addr = dst_addr if rdns else socket.gethostbyname(dst_addr)
        port = dst_port

        self.sendall(
            b'\r\n'.join((
                b'CONNECT ' + addr.encode('idna') + b":" + str(port).encode() + b' HTTP/1.1',
                self._get_proxy_auth_header(username, password).encode(),
                b'Host: ' + dst_addr.encode('idna'),
                b'',
                b''
            ))
        )

        # We just need the first line to check if the connection was successful
        fobj = self.makefile()
        status_line = fobj.readline()
        fobj.close()

        if not status_line:
            raise GeneralProxyError("Connection closed unexpectedly")

        try:
            proto, status_code, status_msg = status_line.split(" ", 2)
        except ValueError:
            raise GeneralProxyError("HTTP proxy server sent invalid response")

        if not proto.startswith("HTTP/"):
            raise GeneralProxyError("Proxy server does not appear to be an HTTP proxy")

        try:
            status_code = int(status_code)
        except ValueError:
            raise HTTPError("HTTP proxy server did not return a valid HTTP status")

        if status_code != 200:
            error = "{0}: {1}".format(status_code, status_msg)
            if status_code in (400, 403, 405):
                # It's likely that the HTTP proxy server does not support the CONNECT tunneling method
                error += ("\n[*] Note: The HTTP proxy server may not be supported by PySocks"
                          " (must be a CONNECT tunnel proxy)")
            raise HTTPError(error)

        self.proxy_sockname = (b"0.0.0.0", 0)
        self.proxy_peername = addr, dst_port

    _proxy_negotiators = {
        PROXY_TYPE_SOCKS4: _negotiate_SOCKS4,
        PROXY_TYPE_SOCKS5: _negotiate_SOCKS5,
        PROXY_TYPE_TOR: _negotiate_SOCKS5,
        PROXY_TYPE_HTTP_CONNECT: _negotiate_tunnel_HTTP,
        PROXY_TYPE_HTTPS_CONNECT: _negotiate_tunnel_HTTP,
    }

    def connect(self, dst_pair):
        """
        Connects to the specified destination through a proxy.
        Uses the same API as socket's connect().
        To addr the proxy server to chain, use set_proxy().

        dest_pair - 2-tuple of (IP/hostname, port).
        """
        dst_addr, dst_port = dst_pair

        # Do a minimal input check first
        if (
            not isinstance(dst_pair, (list, tuple))
            or len(dst_pair) != 2
            or not dst_addr
            or not isinstance(dst_port, int)
        ):
            raise GeneralProxyError("Invalid destination-connection (host, port) pair")

        chain = self.routes.get_route(dst_addr).copy()
        chain.append(Proxy(addr=dst_addr, port=dst_port))  # add final destination to proxies route

        first = True
        result = None
        while True:
            proxy = chain.pop(0)

            proxy_type, proxy_addr, proxy_port, rdns, username, password = proxy

            if first:
                # Initial connection
                result = _BaseSocket.connect(self, (proxy_addr, proxy_port))
                first = False

            if not chain:
                break

            next_hop = chain[0]

            if proxy_type is PROXY_TYPE_NONE:
                result = _BaseSocket.connect(self, (next_hop.addr, next_hop.port))
            else:
                # Connected to proxy server, now negotiate
                try:
                    if proxy_type != PROXY_TYPE_HTTP:
                        # Calls negotiate_{SOCKS4, SOCKS5, HTTPS, HTTP_CONNECT}
                        negotiate = self._proxy_negotiators[proxy_type]
                        negotiate(self, next_hop.addr, next_hop.port, proxy)
                    elif len(chain) == 1:
                        # Pass for last HTTP hop
                        # Now caller should provide correct Proxy-Authorization header
                        # and use full url as request uri (e.g. 'GET http://example.com/ HTTP/1.1')
                        pass
                    else:
                        raise RuntimeError("HTTP proxy hop can be the last only!")

                except socket.error as error:
                    # Wrap socket errors
                    self.close()
                    raise GeneralProxyError("Socket error", error)
                except ProxyError:
                    # Protocol error while negotiating with proxy
                    self.close()
                    raise

        return result
