"""
Monkey socket
"""
import sys
import weakref
import threading

import socket
_orig_socket = socket
del socket

import socks

from socket import *


_GLOBAL_DEFAULT_TIMEOUT = _orig_socket._GLOBAL_DEFAULT_TIMEOUT

_ident2ref = {}
_routes_all = {}


def _socket_factory(*args, **kw):
    global _routes_all

    ident = threading.get_ident()
    if ident not in _routes_all:
        ident = None  # use global

    routes = _routes_all.get(ident)
    return socks.socksocket(*args, routes=routes, **kw)


socket = _socket_factory


def create_connection(
    address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
    source_address=None
):
    """Whole copy of socket.create_connection"""
    host, port = address
    err = None
    for res in getaddrinfo(host, port, 0, SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket(af, socktype, proto)
            if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except error as _:
            err = _
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise error("getaddrinfo returns an empty list")


def _socks_wrap_module(thread, routes, module):
    """Wrap module for given `route` by route from `proxy_chain`

    :param thread: `None` - global, `threading.Thread` object for given thread only
    :param routes: socks.RoutingTable
    :param module: target module object
    """
    global _ident2ref
    global _routes_all

    if thread is not None:
        ident = thread.ident

        # prevent memory leaking
        # cleanup routes when thread die
        _ident2ref[ident] = weakref.ref(thread, lambda x: cleanup_routes)

        thread_id = ident
    else:
        thread_id = None

    _routes_all[thread_id] = routes
    module.socket = sys.modules[__name__]

    cleanup_routes()


def socks_wrap_module_global(routes, module):
    _socks_wrap_module(None, routes, module)


def socks_wrap_module_thread(routes, module):
    _socks_wrap_module(threading.current_thread(), routes, module)


def cleanup_routes():
    global _ident2ref
    global _routes_all

    for ident, ref in tuple(_ident2ref.items()):
        thread = ref()
        if thread is None or not thread.is_alive():
            _routes_all.pop(ident, None)
            _ident2ref.pop(ident, None)
