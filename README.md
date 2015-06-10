# PySocksChain

This project result of merging two projects: [PySocks](https://github.com/Anorov/PySocks/) and [PySocksipyChain](https://github.com/pagekite/PySocksipyChain/)

Project still development but already have key features:

* Chain proxy
* [requests](https://github.com/kennethreitz/requests) adapter
* urllib handler

What is not supported yet:

* HTTPS proxies. If you want read web page through HTTPS just use SOCKS.
* Python 2.

Usage example see in **socks.handlers** and **socks.adapters** modules.

May be not obvious things:

* To use HTTP CONNECT tunneling method you should manually add proxy with scheme 'httpc', this is not fallback for 'http'.
* If you do not want use handlers/adapters you should manually set full uri per request and 'Proxy-Authorization' header (HTTP(S) only)
* HTTP proxy can be the last hop ONLY! For intermediate hops use SOCKS/HTTPC proxies.
