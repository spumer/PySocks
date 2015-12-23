"""
SocksiPy - Python SOCKS module.
Version 1.5.4

Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY DAN HAIM "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMANGE.


This module provides a standard socket-like interface for Python
for tunneling connections through SOCKS proxies.

===============================================================================

Minor modifications made by Christopher Gilbert (http://motomastyle.com/)
for use in PyLoris (http://pyloris.sourceforge.net/)

Minor modifications made by Mario Vilas (http://breakingcode.wordpress.com/)
mainly to merge bug fixes found in Sourceforge

Modifications made by Anorov (https://github.com/Anorov)
-Forked and renamed to PySocks
-Fixed issue with HTTP proxy failure checking (same bug that was in the old ___recvall() method)
-Included SocksiPyHandler (sockshandler.py), to be used as a urllib2 handler,
 courtesy of e000 (https://github.com/e000): https://gist.github.com/869791#file_socksipyhandler.py
 courtesy of e000 (https://github.com/e000): https://gist.github.com/869791#file_socksipyhandler.py
-Re-styled code to make it readable
    -Aliased PROXY_TYPE_SOCKS5 -> SOCKS5 etc.
    -Improved exception handling and output
    -Removed irritating use of sequence indexes, replaced with tuple unpacked variables
    -Fixed up Python 3 bytestring handling - chr(0x03).encode() -> b"\x03"
    -Other general fixes
-Added clarification that the HTTP proxy connection method only supports CONNECT-style tunneling HTTP proxies
-Various small bug fixes

===============================================================================

Modifications made by Spumer (https://github.com/spumer/)

Porting proxy chaining from PySocksipyChain (https://github.com/pagekite/PySocksipyChain/)

New version naming is "<PySocks version>-chain.<major>.<minor>.<patch>

"""

__version__ = "1.5.4-chain.0.2.2"

from .socks import *