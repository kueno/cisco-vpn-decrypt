#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Decrypt Cisco VPN Cleint shared keys.
 Thanks to http://www.unix-ag.uni-kl.de/~massar/bin/cisco-decode

 This program requires pycrypto library.

 Usage:
   echo "DEADBEEF...012345ABCDEF" | ./cisco-vpn-decrypt.py
"""

"""
Copyright (c) 2013 Kouji UENO

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
from binascii import unhexlify
from struct import pack,unpack
import hashlib
import sys
from Crypto.Cipher import DES3

def get_sha1_hash(buf):
    sha1 = hashlib.new('sha1')
    sha1.update(buf)
    return sha1.digest()

def get_key(ht):
    ht=bytearray(ht)
    ht[19] += 1
    h2 = get_sha1_hash(ht)
    ht[19] += 2
    h3 = get_sha1_hash(ht)
    return h2+h3[0:4]

def decrypt_cisco_vpn_key(s):
    ct = bytearray(unhexlify(s))
    iv = ct[0:8]
    key = get_key(ct[0:20])
    checksum = ct[20:40]
    data = ct[40:len(ct)]

    # checksum
    assert bytearray(get_sha1_hash(data))==checksum

    return DES3.new(key, IV=str(iv), mode=DES3.MODE_CBC).decrypt(str(data))

if __name__ == '__main__':
    for line in sys.stdin:
        line = line.rstrip("\n\r")
        if len(line) < 40:
            print "<not valid>\n"
            next
        print decrypt_cisco_vpn_key(line)

