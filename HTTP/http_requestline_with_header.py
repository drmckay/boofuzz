#!/usr/bin/env python
# Designed for use with boofuzz v0.0.9
from boofuzz import *
import sys

def main():
    if len(sys.argv) - 1 < 1:
        print("Usage: fuzz.py target_ip")
        exit(0)

    session = Session(
        target=Target(
            connection=SocketConnection(sys.argv[1], 5800, proto='tcp')
        ),
    )

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ['GET'])
        s_delim(" ", name='space-1')
        s_static("/", name='Request-URI[0]')
	s_string("", name='Request-URI')
        s_delim(" ", name='space-2')
        s_string('HTTP/1.0', name='HTTP-Version')
        s_delim("\r\n", name="Request-Line-CRLF")
    with s_block("Header"):
	s_string("Host", name='Header-name')
	s_delim(":", name='delim-1')
	s_string(" test", name='header-value')
	s_delim("\r\n", name="header-end")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))

    session.fuzz()
    #session.fuzz_single_case(4757)

if __name__ == "__main__":
    main()
