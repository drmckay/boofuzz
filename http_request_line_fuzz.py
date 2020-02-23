#!/usr/bin/env python
# Designed for use with boofuzz v0.0.9
from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 5800, proto='tcp')
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
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
