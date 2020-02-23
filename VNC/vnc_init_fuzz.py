#!/usr/bin/env python
# Designed for use with boofuzz v0.0.9
from boofuzz import *


def main():
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", 5900, proto='tcp')
        ),
    )

    s_initialize(name="Handshake")
    with s_block("ProtocolVersion"):
        s_string("RFB", name='RFB')
        s_delim(" ", name='space-1')
	s_string("003", name='Version1')
        s_delim(".", name='space-2')
        s_string('008', name='Version2')
        s_delim("\n", name="end")


    session.connect(s_get("Handshake"))

    session.fuzz()


if __name__ == "__main__":
    main()
