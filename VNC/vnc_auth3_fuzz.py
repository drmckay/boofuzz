#!/usr/bin/env python
# Designed for use with boofuzz v0.0.9
from boofuzz import *
import struct, time


def pre_send(target, fuzz_data_logger, session, sock):
	print(sock.recv(12))
	time.sleep(0.1)
	sock.send("RFB 003.008\n")
	time.sleep(0.1)
	sectypenum =  struct.unpack('>B', sock.recv(1))[0]
	if sectypenum > 0:
		sectypes = sock.recv(sectypenum)
		print("Supported auth num: %d\n" % sectypenum)
		authtypes = {
			0: "Invalid",
			1: "None",
			2: "VNC",
			16: "Tight"
		}
		print("Supported authentication mechanisms: ")
		for st in sectypes:
			print("\t"+authtypes.get(struct.unpack('>B', st)[0], "Unknown"))

		# Requesting VNC authentication
		sock.send("\x02")

		challenge = sock.recv(16)
		print("Server challenge: %s" % challenge)

	else:
		len = struct.unpack('>I', sock.recv(4))[0]
		print("error: ", sock.recv(len))


def post_send(target, fuzz_data_logger, session, sock):
	#time.sleep(2)
        slen = sock.recv(4)
        if not slen:
                return
        status = struct.unpack(">I", slen)[0]
        if status is 0:
                print("Initialization successful!")
        else:
                print("Init failed")
                reasonlen = struct.unpack('>I', sock.recv(4))[0]
                print(sock.recv(reasonlen))

session = Session(target=Target(connection=SocketConnection("192.168.1.6", 5900, proto='tcp')),pre_send_callbacks=[pre_send], post_test_case_callbacks=[post_send])

s_initialize(name="Auth")
s_string('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', name='auth')


session.connect(session.root, s_get("Auth"))

session.fuzz()
#session.fuzz_single_case(4)
