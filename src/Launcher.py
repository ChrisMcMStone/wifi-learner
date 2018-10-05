#!/usr/bin/env python

import getopt
import logging
import random
import os
import socket
import signal
import subprocess
import sys
import time
import traceback
from binascii import b2a_hex
from multiprocessing import Process
import scapy.layers.dot11 as dot11
from scapy.all import get_if_raw_hwaddr, L2Socket, str2mac, sniff, ETH_P_ALL
import SULInterface
from SnifferProcess import sniff as msniff
from SULState import SULState


def showhelp():
    print "\nSyntax: ./Launcher.py -i <inject_interface>, -t <sniff_interface> " \
        " -s <ssid> -p <pre-shared key> -m query_mode [-g gateway IP]\n"


def getRSNInfo(p):
    if(p.haslayer(dot11.Dot11Beacon)):
        p = p.getlayer(dot11.Dot11Beacon)
    else:
        p = p.getlayer(dot11.Dot11ProbeResp)
    i = 0
    while(True):
        curr = p.getlayer(i)
        if curr == None:
            return None
        if(curr.name == '802.11 Information Element' and curr.ID == 48):
            return str(b2a_hex(curr.info))
        i += 1
        p = p.getlayer(0)


def set_up_sul():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:t:s:p:m:g:")
    except getopt.GetoptError, e:
        print str(e)
        showhelp()
        exit(1)

    opts = dict([(k.lstrip('-'), v) for (k, v) in opts])

    if 'h' in opts or 'i' not in opts or 't' not in opts or 's' not in opts or 'p' not in opts or 'm' not in opts:
        showhelp()
        exit(0)

    inject_iface = opts.get('i')
    sniff_iface = opts.get('t')
    ssid = opts.get('s')
    psk = opts.get('p')
    mode = opts.get('m')

    if 'g' not in opts:
        gateway = '192.168.0.1'
    else:
        gateway = opts.get('g')

    beacon_sniff = True
    # Sniff for Beacons to determine channel and RSNinfo
    while beacon_sniff:
        channel = random.randrange(1,15)
        os.system("iw dev %s set channel %d" % (sniff_iface, channel))
        ps = sniff(timeout=0.1, iface=sniff_iface)
        for p in ps:
            if(p is None or len(p) == 0):
                continue
            if ((p.haslayer(dot11.Dot11Beacon) or
                    p.haslayer(dot11.Dot11ProbeResp)) and p[dot11.Dot11Elt].info == ssid):
                try:
                    rsnInfo = getRSNInfo(p)
                    bssid = p[dot11.Dot11].addr3
                    channel = int(ord(p[dot11.Dot11Elt:3].info))
                    os.system("iwconfig %s channel %d" %
                                (sniff_iface, channel))
                    os.system("iwconfig %s channel %d" %
                                (inject_iface, channel))
                    beacon_sniff = False
                except TypeError:
                    continue

    print "Detected beacon from %s on channel %d..." % (ssid, channel)
    print "Sniffer MAC address: %s" % str2mac(
        get_if_raw_hwaddr(sniff_iface)[1])
    print "Injector address: %s" % str2mac(get_if_raw_hwaddr(inject_iface)[1])
    sul = SULState(inject_iface, ssid, psk, bssid, rsnInfo, gateway)

    return sul, mode, sniff_iface


def query_execute(sul, query):

    if "RESET" in query:
        sul.reset()
        return "DONE"
    else:
        p, t, sc = SULInterface.query(sul, query)
        if "TIMEOUT" not in p and "DATA" not in p:
            sul.last_sc_receive = sc
        tdiff = round(t - sul.last_time_receive)
        sul.last_time_receive = t
        # No times on data frames
        if "DATA" in p or "REJECT" in p:
            return p + ",0.0"
        elif "TIMEOUT" in p:
            return p
        else:
            return p + "," + str(tdiff)


if __name__ == '__main__':

    sul, mode, iface = set_up_sul()
    # TODO: Add bpf filter, ether host = local mac or broadcast
    s = L2Socket(iface=iface, filter=None, nofilter=0, type=ETH_P_ALL)

    rdpipe, wrpipe = os.pipe()
    rdpipe = os.fdopen(rdpipe)
    wrpipe = os.fdopen(wrpipe, "w")

    sul.sniffPipe = rdpipe

    # Fork process, one for sniffer, one for query execution
    pid = 1
    try:
        pid = os.fork()
        if pid == 0:
            try:
                msniff(s, rdpipe, wrpipe, None)
            except:
                print "ERROR with sniffing process"
                raise
        elif pid < 0:
            print "ERROR fork failed"
        else:
            wrpipe.close()
            try:
                if mode == "file":
                    with open("queries", "r") as f:
                        for query in f:
                            query = query.strip()
                            if query == "END":
                                break
                            print "QUERY: " + query
                            response = query_execute(sul, query)
                            print "RESPONSE: " + response

                elif mode == "socket":
                    HOST = '127.0.0.1'
                    PORT = 4444
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((HOST, PORT))
                    s.listen(1)
                    conn, addr = s.accept()
                    print 'Connected by', addr
                    while 1:
                        data = conn.recv(1024)
                        if not data:
                            break
                        query = data.strip()
                        print "QUERY: " + query
                        response = query_execute(sul, query)
                        print "RESPONSE: " + response
                        if response:
                            conn.sendall(response+'\n')
            except:
                traceback.print_exc()
            finally:
                os.waitpid(pid, 0)
    finally:
        sys.exit()
