#!/usr/bin/env python

# Ignore annoying IPv6 warning
import logging
from scapy.all import *
from pbkdf2 import *
from binascii import *
import sys
import signal, os, time
import subprocess
from multiprocessing import Process
import getopt
from SULState import SULState
from SnifferProcess import sniff as msniff
import traceback
import SULInterface

def showhelp():
    print "\nSyntax: ./Launcher.py -i <inject_interface>, -t <sniff_interface> " \
            " -s <ssid> -p <pre-shared key> -m query_mode [-g gateway IP]\n"

def getRSNInfo(p):
    if(p.haslayer(scapy.all.Dot11Beacon)):
        p = p.getlayer(Dot11Beacon)
    else:
        p = p.getlayer(Dot11ProbeResp)
    i = 0
    while(True):
        curr = p.getlayer(i)
        if curr == None: return None
        if(curr.name =='802.11 Information Element' and curr.ID == 48):
            return str(b2a_hex(curr.info))
        i+=1
        p = p.getlayer(0)

def set_up_sul():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:t:s:p:c:m:g:")
    except getopt.GetoptError, e:
        print str(e)
        showhelp()
        exit(1)

    opts = dict([(k.lstrip('-'), v) for (k,v) in opts])

    if 'h' in opts or 'i' not in opts or 't' not in opts or 's' not in opts or 'p' not in opts or 'm' not in opts:
        showhelp()
        exit(0)

    inject_iface = opts.get('i')
    sniff_iface = opts.get('t')
    ssid = opts.get('s')
    psk = opts.get('p')
    mode = opts.get('m')
    channel = int(opts.get('c'))

    if 'g' not in opts:
        gateway = '192.168.0.1'
    else:
        gateway = opts.get('g')


    # Sniff for Beacons to determine channel and RSNinfo
    while(True):
        p = sniff(count=1, iface=sniff_iface)[0]
        if(p is None or len(p) == 0): continue
        if ((p.haslayer(Dot11Beacon) or \
                p.haslayer(Dot11ProbeResp)) and p[Dot11Elt].info == ssid):
            try:
                rsnInfo = getRSNInfo(p)
                bssid = p[Dot11].addr3    
                if 'c' not in opts:
                    channel = int(ord(p[Dot11Elt:3].info))
                    os.system("iwconfig %s channel %d" % (sniff_iface, channel))
                break
            except TypeError:
                continue
            
    # bssid = "2E:1F:23:45:46:1D"
    # rsnInfo = None
    print "Detected beacon from %s on channel %d..." % (ssid, channel)
    print "Sniffer MAC address: %s" % str2mac(get_if_raw_hwaddr(sniff_iface)[1])
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
        tdiff= round(t - sul.last_time_receive)
        sul.last_time_receive = t
        #No times on data frames
        if "DATA" in p or "REJECT" in p:
            return p + ",0.0"
        elif "TIMEOUT" in p:
            return p
        else:
            return p + "," + str(tdiff)



if __name__ == '__main__':

    sul, mode, iface = set_up_sul()
    #TODO: Add bpf filter, ether host = local mac or broadcast
    s = L2Socket(iface=iface, filter=None, nofilter=0, type=ETH_P_ALL)

    rdpipe,wrpipe = os.pipe()
    rdpipe=os.fdopen(rdpipe)
    wrpipe=os.fdopen(wrpipe,"w")

    sul.sniffPipe = rdpipe

    # Fork process, one for sniffer, one for query execution
    pid=1
    try:
        pid = os.fork()
        if pid == 0:
            try:
                msniff(s, rdpipe, wrpipe, None)
            except:
                "ERROR with sniffing process"
                raise
        elif pid < 0:
            log_runtime.error("fork error")
        else:
            wrpipe.close()
            try:
                if mode == "file":
                    with open("queries.txt", "r") as f:
                        for query in f:
                            query = query.strip()
                            if query == "END":
                                break
                            print "QUERY: " + query
                            response = query_execute(sul, query)
                            print "RESPONSE: " + response 

                elif mode == "socket":
                    HOST = '127.0.0.1'
                    PORT = 50008
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((HOST, PORT))
                    s.listen(1)
                    conn, addr = s.accept()
                    print 'Connected by', addr
                    while 1:
                        data = conn.recv(1024)
                        if not data: break
                        query = data.strip()
                        print "QUERY: " + query
                        response = query_execute(sul, query)
                        print "RESPONSE: " + response 
                        if response:
                            conn.sendall(response+'\n')
            except:
                 traceback.print_exc()
            finally:
                os.waitpid(pid,0)
    finally:
        sys.exit()
