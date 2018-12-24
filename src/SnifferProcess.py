import cPickle,os,sys,time,subprocess
from select import select
import scapy.all

# Read packets from raw socket, appy lfilter and write into shared buffer
def sniff(sock, rdpipe, wrpipe, lfilter):

    timeout = 10
    try:
        sys.stdin.close()
        # rdpipe.close()
        stoptime = 0
        remaintime = None
        inmask = [wrpipe,sock]
        try:
            while 1:
                if stoptime:
                    remaintime = stoptime-time.time()
                    if remaintime <= 0:
                        print "timed out"
                        break
                r = None
                if scapy.arch.FREEBSD or scapy.arch.DARWIN:
                    inp, out, err = select(inmask,[],[], 0.05)
                    if len(inp) == 0 or sock in inp:
                        r = sock.nonblock_recv()
                else:
                    inp, out, err = select(inmask,[],[], remaintime)
                    if len(inp) == 0:
                        break
                    if sock in inp:
                        r = sock.recv()
                if wrpipe in inp:
                    if timeout:
                        stoptime = time.time()+timeout
                if r is None:
                    continue
                if lfilter and not lfilter(r):
                    continue
                cPickle.dump(r,wrpipe)
        except SystemExit:
            pass
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print "--- Error in child %i" % os.getpid()
            print(e)
    finally:
        try:
            os.setpgrp() # Chance process group to avoid ctrl-C
            # sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
            # cPickle.dump( (conf.netcache,sent_times), wrpipe )
            wrpipe.close()
        except:
            pass
