import utils
from scapy.all import *
import struct
from binascii import *
from EAPOLState import EAPOLState
from Crypto.Cipher import AES
import cPickle,os,sys,time,subprocess

def psniff(sul, pf=None):
    stoptime = time.time()+sul.TIMEOUT
    while stoptime > time.time():
        # Read one frame from sniff buffer
        inmask = [sul.sniffPipe]
        inp, out, err = select(inmask,[],[], 0)
        r = cPickle.load(sul.sniffPipe)
        if not pf:
            return r
        elif pf and pf(r):
            return r
        else:
            continue
    return None

def bsniff(sul, pf=None, delayTime=5):
    stoptime = time.time()+delayTime
    pks = []
    while stoptime > time.time():
        # Read one frame from sniff buffer
        inmask = [sul.sniffPipe]
        inp, out, err = select(inmask,[],[], 0)
        r = cPickle.load(sul.sniffPipe)
        if not pf:
            return r
        elif pf and pf(r):
            pks.append(r)
        else:
            continue
    return pks

def _filter(sul, x):

    # Packet received after last sent
    # Addressed to fuzzer
    # No assoc response (temp hack to avoid issue of resetting SC at start of handshake
    # Not control frame
    # Not ATIM frame
    # Not Action
    # Not Null frame
    # Not IP packet destined for broadcast/multicast IP
    #f print "RPT = %f" % x.time
    # print "RSC = " + str(x.SC)
    # TODO remove, assoc and auth frame filtering (need to deal with reset SC when eapol handshake starts). 

    filt = x is not None and \
           x.time > sul.last_time_receive and \
           x.addr1 == sul.staMac and \
           x.type != 1 and \
           not (x.type == 0 and x.subtype == 1) and \
           not (x.type == 0 and x.subtype == 11) and \
           not (x.type == 0 and x.subtype == 9) and \
           not (x.type == 0 and x.subtype == 13) and \
           not (x.type == 2 and x.subtype == 4) and \
           (x.SC >> 4) > sul.last_sc_receive and \
           not (x.haslayer(IP) and _isBroadCastIP(x.getlayer(IP).dst)) and \
           not x.haslayer(Raw) and \
           not ((str(x.addr3)[:8] == "01:00:5e") or \
           (str(x.addr1)[:8] == "01:00:5e") or \
           (str(x.addr3)[:5] == "33:33") or \
           (str(x.addr1)[:5] == "33:33") or \
           (str(x.addr3) == "ff:ff:ff:ff:ff:ff") or \
           (str(x.addr1) == "ff:ff:ff:ff:ff:ff")) and \
           not (x.haslayer(Dot11WEP) and _checkDecryptBroadcast(sul, x)) 

    # if filt:
        # print "NEW SC = " + str((x.SC >> 4))
        # print "OLD SC = " + str(lsc)

    return filt

# def _checkDecryptBroadcast(sul, p):
    # x = sul.decryptTrafficCcmp(p)
    # if(x.haslayer(IP)):
        # return _isBroadCastIP(x.getlayer(IP).dst)

def _checkDecryptBroadcast(sul, p):
    x = sul.decryptTrafficCcmp(p)
    return not x.haslayer(SNAP)

def _isBroadCastIP(ipaddr):
    #Probably broadcast
    if str(ipaddr)[-3:] == "255":
        return True
    else:
        x = int(str(ipaddr[:3]))
        if x >= 224 and x <= 239:
            return True
    return False

def _filterBRD(sul, x):

    # Packet received after last sent
    # Addressed to multicast or broadcast MAC
    # Not control frame
    # Not ATIM frame
    # Not Action
    # Not Null frame TODO possibly need to remove this for the iOS testing. 

    filt = x is not None and \
            x.time > sul.last_time_receive and \
            x.addr2 == sul.bssid and \
            ((str(x.addr3)[:8] == "01:00:5e") or \
            (str(x.addr1)[:8] == "01:00:5e") or \
            (str(x.addr3)[:5] == "33:33") or \
            (str(x.addr1)[:5] == "33:33") or \
            (str(x.addr3) == "ff:ff:ff:ff:ff:ff") or \
            (str(x.addr1) == "ff:ff:ff:ff:ff:ff") or \
            (x.haslayer(IP) and _isBroadCastIP(x.getlayer(IP).dst))) and \
            x.type != 1 and \
            not (x.type == 0 and x.subtype == 9) and \
            not (x.type == 0 and x.subtype == 13) and \
            not (x.type == 2 and x.subtype == 4) 

    return filt

def query(sul, cmd):

    if cmd == 'DELAY':
        response = psniff(sul, lambda x: _filter(sul, x))
        return genAbstractOutput(sul, response)

    if "ASSOC" in cmd:
        if(len(cmd) > 5):
            resp, t, sc = assoc(sul, cmd[11:-1])
        else:
            resp, t, sc = assoc(sul)
        if "ACCEPT" in resp:
            sul.last_time_receive = t
            # TODO Might need to force wait for start of handshake
            return query(sul, "DELAY")
        else:
            return resp, t, sc

    elif cmd == 'BRD':
        responses = bsniff(sul, lambda x: _filterBRD(sul, x))
        rstring = ""
        for r in responses:
            output = genAbstractOutput(sul, r)[0]
            if output not in rstring:
                rstring += output + ","
        rstring = rstring[:-1]
        return rstring

    elif cmd == 'E2_ENC_DATA':
        message2 = sul.eapol.buildFrame2(Anonce=sul.Anonce, ReplayCounter=sul.ReplayCounter)
        sul.send(message2)
        query(sul, "ENC_DATA")

    elif 'E2' in cmd:
        if cmd == 'E2':
            message2 = sul.eapol.buildFrame2(Anonce=sul.Anonce, ReplayCounter=sul.ReplayCounter)
        else:
            # Extract parameters, format e.g. EAPOL_2(KD=WPA2|RSNE=cc)
            params = cmd[4:-1].split('|')
            kd = None
            rsne = None
            cipher = None
            invalidMic = False
            rc=sul.ReplayCounter
            kf = None
            for x in params:
                if 'KD' in x:
                    kd = sul.kdvals[x[3:]]
                elif 'RSNE' in x:
                    rsne = sul.rsnvals[x[5:]] + '0000'
                elif 'CS' in x:
                    cipher = sul.ciphervals[x[3:]]
                elif 'MIC' in x:
                    if x[4:] == 'F':
                        invalidMic = True
                elif 'RC' in x:
                    if x[3:] == '>':
                        rc = '11'*8 
                elif 'KF' in x:
                    flags = x[3:7]
                    p = 0 if flags[0]=='x' else 1
                    m = 0 if flags[1]=='x' else 1
                    s = 0 if flags[2]=='x' else 1
                    e = 0 if flags[3]=='x' else 1
                    kf = 0b00000000 
                    if m: kf += 1
                    if s: kf += 2
                    if e: kf += 4
                    if not p:
                        cipher -= 8
            
            if cipher: cipher = '0'+str(hex(cipher))[2:]
            if kf: kf = str(kf).zfill(2)

            message2 = sul.eapol.buildFrame2(Anonce=sul.Anonce, \
                    ReplayCounter=rc, invalidMic=invalidMic, \
                    rsnInfo=rsne, kd=kd, cipher=cipher, kf=kf)
        sul.send(message2)

    elif cmd == 'E4_ENC_DATA':
        message4 = sul.eapol.buildFrame4(ReplayCounter=sul.ReplayCounter)
        sul.send(message4)
        query(sul, "ENC_DATA")

    elif 'E4' in cmd:
        if cmd == 'E4':
            message4 = sul.eapol.buildFrame4(ReplayCounter=sul.ReplayCounter)
        else:
            # Extract parameters, format e.g. EAPOL_2(KD=WPA2|RSNE=cc)
            params = cmd[4:-1].split('|')
            kd = None
            rsne = None
            cipher = None
            invalidMic = False
            rc=sul.ReplayCounter
            nonce=None
            kf=None
            for x in params:
                if 'KD' in x:
                    kd = sul.kdvals[x[3:]]
                elif 'RSNE' in x:
                    rsne = sul.rsnvals[x[5:]] + '0000'
                elif 'CS' in x:
                    cipher = sul.ciphervals[x[3:]]
                elif 'MIC' in x:
                    if x[4:] == 'F':
                        invalidMic = True
                elif 'RC' in x:
                    if x[3:] == '>':
                        rc = '11'*8 
                elif 'NONC' in x:
                    if x[5:] == 'W':
                        nonce = '10'*32
                    else:
                        nonce = '11'*32
                elif 'KF' in x:
                    flags = x[3:7]
                    p = 0 if flags[0]=='x' else 1
                    m = 0 if flags[1]=='x' else 1
                    s = 0 if flags[2]=='x' else 1
                    e = 0 if flags[3]=='x' else 1
                    kf = 0b00000000 
                    if m: kf += 1
                    if s: kf += 2
                    if e: kf += 4
                    if not p:
                        cipher -= 8
            
            if cipher: cipher = '0'+str(hex(cipher))[2:]
            if kf: kf = str(kf).zfill(2)

            message4 = sul.eapol.buildFrame4(rc, Snonce=nonce, invalidMic=invalidMic, \
                    rsnInfo=rsne, kd=kd, cipher=cipher, kf=kf)
        sul.send(message4)

    elif cmd == 'ENC_DATA':
        # ep = Dot11(addr1 = sul.bssid, addr2 = sul.staMac, addr3 = sul.bssid)
        # ep = ep/sul.queries['DHCPDisc']
        # #sul.sendEncryptedFrame(sul.queries['DHCPDisc'], addr1, addr2, addr3)
        # sul.send_ccmp(ep)

        # ep = Dot11(addr1 = sul.bssid, addr2 = sul.staMac, addr3 = "ff:ff:ff:ff:ff:ff")
        # ep = ep/sul.queries['ARP']
        # # sul.sendEncryptedFrame(sul.queries['ARP'], addr1, addr2, addr3)
        # sul.send_ccmp(ep)
        addr1 = sul.bssid
        addr2 = sul.staMac
        # addr3 = sul.bssid
        # sul.sendEncryptedFrame(sul.queries['DHCPDisc'], addr1, addr2, addr3)
        addr3 = "ff:ff:ff:ff:ff:ff"
        sul.sendEncryptedFrame(sul.queries['ARP'], addr1, addr2, addr3)

        response = query(sul, "DELAY")
        if "TIMEOUT" in response:
            response = query(sul, "DELAY")
            print "retrying encrypted data"
        if "TIMEOUT" in response:
            response = query(sul, "DELAY")
            print "retrying encrypted data"
        if "TIMEOUT" in response:
            response = query(sul, "DELAY")
            print "retrying encrypted data"
        else:
            return response

    # TODO Finish TKIP Support
    # elif cmd == 'TKIP_DATA':
    #     addr1 = sul.bssid
    #     addr2 = sul.staMac
    #     addr3 = sul.bssid
    #     sul.sendEncTKIP(sul.queries['ARP'], addr1, addr2, addr3)
    #     response = query(sul, "DELAY")
    #     return response

    elif cmd == 'DATA':
        addr1 = sul.bssid
        addr2 = sul.staMac
        addr3 = "ff:ff:ff:ff:ff:ff"
        sul.send((RadioTap() / Dot11() / sul.queries['DHCPDisc']), addr1=addr1, addr2=addr2, addr3=addr3)
        addr3 = "ff:ff:ff:ff:ff:ff"
        sul.send(RadioTap()/Dot11()/sul.queries['ARP'],addr1=addr1, addr2=addr2, addr3=addr3)

    else:
        message = sul.queries[cmd]
        if message:
            sul.send(message)
        else:
            return "NO command"

    return query(sul, "DELAY")
    

def assoc(sul, rsn=None):

    # Deauthenticate previously associated MAC to free up memory
    sul.send(sul.queries["Deauth"], count=5)

    # Reset sequence numbers etc
    sul.reset()

    # Initialize state of handshake for supplicant
    sul.eapol = EAPOLState(sul.RSNinfo, sul.psk, \
            sul.ssid, sul.staMac, sul.bssid)

    retryCount = 0

    print "$ Attempting to associate with AP."
    while retryCount < 10:
        #time.sleep(1) for iphone
        try:
            sul.send(sul.queries["Auth"])
            auth_response = psniff(sul, lambda x: (x.haslayer(Dot11Auth) \
                    and x.getlayer(Dot11Auth).status == 0 \
                    and x.addr1 == sul.staMac))
            if not auth_response:
                print "$ Failed to Authenticate, retrying..."
                sul.send(sul.queries["Deauth"], count=5)
                time.sleep(1)
                continue
            print "$ Authenticated."

            if rsn == None:
                sul.send(sul.queries["AssoReq"] / Dot11Elt(ID='RSNinfo', info=a2b_hex(sul.RSNinfoReal)))
      #          print sul.RSNinfoReal
            else:
                sul.send(sul.queries["AssoReq"] / Dot11Elt(ID='RSNinfo', info=a2b_hex(sul.rsnvals[rsn]+'0000')))
      #          print sul.rsnvals[rsn]+'0000'


            assoc_response = psniff(sul, lambda x: (x.haslayer(Dot11AssoResp) \
                    and x.addr1 == sul.staMac))
            if not assoc_response:
                print "$ Failed to Associate, retrying..."
                sul.send(sul.queries["Deauth"], count=5)
                time.sleep(1)
                retryCount += 1
                continue
            if assoc_response.getlayer(Dot11AssoResp).status == 0:
                print "$ Associated."
                return "ACCEPT", assoc_response.time, 0
            else:
                print "$ Association rejected."
                return "REJECT", assoc_response.time, 0

        except Exception as e: 
            print "ERROR in association"
            print(e)
            continue

    return "TIMEOUT", 0, 0


def genAbstractOutput(sul, p):

    # If no response, i.e. TIMEOUT
    if not p:
        t = sul.last_time_receive + sul.TIMEOUT
        return "TIMEOUT,"+str(sul.TIMEOUT), t, sul.last_sc_receive

    p_string = ""
    # If encrypted data
    if p.haslayer(Dot11WEP):
        dec = None
        try:
            dec = sul.decryptTrafficCcmp(p)
            print dec.summary()
            if dec.haslayer(SNAP) or "313233" in b2a_hex(str(dec.getlayer(Raw))):
                print str(b2a_hex(str(dec.getlayer(Raw))))
                pstring = "CCMP_DATA"
            else:
                raise Exception('')
        except:
            try:
                # TODO Finish TKIP Support
                # dec = sul.decryptTrafficTkip(p)
                # print b2a_hex(str(dec.getlayer(Raw)))
                # if not dec.haslayer(IP) or (dec.haslayer(Raw) and b2a_hex(str(dec.getlayer(Raw)).contains("74657374"))):
                    # raise Exception('')
               # pstring = "TKIP_DATA"
                return query(sul, "DELAY")
            except Exception as e: 
                print(e)
                pstring = "ENC_DATA_UNKNOWN"
        sc = (p.SC >> 4)
        return pstring, p.time, sc

    # If handshake message
    p = p[Dot11]
    ep = utils.getEapolLayer(p)
    if ep:
        if utils.validMessage1(ep):
            sul.Anonce = p.Nonce
            sul.ReplayCounter = p.ReplayCounter
        elif utils.validMessage3(ep):
            sul.ReplayCounter = p.ReplayCounter
        pstring = _parseResponse(ep, sul)
    else:
        pstring = _parseResponse(p, sul)
    sc = (p.SC >> 4)
    return pstring, p.time, sc

def _parseResponse(p, sul):
    if not p.haslayer(Dot11):
        return utils.genEapolString(p, sul)
    elif p.haslayer(LLC):
        return "UNENCRYPTED_DATA"
    else:
        if "Dot11" in p.summary():
            return p.summary().split("Dot11", 1)[1].split(" ", 1)[0]
        return p.summary()