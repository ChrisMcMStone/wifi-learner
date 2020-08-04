import utility.utils
from scapy.all import *
import struct
from binascii import *
from EAPOLState import EAPOLState
from Cryptodome.Cipher import AES
import cPickle,os,sys,time,subprocess
import traceback


# Sniff for pairwise/unicast traffic
def psniff(sul, pf=None):
    sp = sul.sniffPipe
    stoptime = time.time() + sul.TIMEOUT
    while stoptime > time.time():
        # Read one frame from sniff buffer
        inmask = [sp]
        inp, out, err = select(inmask,[],[], 0)
        r = cPickle.load(sp)
        # Does packet pass the filter
        if not pf:
            return r
        elif pf and pf(r):
            return r
        else:
            continue
    return None

# Function applied to sniffer
def _filter(sul, x):

    # Packet received after last sent
    # Addressed to us?
    # No assoc response (temp hack to avoid issue of resetting SC at start of handshake
    # Not control frame
    # Not ATIM frame
    # Not Action
    # Not Null frame
    # Not IP packet destined for broadcast/multicast IP

    filt = (x is not None and
            x.time > sul.last_time_receive and
            x.addr1 == sul.staMac and
            x.type != 1 and
            not (x.type == 0 and x.subtype == 1) and
            not (x.type == 0 and x.subtype == 11) and
            not (x.type == 0 and x.subtype == 9) and
            not (x.type == 0 and x.subtype == 13) and
            not (x.type == 2 and x.subtype == 4) and
            ((x.SC >> 4) > sul.last_sc_receive) and
            not ((str(x.addr3)[:8] == '01:00:5e') or
                 (str(x.addr1)[:8] == '01:00:5e') or
                 (str(x.addr3)[:5] == '33:33') or
                 (str(x.addr1)[:5] == '33:33') or
                 (str(x.addr3) == 'ff:ff:ff:ff:ff:ff') or
                 (str(x.addr1) == 'ff:ff:ff:ff:ff:ff')))
           #not (x.haslayer(Dot11WEP) and _checkDecryptBroadcast(sul, x))

    return filt


# Parse string representation of query to construct corresponding concrete
# message with parameters.
def query(sul, cmd):

    if 'DELAY' in cmd:
        response = psniff(sul, lambda x: _filter(sul, x))
        return genAbstractOutput(sul, response)
    
    if 'AUTH' in cmd:
        resp, t, sc = auth(sul)
        return resp, t, sc

    if 'ASSOC' in cmd:
        if len(cmd) > 5:
            resp, t, sc = assoc(sul, cmd[11:-1])
        else:
            resp, t, sc = assoc(sul)

        if 'ACCEPT' in resp:
            sul.last_time_receive = t
            # wait for 4 way handshake to begin
            resp, t, sc = query(sul, 'DELAY')
            return resp, t, sc
        else:
            return resp, t, sc

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
                    elif x[3] == "+":
                        rc += int(x[4:])
                    elif x[3] == "-":
                        rc -= int(x[4:])
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
                    elif x[3] == "+":
                        rc += int(x[4:])
                    elif x[3] == "-":
                        rc -= int(x[4:])
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

            message4 = sul.eapol.buildFrame4(rc, Snonce=nonce, invalidMic=invalidMic,
                                             rsnInfo=rsne, kd=kd, cipher=cipher, kf=kf)
        sul.send(message4)

    elif cmd == 'ENC_DATA':
        return query(sul, 'ENC_DATA_AES')

    elif cmd == 'ENC_DATA_AES':
        # Try both a DHCP discovery and ARP to elicit encrypted response
        ep2 = sul.queries['ARP']
        sul.sendAESFrame(ep2, addr1 = sul.bssid, addr2=sul.staMac, addr3 = 'ff:ff:ff:ff:ff:ff')

        ep = sul.queries['DHCPDisc']
        sul.sendAESFrame(ep, sul.bssid, sul.staMac, sul.bssid)

        response = query(sul, 'DELAY')
        return response

    elif cmd == 'ENC_DATA_TKIP':
        # Try both a DHCP discovery and ARP to elicit encrypted response
        ep2 = sul.queries['ARP']
        sul.sendTKIPFrame(ep2, addr1 = sul.bssid, addr2=sul.staMac, addr3 = 'ff:ff:ff:ff:ff:ff')

        ep = sul.queries['DHCPDisc']
        sul.sendTKIPFrame(ep, sul.bssid, sul.staMac, sul.bssid)

        response = query(sul, 'DELAY')
        return response

    elif cmd == 'DATA':
        addr1 = sul.bssid
        addr2 = sul.staMac
        addr3 = 'ff:ff:ff:ff:ff:ff'
        sul.send((RadioTap() / Dot11() / sul.queries['DHCPDisc']), addr1=addr1, addr2=addr2, addr3=addr3)
        addr3 = 'ff:ff:ff:ff:ff:ff'
        sul.send(RadioTap()/Dot11()/sul.queries['ARP'],addr1=addr1, addr2=addr2, addr3=addr3)

    else:
        message = sul.queries[cmd]
        if message:
            sul.send(message)
        else:
            return 'NO command'

    return query(sul, 'DELAY')


def auth(sul):
    sul.last_sc_receive = 0
    print '$ Attempting to authenticate with AP.'
    # Send and recieve Auth frames
    sul.send(sul.queries['Auth'])
    auth_response = psniff(sul,
                            lambda x: (x.haslayer(Dot11Auth)
                                        and x.getlayer(Dot11Auth).status == 0
                                        and x.addr1 == sul.staMac))
    if not auth_response:
        print '$ Failed to Authenticate, returning timeout...'
        return 'TIMEOUT', 0, 0
        # sul.send(sul.queries['Deauth'], count=5)
        # time.sleep(1)
        # continue
    print '$ Authenticated.'
    
    return 'AUTH_ACCEPT', auth_response.time, 0
    
# Associate with the AP to kick off the 4-way handshake. This method deals with the
# inevitable case that the AP will take a while to respond and as such requires multiple attempts.
def assoc(sul, rsn=None):

    # Send association request using the chosen RSN element (cipher suite)
    if rsn == None:
        sul.send(sul.queries['AssoReq'] / Dot11Elt(ID='RSNinfo', info=a2b_hex(sul.RSNinfoReal)))
    else:
        sul.send(sul.queries['AssoReq'] / Dot11Elt(ID='RSNinfo', info=a2b_hex(sul.rsnvals[rsn]+'0000')))


    assoc_response = psniff(sul, lambda x: x.addr1 == sul.staMac)
    if assoc_response.haslayer(Dot11AssoResp):
        if assoc_response.getlayer(Dot11AssoResp).status == 0:
            print('$ Associated.')
            return 'ACCEPT', assoc_response.time, 0
        else:
            print('$ Association rejected. Status code %s'
                    % str(assoc_response.getlayer(Dot11AssoResp).status))
            return 'REJECT', assoc_response.time, 0
    else:
        return genAbstractOutput(sul, assoc_response)


def payload_to_iv_ccmp(payload):
    iv0 = payload[0]
    iv1 = payload[1]
    wepdata = payload[4:8]
    return ord(iv0) + (ord(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)

def payload_to_iv_tkip(payload):
    iv0 = payload[2]
    iv1 = payload[0]
    wepdata = payload[4:8]
    return ord(iv0) + (ord(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)


# Parse packet to construct abstract string to feed back to learner
def genAbstractOutput(sul, p):

    # If no response, i.e. TIMEOUT
    if not p:
        t = sul.last_time_receive + sul.TIMEOUT
        return 'TIMEOUT,'+str(sul.TIMEOUT), t, sul.last_sc_receive

    p_string = ''
    # If encrypted data
    if (p.getlayer(Dot11).type == 2
            and p.getlayer(Dot11).subtype == 0x0
            and p.getlayer(Dot11).FCfield & 0x40):

        dec = None

        # This assumes AES is used. It is overriden if TKIP decryption succeeds.
        iv = payload_to_iv_ccmp(p[Raw].load)

        # Try decrypting with AES
        try:
            dec = sul.decryptTrafficAES(p)

            # TODO/FIXME checking for Raw layer is hack which I don't think will always work.
            if dec.haslayer(Raw):
                raise ValueError('AES Decryption Failed, trying TKIP')

            # print dec.summary()
            pstring = 'AES_DATA'

        except:
            # If AES fails, try with TKIP
            try:
                dec = sul.decryptTrafficTKIP(p)
                if dec.haslayer(Raw):
                    raise ValueError('TKIP Decryption Failed')
                # print dec.summary()
                pstring = 'TKIP_DATA'

                iv = payload_to_iv_tkip(p[Raw].load)

            except Exception as e:
                print(e)
                pstring = 'AES_DATA'

        # Track if packet number was 1 or something higher. This allows
        # the detection of key reinstallations that reset the packet
        # number back to 1.
        if iv == 1:
            pstring += "_1"
        else:
            pstring += "_n"

        sc = (p.SC >> 4)
        sul.sendAck()
        return pstring, p.time, sc

    # If EAPOL handshake message
    p = p[Dot11]
    ep = utility.utils.getEapolLayer(p)
    if ep:
        # Extract the parameters needed to construct subsequent
        # handshake messages.
        if utility.utils.validMessage1(ep):
            sul.Anonce = p.Nonce
            sul.ReplayCounter = p.ReplayCounter
        elif utility.utils.validMessage3(ep):
            sul.ReplayCounter = p.ReplayCounter
        pstring = _parseResponse(ep, sul)
    else:
        pstring = _parseResponse(p, sul)
    sc = (p.SC >> 4)
    # Return string of packet, timestamp and sequence counter
    sul.sendAck()
    return pstring, p.time, sc

def _parseResponse(p, sul):
    if not p.haslayer(Dot11):
        return utility.utils.genEapolString(p, sul)
    elif p.haslayer(LLC):
        return 'UNENCRYPTED_DATA'
    else:
        if 'Dot11' in p.summary():
            return p.summary().split('Dot11', 1)[1].split(' ', 1)[0]
        return p.summary()
