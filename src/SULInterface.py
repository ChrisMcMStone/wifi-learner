import utility.utils
from scapy.all import *
import struct
from binascii import *
from EAPOLState import EAPOLState
from Cryptodome.Cipher import AES
import cPickle,os,sys,time,subprocess
from TLSState import TLSState
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

    #f print 'RPT = %f' % x.time
    # print 'RSC = ' + str(x.SC)
    # TODO remove, assoc and auth frame filtering (need to deal with reset SC when eapol handshake starts).

    #try:
    #    (x[Dot11][EAP].show())
    #    print('######### PACKET START ##############')
    #    print(x.show())
    #    print('######### PACKET END  ##############')
    #    print('######### PACKET TEST START  ##############')
    #    print(x is not None)
    #    print(x.time > sul.last_time_receive)
    #    print(x.addr1 == sul.staMac)
    #    print(x.type != 1)
    #    print(not (x.type == 0 and x.subtype == 1))
    #    print(not (x.type == 0 and x.subtype == 11))
    #    print(not (x.type == 0 and x.subtype == 9))
    #    print(not (x.type == 0 and x.subtype == 13))
    #    print(not (x.type == 2 and x.subtype == 4))
    #    print((x.SC >> 4) > sul.last_sc_receive)
    #    print(not (x.haslayer(IP) and _isBroadCastIP(x.getlayer(IP).dst)))
    #    print(not ((str(x.addr3)[:8] == '01:00:5e') or
    #         (str(x.addr1)[:8] == '01:00:5e') or
    #         (str(x.addr3)[:5] == '33:33') or
    #         (str(x.addr1)[:5] == '33:33') or
    #         (str(x.addr3) == 'ff:ff:ff:ff:ff:ff') or
    #         (str(x.addr1) == 'ff:ff:ff:ff:ff:ff')))
    #    print('######### PACKET TEST END  ##############')
    #    print('SC = %s, last_sc_receive = %s'
    #          % (str(x.SC), str(sul.last_sc_receive)))
    #    print('############# SC ##################')
    #except IndexError:
    #     ''

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
            not (x.haslayer(IP) and _isBroadCastIP(x.getlayer(IP).dst)) and
            not ((str(x.addr3)[:8] == '01:00:5e') or
                 (str(x.addr1)[:8] == '01:00:5e') or
                 (str(x.addr3)[:5] == '33:33') or
                 (str(x.addr1)[:5] == '33:33') or
                 (str(x.addr3) == 'ff:ff:ff:ff:ff:ff') or
                 (str(x.addr1) == 'ff:ff:ff:ff:ff:ff')))
           #not (x.haslayer(Dot11WEP) and _checkDecryptBroadcast(sul, x))

    #if filt:
    #    print('## SC value: %s'
    #          % str(x.SC >> 4))
    #    print('## Last SC value: %s'
    #          % str(sul.last_sc_receive))

    return filt

# Used for ignoring broadcast data
def _isBroadCastIP(ipaddr):
    #Probably broadcast
    if str(ipaddr)[-3:] == '255':
        return True
    else:
        x = int(str(ipaddr[:3]))
        if x >= 224 and x <= 239:
            return True
    return False

# Parse string representation of query to construct corresponding concrete
# message with parameters.
def query(sul, cmd):

    if 'DELAY' in cmd:
        response = psniff(sul, lambda x: _filter(sul, x))
        return genAbstractOutput(sul, response)

    if 'ASSOC' in cmd:
        if len(cmd) > 5:
            resp, t, sc = assoc(sul, cmd[11:-1])
        else:
            resp, t, sc = assoc(sul)

        if 'ACCEPT' in resp:
            sul.last_time_receive = t
            # TODO Might need to force wait for start of handshake
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

    elif 'EAP_RESP' in cmd:
        # Extract parameters, format e.g. EAP_RESP(INFO=ID),
        # EAP_RESP(ENC_TYPE=TTLS) Only TTLS supported atm

        params = cmd[8:-1].split('=')
        if 'INFO' in params[0]:
            if 'ID' in params[1]:
                packet = sul.eap.id_resp()
                sul.send(packet)
        elif 'ENC_TYPE' in params[0]:
            packet = sul.eap.enc_resp(params[1])
            sul.send(packet)


    elif 'EAP_TTLS' in cmd:
        # EAP_TTLS(CLIENT_HELLO)
        param = cmd[8:-1]
        if 'CLIENT_HELLO' in param:
            packet = sul.eap.client_hello()
            sul.tlsstate = TLSState(packet, sul)
            sul.send(packet)
        elif 'CLIENT_KEY_EX' in param:
            packet = sul.tlsstate.client_key_exchange()
            sul.send(packet)

    else:
        message = sul.queries[cmd]
        if message:
            sul.send(message)
        else:
            return 'NO command'

    return query(sul, 'DELAY')

# Associate with the AP to kick off the 4-way handshake. This method deals with the
# inevitable case that the AP will take a while to respond and as such requires multiple attempts.
def assoc(sul, rsn=None):

    sul.last_sc_receive = 0

    print '$ Attempting to associate with AP.'
    while True:
        #time.sleep(1) for iphone which need delay between attempts
        try:
            # Send and recieve Auth frames
            sul.send(sul.queries['Auth'])
            auth_response = psniff(sul,
                                   lambda x: (x.haslayer(Dot11Auth)
                                              and x.getlayer(Dot11Auth).status == 0
                                              and x.addr1 == sul.staMac))
            if not auth_response:
                print '$ Failed to Authenticate, retrying...'
                sul.send(sul.queries['Deauth'], count=5)
                time.sleep(1)
                continue
            print '$ Authenticated.'

            # Send association request using the chosen RSN element (cipher suite)
            if rsn == None:
                sul.send(sul.queries['AssoReq'] / Dot11Elt(ID='RSNinfo', info=a2b_hex(sul.RSNinfoReal)))
            else:
                sul.send(sul.queries['AssoReq'] / Dot11Elt(ID='RSNinfo', info=a2b_hex(sul.rsnvals[rsn]+'0000')))


            assoc_response = psniff(sul, lambda x: (x.haslayer(Dot11AssoResp)
                                                    and x.addr1 == sul.staMac))
            if not assoc_response:
                print('$ Failed to Associate, retrying...')
                sul.send(sul.queries['Deauth'], count=5)
                time.sleep(1)
                continue
            if assoc_response.getlayer(Dot11AssoResp).status == 0:
                print('$ Associated.')
                sul.last_sc_receive = -1 # TODO this might be if EAP
                return 'ACCEPT', assoc_response.time, 0
            else:
                print('$ Association rejected. Status code %s'
                      % str(assoc_response.getlayer(Dot11AssoResp).status))
                return 'REJECT', assoc_response.time, 0

        except Exception as e:
            print('ERROR in association')
            print(e)
            traceback.print_exc()
            continue

    return 'TIMEOUT', 0, 0

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
            except Exception as e:
                print(e)
                pstring = 'ENC_DATA_UNKNOWN'

        sc = (p.SC >> 4)
        sul.sendAck()
        return pstring, p.time, sc

    # try eap
    try:
        eapp = p[EAP]
        sul.sendAck()
        return parse_eap(sul, p,eapp)

    except IndexError:
        'Not an EAP packet'

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

# parse packet, EAP layer
def parse_eap(sul, p, eapp):
        pstring = 'EAP'
        sul.eap.count_id = eapp.id

        # https://www.iana.org/assignments/eap-numbers/eap-numbers.xml#eap-numbers-1
        if eapp.code == 1 :

            try: # TODO When extending to other types (eg. eap-pwd or eap-tls)
                 # this condition will have to be properly created
                server_hello = bool(p.M)
            except:
                server_hello = False

            if not server_hello:
                pstring += '_REQUEST'
                # Asking for username
                pstring += '('
                # EAP types is from scapy eap.py TODO clean namespace
                pstring += 'TYPE=%s(%s)' % (eapp.type, eap_types[eapp.type].upper())
                pstring += ')'
            else:
                # Start of server hello message
                pstring +='_TTLS'
                pstring += '('
                sh_data = [] # Server hello data

                while True:
                    # Save current packet data and read next packet while
                    # more bit is set

                    # Get more bit
                    try:
                        server_hello = bool(p.M)
                    except:
                        server_hello = False

                    # Save Data
                    sh_data.append(eapp.data)

                    # Send ACK
                    sul.send(sul.eap.sh_resp())

                    # Read next packet and loop
                    sul.last_sc_receive = (p.SC >> 4)
                    p = psniff(sul, lambda x: _filter(sul, x))

                    eapp = p[EAP]
                    sul.eap.count_id = eapp.id

                    # If more bit
                    if not server_hello:
                        break

                # Construct TLS packet and extract server public key
                tls_packet = TLS(''.join(sh_data))
                sul.tlsstate.server_hello(tls_packet)

                # pstring += ('|CONTENT=%s' % ','.join(
                #     map(lambda x: TLS_CONTENT_TYPES[x.content_type].upper(),
                #         sul.tlsstate.server_hello.records)))

                pstring += ('HANDSHAKES=%s' % ','.join(
                    map(lambda x: TLS_HANDSHAKE_TYPES[x.handshakes[0].type].upper(),
                        sul.tlsstate.server_hello.records)))

                # pstring += ('|PK=%s'
                #             % base64.b16encode(str(sul.tlsstate.server.modulus)))
                pstring += ')'

        elif eapp.code == 2 :
            pstring += '_RESPONSE'
        elif eapp.code == 3 :
            pstring += '_SUCCESS'
        elif eapp.code == 4 :
            pstring += '_FAILURE'
        elif eapp.code == 5 :
            pstring += '_INITIATE'
        elif eapp.code == 6 :
            pstring += '_FINISH'
        else:
            pstring += '_INVALID_CODE'


        sc = (p.SC >> 4)

        return pstring, p.time, sc
