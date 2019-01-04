from scapy.all import *
import struct
from binascii import *
from EAPOLState import EAPOLState
from EAPState import EAPState
from crypto.HandleTKIP import *
from crypto.HandleAES import *
import time
import SULInterface
import utility.utils, os

# Maintains the state for the System Under Learning.
class SULState:

    def __init__(self, iface, ssid, psk, bssid, rsnInfo, gateway):
        self.iface = iface
        self.sniffPipe = None
        # Set MAC addresses
        self.ssid = ssid
        self.bssid = bssid
        self.staMac = str2mac(get_if_raw_hwaddr(self.iface)[1])
        # Pre-shared key
        self.psk = psk
        # Sequence counters
        self.sc_send = 0
        # Send and recieve times
        self.last_sc_receive = -1
        self.last_time_receive = 0.0
        # Required for EAPOL frames
        self.Anonce = '00' * 32
        self.ReplayCounter = '00' * 8
        self.RSNinfo = rsnInfo[:36] + '0000'
        self.RSNinfoReal = rsnInfo[:36] + '0000'
        # Required for ARP requests
        self.gateway = gateway
        lastoctindex = gateway.rfind('.')+1
        self.ipsrc = (gateway[:lastoctindex]
                      + str(random.randint(int(gateway[lastoctindex:]),250)))

        self._buildQueries()
        # Timeout for waiting for responses
        self.TIMEOUT = 2.0
        # Initialize state of handshake for supplicant
        self.eapol = EAPOLState(self.RSNinfo, self.psk,
                                self.ssid, self.staMac, self.bssid)
        self.eap = EAPState(self.staMac, self.bssid)

        # Initialize crypto handlers
        self.aesHandler = HandleAES()
        self.tkipHandler = HandleTKIP()

    def reset(self):
        self.sc_send = 0
        #self.last_sc_receive = -1
        # Deauthenticate previously associated MAC to free up memory
        self.send(self.queries["Deauth"], count=5)
        self.last_time_receive = time.time()
        self.Anonce = '00' * 32
        self.ReplayCounter = '00' * 8
        self.gtk_kde = None
        # Change MAC Address to prevent being blacklisted by the network
        # Using iproute2
        #m = utility.utils.randomMAC()
        #os.system("ip link set dev %s down" % (self.iface))
        #os.system("ip link set dev %s address %s" % (self.iface, m))
        #os.system("ip link set dev %s up" % (self.iface))
        #self.staMac = str2mac(get_if_raw_hwaddr(self.iface)[1])
        #print "injector mac randomized, new mac: %s" % m
        #self.eapol.staMacbin = a2b_hex(self.staMac.lower().replace(":",""))
        self._buildQueries()

    # Send raw packet
    def send(self, packet, count=1, addr1=None, addr2=None, addr3=None):
        packet.SC = (self.sc_send << 4)
        if not addr1:
            packet.addr1 = self.bssid
        else:
            packet.addr1 = addr1
        if not addr2:
            packet.addr2 = self.staMac
        else:
            packet.addr2 = addr2
        if not addr3:
            packet.addr3 = self.bssid
        else:
            packet.addr3 = addr3

        self.sc_send = self.sc_send + 1
        sendp(packet, iface=self.iface, verbose=0, count=count)

    # Send frame encrypted with AES-CCMP
    def sendAESFrame(self, payload, addr1, addr2, addr3, count=1):

        dot11 = Dot11(addr1=addr1, addr2=addr2, addr3=addr3, FCfield=0x41, type=0x2, subtype=0x0)
        dot11wep = self.aesHandler.encapsulate(str(payload), self.eapol.tk , addr1, addr2, addr3)
        packet = RadioTap()/dot11/dot11wep

        self.sc_send = self.sc_send + 1
        sendp(packet, iface=self.iface, verbose=0, count=1)

    # Send frame encrypted with TKIP
    def sendTKIPFrame(self, payload, addr1, addr2, addr3, count=1):

        # Retrieve the ARP Request message and generate the headers.
        dot11 = Dot11(addr1=addr1, addr2=addr2, addr3=addr3, FCfield='wep+to-DS', type='Data', subtype=0)
        dot11wep = self.tkipHandler.encapsulate(str(payload), a2b_hex(addr2.lower().replace(":","")), \
        a2b_hex(addr1.lower().replace(":","")), 0, self.eapol.mmirxk , self.eapol.tk)
        packet = RadioTap()/dot11/dot11wep

        self.sc_send = self.sc_send + 1
        sendp(packet, iface=self.iface, verbose=0, count=1)

    # Decrypt response with AES-CCMP
    def decryptTrafficAES(self, p):
        plaintext = self.aesHandler.decapsulate(p, self.eapol.tk)
        return self.aesHandler.deBuilder(p, plaintext, False)

    # Decrypt response with TKIP
    def decryptTrafficTKIP(self, p):
        plaintext = self.tkipHandler.decapsulate(p, self.eapol.tk, self.eapol.mmitxk)
        return self.tkipHandler.deBuilder(p, plaintext, False)

    def _buildQueries(self):
        # Construct all the static frames that are supported by learner.
        self.queries = {
            'AssoReq':(RadioTap() / Dot11()
                       / Dot11AssoReq(cap="short-slot+ESS+privacy+short-preamble")
                       / Dot11Elt(ID='SSID', info=self.ssid)
                       / Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24")),

            'AssoResp':(RadioTap() / Dot11() / Dot11AssoResp()),

            'Disas':(RadioTap() / Dot11() / Dot11Disas()),

            'ReassoReq':(RadioTap() / Dot11()
                         / Dot11ReassoReq(cap="short-slot+ESS+privacy+short-preamble")
                         / Dot11Elt(ID='SSID', info=self.ssid)
                         / Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24")
                         / Dot11Elt(ID='RSNinfo', info=a2b_hex(self.RSNinfo))),

            'ReassoResp':RadioTap() / Dot11() / Dot11ReassoResp(),

            'Auth':RadioTap() / Dot11() / Dot11Auth(algo="open", seqnum=1),

            'Deauth':RadioTap() / Dot11() / Dot11Deauth(reason=7),

            'ProbeReq':(RadioTap() / Dot11() / Dot11ProbeReq() / Dot11Elt(ID='SSID', info=self.ssid)
                        / Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24")
                        / Dot11Elt(ID='RSNinfo', info=a2b_hex(self.RSNinfo))),

            'ProbeResp':(RadioTap() / Dot11() / Dot11ProbeResp()
                         / Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24")
                         / Dot11Elt(ID='RSNinfo', info=a2b_hex(self.RSNinfo))),

            'DHCPDisc':(LLC() / SNAP() / IP(src='0.0.0.0', dst='255.255.255.255')
                        / UDP(dport=67,sport=68)
                        / BOOTP(op=1, chaddr=get_if_raw_hwaddr(self.iface)[1], xid=random.randint(0, 0xFFFFFFFF))
                        / DHCP(options=[('message-type','discover'), 'end'])),

            'ARP':(LLC() / SNAP()
                   / ARP(op='who-has',
                         pdst=self.gateway,
                         psrc= self.ipsrc,
                         hwsrc=self.staMac,
                         hwdst=self.bssid))
            }

        # Hex rep of all possible RSN values (ciphersuites)
        self.rsnvals = {'tc':'0100000fac020100000fac040100000fac02', \
            'tt':'0100000fac020100000fac020100000fac02', \
            'cc':'0100000fac040100000fac040100000fac02', \
            'ct':'0100000fac040100000fac020100000fac02', \
            'ww':'0100000fac010100000fac010100000fac02', \
            'wpa1':'dd160050f20101000050f20201000050f20401000050f202'}

        self.kdvals = {'WPA2':'02', \
                'WPA1':'fe', \
                'RAND': '10'}

        self.ciphervals = {'MD5':0x09, \
                'SHA1':0x0a}

        self.rsnvalsRev = {v: k for k, v in self.rsnvals.items()}
