from scapy.all import *
import struct
from binascii import *
from EAPOLState import EAPOLState
from Crypto.Cipher import AES as dAES
from Cryptodome.Cipher import AES
from ccmp import Ccmp
import time
import SULInterface
# from tkip import Tkip
# from mytkip import TKIP_encr
import utils, os

class SULState:

    def __init__(self, iface, ssid, psk, bssid, rsnInfo, gateway):
        self.iface = iface
        self.sniffPipe = None
        self.ssid = ssid
        self.bssid = bssid
        self.staMac = str2mac(get_if_raw_hwaddr(self.iface)[1])
        self.psk = psk
        self.sc_send = 0
        self.last_sc_receive = -1
        self.last_time_receive = 0.0
        self.maxAssociateAttempts = 10
        self.Anonce = '00' * 32
        self.ReplayCounter = '00' * 8
        self.gtk_kde = None
        self.RSNinfo = rsnInfo[:36] + '0000'
        self.RSNinfoReal = rsnInfo[:36] + '0000'
        self.gateway = gateway
        self._buildQueries()
        self.PN = bytearray('\x00\x00\x00\x00\x00\x00')
        self.TIMEOUT = 2.0
        # Initialize state of handshake for supplicant
        self.eapol = EAPOLState(self.RSNinfo, self.psk, \
                self.ssid, self.staMac, self.bssid)


    def reset(self):
        self.sc_send = 0
        #self.last_sc_receive = -1
        # Deauthenticate previously associated MAC to free up memory
        self.send(self.queries["Deauth"], count=5)
        self.last_time_receive = time.time()
        self.Anonce = '00' * 32
        self.ReplayCounter = '00' * 8
        self.gtk_kde = None

    # Association Filter
    # lfilter=lambda x: x.haslayer(Dot11) and x.addr1 == self.staMac and x.getlayer(Dot11).type != 1)

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

    def send_ccmp(self, payload):
        self.PN[5] += 1
        x = Ccmp()
        cipher = AES.new(self.eapol.tk, AES.MODE_ECB)
        p = RadioTap()/payload
        p.SC = (self.sc_send << 4)
        p.subtype = 0
        p.type = "Data"
        p.FCfield = 0x41
        enc_packet = x.encryptCCMP(p, cipher, self.PN, False)
            ## Flip FCField bits accordingly
        if enc_packet[Dot11].FCfield == 1L:
            enc_packet[Dot11].FCfield = 65L
        elif enc_packet[Dot11].FCfield == 2L:
            enc_packet[Dot11].FCfield = 66L

        self.sc_send = self.sc_send + 1
        print enc_packet.summary()
        print enc_packet.show()
        sendp(enc_packet, iface=self.iface, verbose=0, count=1)


                
    def sendEncryptedFrame(self, payload, addr1, addr2, addr3, count=1):  

        a1 = bytearray.fromhex(addr1.replace(':', ''))
        a2 = bytearray.fromhex(addr2.replace(':', ''))
        a3 = bytearray.fromhex(addr3.replace(':', ''))

        #self.PN[5] += 1
        
        # Set up CCMP header
        # Assumes no more than 255 data frames will be sent (for simplicity)
        ccmpHeader = bytearray(8)
        ccmpHeader[0] = self.PN[5]
        ccmpHeader[1] = self.PN[4]
        ccmpHeader[2] = 0b00000000 # rsv
        ccmpHeader[3] = 0b00100000 # keyid
        ccmpHeader[4] = self.PN[3]
        ccmpHeader[5] = self.PN[2]
        ccmpHeader[6] = self.PN[1]
        ccmpHeader[7] = self.PN[0]

        # Construct AAD required for MIC
        aad = bytearray(24)
        aad[0] = 0b00001000 # Frame control bits
        aad[1] = 0b01000001

        for i in range(6): # MAC Addresses
            aad[i+2] = a1[i]
            aad[i+8] = a2[i]
            aad[i+14] = a3[i]

        # 2 bytes for Sequence Control Field left at 0, TODO: deal with fragment No
        # 2 bytes for QoS Control field left at 0

        nonce = bytearray(13)
        # Nonce Flags (Priority, Management, Reserved) left at 0
        for i in range(6): # Address 2
            nonce[i+1] = a2[i]
            nonce[i+7] = self.PN[i]

        cipher = dAES.new(str(self.eapol.tk), AES.MODE_CCM, str(nonce), mac_len=8, assoc_len=22)
        cipher.update(str(aad))
        encrypted_payload = cipher.encrypt(str(payload))
        mic = cipher.digest()

        packet = RadioTap() / Dot11() / Raw(str(ccmpHeader)) / Raw(str(encrypted_payload)) / Raw(str(mic))
        packet.SC = (self.sc_send << 4)
        packet.addr1 = addr1
        packet.addr2 = addr2
        packet.addr3 = addr3
        packet.subtype = 0
        packet.type = "Data"
        packet.FCfield = 0x41

        self.sc_send = self.sc_send + 1
        #packet.show()
        sendp(packet, iface=self.iface, verbose=0, count=1)
    
    def decryptTrafficCcmp(self, p):
        x = Ccmp()
        y = AES.new(self.eapol.tk, AES.MODE_ECB)
        stream, PN = x.decoder(p, y)
        pckt = x.deBuilder(p, stream, False)
        return pckt

    # TODO Finish TKIP Support
    # def decryptTrafficTkip(self, p):
    #     x = Tkip()
    #     y = AES.new(self.eapol.tk, AES.MODE_ECB)
    #     stream = x.decoder(p, y)
    #     pckt = x.deBuilder(p, stream)
    #     return pckt

    # def sendEncTKIP(self, payload, addr1, addr2, addr3):
    #     ta = bytearray(re.sub(':','', addr1).decode("hex"))
    #     sa = bytearray(re.sub(':','', addr2).decode("hex"))
    #     da = bytearray(re.sub(':','', addr3).decode("hex"))

    #     self.PN[5] += 1
    #     iv = a2b_p("00 00 00 00 00 00")
    #     alg = TKIP_encr(self.eapol.tk)
    #     alg.setTA(ta)
    #     ciphertext = alg.encrypt(payload, iv, sa, da, self.eapol.tkipmic)

    #     packet = RadioTap() / Dot11() / Raw(ciphertext)
    #     packet.SC = 0
    #     packet.addr1 = addr1
    #     packet.addr2 = addr2
    #     packet.addr3 = addr3
    #     packet.subtype = 0
    #     packet.type = "Data"
    #     packet.FCfield = 0x41
    #     sendp(packet, iface=self.iface, verbose=0, count=1)

            
    def _buildQueries(self):

        self.queries = {\
            'AssoReq':RadioTap() / Dot11() / \
                   Dot11AssoReq(cap="short-slot+ESS+privacy+short-preamble") / \
                   Dot11Elt(ID='SSID', info=self.ssid) / \
                   Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24"),  \
            \
            'AssoResp':RadioTap() / Dot11() / Dot11AssoResp(), \
            \
            'Disas':RadioTap() / Dot11() / Dot11Disas(), \
            \
            'ReassoReq':RadioTap() / Dot11() / \
                   Dot11ReassoReq(cap="short-slot+ESS+privacy+short-preamble") / \
                   Dot11Elt(ID='SSID', info=self.ssid) / \
                   Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24") / \
                   Dot11Elt(ID='RSNinfo', info=a2b_hex(self.RSNinfo)), \
            \
            'ReassoResp':RadioTap() / Dot11() / Dot11ReassoResp(), \
            \
            'Auth':RadioTap() / Dot11() / Dot11Auth(algo="open", seqnum=1), \
            \
            'Deauth':RadioTap() / Dot11() / Dot11Deauth(reason=7), \
            \
            'ProbeReq':RadioTap() / Dot11() / Dot11ProbeReq() / \
                   Dot11Elt(ID='SSID', info=self.ssid) / \
                   Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24") / \
                   Dot11Elt(ID='RSNinfo', info=a2b_hex(self.RSNinfo)), \
            \
            'ProbeResp':RadioTap() / Dot11() / Dot11ProbeResp() / \
                   Dot11Elt(ID='Rates', info="\x82\x84\x02\x8b\x96\x04\x0b\x16\x0c\x12\x18\x24") / \
                   Dot11Elt(ID='RSNinfo', info=a2b_hex(self.RSNinfo)), \
            \
            'DHCPDisc':LLC() / SNAP() / IP(src='0.0.0.0', dst='255.255.255.255') / \
                   UDP(dport=67,sport=68) / BOOTP(op=1, chaddr=get_if_raw_hwaddr(self.iface)[1], xid=random.randint(0, 0xFFFFFFFF)) / \
                   DHCP(options=[('message-type','discover'), ('max_dhcp_size', 1500), ('hostname', 'test'), ('end')]),
            \
            'ARP':LLC() / SNAP() / ARP(pdst=self.gateway, hwsrc=self.staMac)
            }
            #'ARP':LLC() / SNAP() / ARP(op=ARP.who_has, pdst=self.gateway, psrc="192.168.0.1", hwsrc=self.staMac, hwdst=self.bssid)

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
