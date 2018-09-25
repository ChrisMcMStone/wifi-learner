
# Taken from https://github.com/ICSec/pyDot11

from Cryptodome.Cipher import AES
from scapy.layers.dot11 import RadioTap, Dot11, Dot11WEP
from scapy.layers.l2 import LLC
from scapy.layers.inet import IP
from scapy.packet import Raw, Padding
from scapy.utils import hexstr
from utils import Packet
from zlib import crc32
import binascii, re, struct, sys

class Ccmp(object):
    """All things CCMP related"""

    def __init__(self):
        self.pt = Packet()

    def toDS(self, pkt):
        return pkt[Dot11].FCfield & 0x1 > 0

    def fromDS(self, pkt):
        return pkt[Dot11].FCfield & 0x2 > 0

    def moreFrag(self, pkt):
        return pkt[Dot11].FCfield & 0x4 > 0

    def order(self, pkt):
        return pkt[Dot11].FCfield & 0x128 > 0

    def fragNum(self, pkt):
        if sys.byteorder == 'little':
            return pkt[Dot11].SC & 0xf
        else:
            return (pkt[Dot11].SC >> 8) & 0xf

    def bcopy(self, src, dst, src_offset, dst_offset):
        for i in range(0, len(src)):
            dst[i + dst_offset] = src[i + src_offset]

    def xorRange(self, src1, src2, dst, sz):
        for i in range(0, sz):
            try:
                dst[i] = src1[i] ^ src2[i]
            except:
                pass
        return bytearray(dst)

    ## Here we must find if the packet has FCS. This isn't easy because this field isn't always in the same place.
    def hasFCS(self, pkt):

        ## These bits are relative to a single byte, not 4 bytes.
        TSFT = 1 << 0
        FCS  = 1 << 4
        Ext  = 1 << 7

        pktbytes = bytearray(str(pkt))

        ## If packet has TSFT we have to skip that field later on to find Flags
        hasTSFT = bool(pktbytes[4] & TSFT)

        ## Start seaching for Flags on byte 8
        i = 7
        hasExt = pktbytes[i] & Ext

        ## Skip extra present flags that may be present
        if hasExt:
            radiotap_len = pktbytes[2]
            while i < radiotap_len:
                hasExt = pktbytes[i] & Ext
                if not hasExt:
                    break
                i += 4
        else:
            i += 1

        ## Skip MAC timestamp
        if hasTSFT:
            i += 9

        ## Flags are here
        flags = pktbytes[i]

        if flags & FCS:
            #print 'Packet has FCS'
            return True
        else:
            #print 'Packet has NO FCS'
            return False


    def decoder(self, origPkt, aesKey):
        """Decrypt the packet
        For normal 802.11 usage, there will be an FCS present
        Thus, we are forcing this step
        If we wanted to check against non FCSd packets
        We could use the function self.hasFCS(pkt)
        If it returned false, then we could simply do:
        pload = str(origPkt[Dot11WEP])
        """

        ## Remove the FCS so that we maintain packet size
        pload = self.pt.byteRip(origPkt[Dot11WEP],
                                order = 'last',
                                qty = 4,
                                chop = True,
                                output = 'str')

        dot11 = origPkt[Dot11]
        MIC = bytearray(16)
        PN = bytearray(6)

        ## Get the IV
        PN[0] = pload[7]
        PN[1] = pload[6]
        PN[2] = pload[4]
        PN[3] = pload[5]
        PN[4] = pload[1]
        PN[5] = pload[0]

        ## AAD is used to generate the MIC, it has to be filled with some packet data.
        AAD = bytearray(32)
        AAD[0] = 0
        AAD[1] = 22 + 6*int(self.fromDS(origPkt) and self.toDS(origPkt))
        if dot11.subtype == 8:
            AAD[1] += 2

        AAD[2] = dot11.proto | (dot11.type << 2) | ((dot11.subtype << 4) & 0x80)
        AAD[3] = 0x40 | self.toDS(origPkt) | (self.fromDS(origPkt) << 1) | (self.moreFrag(origPkt) << 2) | (self.order(origPkt) << 7)
        self.bcopy(bytearray(re.sub(':','', dot11.addr1).decode("hex")), AAD, 0, 4)
        self.bcopy(bytearray(re.sub(':','', dot11.addr2).decode("hex")), AAD, 0, 10)
        self.bcopy(bytearray(re.sub(':','', dot11.addr3).decode("hex")), AAD, 0, 16)

        AAD[22] = self.fragNum(origPkt)
        AAD[23] = 0

        if self.fromDS(origPkt) and self.toDS(origPkt):
            self.bcopy(bytearray(re.sub(':','', dot11.addr4).decode("hex")), AAD, 0, 24)

        ## DEBUG
        #print "".join("{:02x} ".format(e) for e in AAD)

        crypted_block = [0]*16
        total_sz = len(pload) - 16
        offset = 8
        blocks = (total_sz + 15) / 16

        ## DEBUG
        #print("%d %d %d" % (total_sz, offset, blocks))

        ### Duplication?
        counter = bytearray(16)
        counter[0] = 0x59
        counter[1] = 0
        
        self.bcopy(bytearray(re.sub(':','', dot11.addr2).decode("hex")), counter, 0, 2)
        self.bcopy(PN, counter, 0, 8)
        counter[14] = (total_sz >> 8) & 0xff
        counter[15] = total_sz & 0xff
        
        ## DEBUG
        #print "".join("{:02x} ".format(e) for e in counter)

        MIC = bytearray(aesKey.encrypt(str(counter)))
        MIC = self.xorRange(MIC, AAD, MIC, 16)
        MIC = bytearray(aesKey.encrypt(str(MIC)))
        MIC = self.xorRange(MIC, AAD[16:], MIC, 16)
        MIC = bytearray(aesKey.encrypt(str(MIC)))

        ### Duplication?
        counter[0] &= 0x07
        counter[14] = 0
        counter[15] = 0

        crypted_block = aesKey.encrypt(str(counter))
        nice_MIC = bytearray(pload[total_sz+8:])
        
        ## DEBUG
        #print("%d %d %d" % (total_sz, offset, blocks))
        
        self.xorRange(bytearray(crypted_block), nice_MIC, nice_MIC, 8)

        ## Decrypt packet with CCMP
        stream = ''
        
        last = total_sz % 16
        
        for i in range(1, blocks + 1):
            if last > 0 and i == blocks:
                block_sz = last
                #block_sz = total_sz % 16
            else:
                block_sz = 16

            counter[14] = (i >> 18) & 0xff
            counter[15] = i & 0xff
            crypted_block = aesKey.encrypt(str(counter))

            pload1 = bytearray(pload[offset:])
            pload2 = bytearray(pload[(i - 1) * 16:])
            cb = bytearray(crypted_block)
            self.xorRange(cb, pload1, pload2, block_sz)
            self.xorRange(MIC, pload2, MIC, block_sz)
            MIC = bytearray(aesKey.encrypt(str(MIC)))

            stream += pload2[:block_sz]
            offset += block_sz

        #stream += pload2[block_sz:]

        return stream, PN


    def deBuilder(self, packet, stream, genFCS):
        """Return the decrypted packet"""

        ## Remove the FCS from the old packet body
        postPkt = RadioTap(self.pt.byteRip(packet.copy(),
                                           chop = True,
                                           order = 'last',
                                           output = 'str',
                                           qty = 4))

        ## Remove RadioTap() info if required
        if genFCS is False:
            postPkt = RadioTap()/postPkt[RadioTap].payload
        
        ## Rip off the Dot11WEP layer
        del postPkt[Dot11WEP]

        ## Add the stream to LLC
        decodedPkt = postPkt/LLC(str(stream))

        ## Flip FCField bits accordingly
        if decodedPkt[Dot11].FCfield == 65L:
            decodedPkt[Dot11].FCfield = 1L
        elif decodedPkt[Dot11].FCfield == 66L:
            decodedPkt[Dot11].FCfield = 2L

        ## Return the decoded packet with or without FCS
        if genFCS is False:
            return decodedPkt
        else:
            return decodedPkt/Padding(load = binascii.unhexlify(self.pt.endSwap(hex(crc32(str(decodedPkt[Dot11])) & 0xffffffff)).replace('0x', '')))


    def encryptCCMP(self, pkt, aesKey, PN, genFCS):
        """Encrypts a packet with CCMP
        Given the packet as pkt
        The temporal key contained within AES as aesKey
        The PN as PN
        
        This function expects a packet not to have FCS
        If one wanted to implement this function being able to deal with FCS
        pload = self.pt.byteRip(pkt[LLC],
                                order = 'last',
                                qty = 4,
                                chop = True,
                                output = 'str')
        """
        
        ## Obtain the LLC in str format
        pload = str(pkt[LLC])

        dot11 = pkt[Dot11]
        MIC = bytearray(16)

        # We have to prepend the CCMP header to the pload
        total_sz = len(pload)
        ccmphdr = bytearray([PN[5], PN[4], 0x00, 0x20, PN[3], PN[2], PN[1], PN[0]])
        pload = ccmphdr + pload

        ## AAD is used to generate the MIC, it has to be filled with some packet data.
        AAD = bytearray(32)
        AAD[0] = 0
        AAD[1] = 22 + 6*int(self.fromDS(pkt) and self.toDS(pkt))
        if dot11.subtype == 8:
            AAD[1] += 2
        AAD[2] = dot11.proto | (dot11.type << 2) | ((dot11.subtype << 4) & 0x80)
        AAD[3] = 0x40 | self.toDS(pkt) | (self.fromDS(pkt) << 1) | (self.moreFrag(pkt) << 2) | (self.order(pkt) << 7)
        self.bcopy(bytearray(re.sub(':','', dot11.addr1).decode("hex")), AAD, 0, 4)
        self.bcopy(bytearray(re.sub(':','', dot11.addr2).decode("hex")), AAD, 0, 10)
        self.bcopy(bytearray(re.sub(':','', dot11.addr3).decode("hex")), AAD, 0, 16)
        AAD[22] = self.fragNum(pkt)
        AAD[23] = 0

        if self.fromDS(pkt) and self.toDS(pkt):
            self.bcopy(bytearray(re.sub(':','', dot11.addr4).decode("hex")), AAD, 0, 24)
        
        ### This can be done ahead of time or not objectified
        crypted_block = [0]*16
        offset = 8
        
        blocks = (total_sz + 15) / 16
        
        ### This can be done ahead of time or not objectified
        counter = bytearray(16)
        counter[0] = 0x59
        counter[1] = 0
        
        self.bcopy(bytearray(re.sub(':','', dot11.addr2).decode("hex")), counter, 0, 2)
        self.bcopy(PN, counter, 0, 8)
        counter[14] = (total_sz >> 8) & 0xff
        counter[15] = total_sz & 0xff
        MIC = bytearray(aesKey.encrypt(str(counter)))
        self.xorRange(MIC, AAD, MIC, 16)
        MIC = bytearray(aesKey.encrypt(str(MIC)))
        self.xorRange(MIC, AAD[16:], MIC, 16)
        MIC = bytearray(aesKey.encrypt(str(MIC)))
        
        ### Can we do this ahead of time?
        counter[0] &= 0x07
        counter[14] = 0
        counter[15] = 0

        ## Calculate and append the MIC
        crypted_block = aesKey.encrypt(str(counter))
        pload += bytearray(crypted_block)[:8]

        ## Encrypt packet with CCMP
        encrypted = ''
        last = total_sz % 16
        for i in range(1, blocks+1):
            if( last > 0 and i == blocks):
                block_sz = last
            else:
                block_sz = 16

            pload1 = bytearray(pload[offset:])
            self.xorRange(MIC, pload1, MIC, block_sz)
            MIC = bytearray(aesKey.encrypt(str(MIC)))
            counter[14] = (i >> 8) & 0xff
            counter[15] = i & 0xff
            crypted_block = aesKey.encrypt(str(counter))
            cb = bytearray(crypted_block)
            pload2 = bytearray(pload[(i - 1) * 16:])
            self.xorRange(cb, pload1, pload2, block_sz)
            encrypted += pload2[:block_sz]
            offset += block_sz

        pload1 = bytearray(pload[offset:])
        self.xorRange(pload1, MIC, pload1, 8)
        encrypted = ccmphdr + encrypted + pload1
        
        del pkt[LLC]
        finalPkt = pkt/Raw(encrypted)

        ## Return the encrypted packet with or without FCS
        if genFCS is True:
            return finalPkt/Raw(binascii.unhexlify(self.pt.endSwap(hex(crc32(str(finalPkt[Dot11])) & 0xffffffff)).replace('0x', '')))
        else:
            return finalPkt
