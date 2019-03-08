import random
import binascii
from scapy.all import *
import struct
from zlib import crc32
from Cryptodome.Cipher import AES
import os

def long2bytes(n):
    length = 10
    #s = str(n)
    #length = len(s)
    return ('%%0%dx' % (length << 1) % n).decode('hex')[-length:]

## Code taken and adapted from https://github.com/beurdouche/tools/blob/master/pyrit/pyrit/cpyrit/

def str2hex(string):
    """Convert a string to it's hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))


class XStrFixedLenField(scapy.fields.StrFixedLenField):
    """String-Field with nice repr() for hexdecimal strings"""

    def i2repr(self, pkt, x):
        return str2hex(scapy.fields.StrFixedLenField.i2m(self, pkt, x))


class XStrLenField(scapy.fields.StrLenField):
    """String-Field of variable size with nice repr() for hexdecimal strings"""

    def i2repr(self, pkt, x):
        return str2hex(scapy.fields.StrLenField.i2m(self, pkt, x))


class EAPOL_Key(scapy.packet.Packet):
    """EAPOL Key frame"""
    name = "EAPOL Key"
    fields_desc = [scapy.fields.ByteEnumField("DescType", 254,
                                                {2: "RSN Key",
                                                254: "WPA Key"})]
scapy.packet.bind_layers(scapy.layers.eap.EAPOL, EAPOL_Key, type=3)


class EAPOL_AbstractEAPOLKey(scapy.packet.Packet):
    """Base-class for EAPOL WPA/RSN-Key frames"""
    fields_desc = [scapy.fields.FlagsField("KeyInfo", 0, 16,
                                ["HMAC_MD5_RC4", "HMAC_SHA1_AES", "undefined", \
                                 "pairwise", "idx1", "idx2", "install", \
                                 "ack", "mic", "secure", "error", "request", \
                                 "encrypted"]),
        scapy.fields.ShortField("KeyLength", 0),
        scapy.fields.LongField("ReplayCounter", 0),
        XStrFixedLenField("Nonce", '\x00' * 32, 32),
        XStrFixedLenField("KeyIV", '\x00' * 16, 16),
        XStrFixedLenField("WPAKeyRSC", '\x00' * 8, 8),
        XStrFixedLenField("WPAKeyID", '\x00' * 8, 8),
        XStrFixedLenField("WPAKeyMIC", '\x00' * 16, 16),
        scapy.fields.ShortField("WPAKeyLength", 0),
        scapy.fields.ConditionalField(
                            XStrLenField("WPAKey", None,
                                length_from=lambda pkt: pkt.WPAKeyLength), \
                            lambda pkt: pkt.WPAKeyLength > 0)]


class EAPOL_WPAKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL WPA Key"
    keyscheme = 'HMAC_MD5_RC4'
scapy.packet.bind_layers(EAPOL_Key, EAPOL_WPAKey, DescType=254)


class EAPOL_RSNKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL RSN Key"
    keyscheme = 'HMAC_SHA1_AES'
scapy.packet.bind_layers(EAPOL_Key, EAPOL_RSNKey, DescType=2)

def isFlagSet(packet, name, value):
    """Return True if the given field 'includes' the given value.
       Exact behaviour of this function is specific to the field-type.
    """
    field, val = packet.getfield_and_val(name)
    return str(value) in str(val)
    # if isinstance(field, scapy.fields.EnumField):
        # if val not in field.i2s:
            # return False
        # return field.i2s[val] == value
    # else:
        # print "got here"
        # return (1 << field.names.index([value])) & packet.__getattr__(name) != 0


def areFlagsSet(packet, name, values):
    """Return True if the given field 'includes' all of the given values."""
    return all(isFlagSet(packet, name, value) for value in values)


def areFlagsNotSet(packet, name, values):
    """Return True if the given field 'includes' none of the given values."""
    return all(not isFlagSet(packet, name, value) for value in values)

def getEapolLayer(p):
    if(EAPOL_RSNKey in p):
        return p[EAPOL_RSNKey]
    elif(EAPOL_WPAKey in p):
        return p[EAPOL_WPAKey]
    return None

def genEapolString(kp, sul):
    s = ''
    keyData = None
    if(validMessage1(kp)):
        s += 'E1'
    elif(validMessage3(kp)):
        s += 'E3'
        ### EXTRACT GTK
        # sul.gtk_kde = kp[EAPOL_RSNKey].WPAKey
        # gtk = binascii.b2a_hex(aes_unwrap_key(sul.eapol.kek, sul.gtk_kde))
        # decKeyData = str(gtk)
        # for rsn in sul.rsnvals:
            # if sul.rsnvals[rsn] in decKeyData:
                # keyData = "|RSNE=" + rsn

        # gtk_index = gtk.find("0fac01")
        # gtk = gtk[(gtk_index+10):(gtk_index+10+32)]
    else:
        S += 'EX'

    if(EAPOL_RSNKey in kp):
        s += '(KD=WPA2'
    elif(EAPOL_WPAKey in kp):
        s += '(KD=WPA1'
    else:
       return None

    if(isFlagSet(kp, 'KeyInfo', ('HMAC_SHA1_AES'))):
        s += '|CS=SHA1'
    elif(isFlagSet(kp, 'KeyInfo', ('HMAC_MD5_RC4'))):
        s += '|CS=MD5'

    #s += '[RC=' + str(kp.ReplayCounter) + ']'
    if keyData:
        s += keyData

    s += ')'
    return s


def validMessage1(wpakey_p):
    if(areFlagsSet(wpakey_p, 'KeyInfo', ('pairwise', 'ack')) \
            and areFlagsNotSet(wpakey_p, 'KeyInfo', ('install', 'mic'))):
        return True
    return False

def validMessage3(wpakey_p):
    if(areFlagsSet(wpakey_p, 'KeyInfo', ('pairwise', 'install', 'ack', 'mic'))):
        return True
    return False


## Taken from https://www.centos.org/docs/5/html/5.2/Virtualization/sect-Virtualization-Tips_and_tricks-Generating_a_new_unique_MAC_address.html

def randomMAC():
    mac = [ 0x00, 0x16, 0x3e,
    random.randint(0x00, 0x7f),
    random.randint(0x00, 0xff),
    random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def fillByteArray(b1, b2, start):
    for i in range(len(b2)):
        b1[start + i] = b2[i]
    return b1

## Taken from https://gist.github.com/kurtbrose/4243633

QUAD = struct.Struct('>Q')

def aes_unwrap_key_and_iv(kek, wrapped):
    n = len(wrapped)/8 - 1
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek).decrypt
    for j in range(5,-1,-1): #counting down
        for i in range(n, 0, -1): #(n, n-1, ..., 1)
            ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return "".join(R[1:]), A

#key wrapping as defined in RFC 3394
#http://www.ietf.org/rfc/rfc3394.txt
def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        print "Integrity Check Failed: "+hex(key_iv)+" (expected "+hex(iv)+")"
    return key

#alternate initial value for aes key wrapping, as defined in RFC 5649 section 3
#http://www.ietf.org/rfc/rfc5649.txt
def aes_unwrap_key_withpad(kek, wrapped):
    if len(wrapped) == 16:
        plaintext = AES.new(kek).decrypt(wrapped)
        key, key_iv = plaintext[:8], plaintext[8:]
    else:
        key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    key_iv = "{0:016X}".format(key_iv)
    if key_iv[:8] != "A65959A6":
        raise ValueError("Integrity Check Failed: "+key_iv[:8]+" (expected A65959A6)")
    key_len = int(key_iv[8:], 16)
    return key[:key_len]

def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext)/8
    R = [None]+[plaintext[i*8:i*8+8] for i in range(0, n)]
    A = iv
    encrypt = AES.new(kek).encrypt
    for j in range(6):
        for i in range(1, n+1):
            B = encrypt(QUAD.pack(A) + R[i])
            A = QUAD.unpack(B[:8])[0] ^ (n*j + i)
            R[i] = B[8:]
    return QUAD.pack(A) + "".join(R[1:])

def aes_wrap_key_withpad(kek, plaintext):
    iv = 0xA65959A600000000 + len(plaintext)
    plaintext = plaintext + "\0" * ((8 - len(plaintext)) % 8)
    if len(plaintext) == 8:
        return AES.new(kek).encrypt(QUAD.pack[iv] + plaintext)
    return aes_wrap_key(kek, plaintext, iv)


def setBit( value , index ):
    """ Set the index'th bit of value to 1.
    """
    mask = 1 << index
    value &= ~mask
    value |= mask
    return value

def getBit( value , index ):
    """ Get the index'th bit of value.
    """
    return (value >> index) & 1

def getKeyID( id ):
    """ Get the 8-bit key identifier from an integer.
    """
    assert( 0 <= id <= 3 ), \
    'The Key ID must be a value between 0 and 3 included.'
    keyid = 0x00
    if id == 1:
        keyid = setBit( keyid , 6 )
    if id == 2:
        keyid = setBit( keyid , 7 )
    if id == 3:
        keyid = setBit( keyid , 6 )
        keyid = setBit( keyid , 7 )
    return keyid

def printTerminalLine( character ):
    """ Print a horizontal line over the full width of the terminal screen.
    """
    os.system( "printf '%*s\n' \"${COLUMNS:-$(tput cols)}\" '' | tr ' ' " + character )

class Packet(object):
    """Class to deal with packet specific tasks"""

    def __init__(self):
        self.nonceDict = {'8a': 'a1',
                          '0a': 'a2',
                          'ca': 'a3',
                          '89': 't1',
                          '09': 't2',
                          'c9': 't3'}


    def byteRip(self, stream, chop = False, compress = False, order = 'first', output = 'hex', qty = 1):
        """Take a scapy hexstr(str(pkt), onlyhex = 1) and grab based on what you want
        chop is the concept of removing the qty based upon the order
        compress is the concept of removing unwanted spaces
        order is concept of give me first <qty> bytes or gives me last <qty> bytes
        output deals with how the user wishes the stream to be returned
        qty is how many nibbles to deal with

        QTY IS DOUBLE THE NUMBER OF BYTES
        THINK OF QTY AS A NIBBLE
        2 NIBBLES FOR EVERY BYTE

        Important to note that moving to a pure string versus a list,
        will probably help with memory consumption

        Eventually, need to add a kwarg that allows us to specify,
        which bytes we want, i.e. first and last based on order
        """

        def pktFlow(pkt, output):
            if output == 'hex':
                return pkt
            if output == 'str':
                return binascii.unhexlify(str(pkt).replace(' ', ''))

        stream = hexstr(str(stream), onlyhex = 1)
        streamList = stream.split(' ')
        streamLen = len(streamList)

        ## Deal with first bytes
        if order == 'first':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[0:qty]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[qty:]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[0:qty]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[qty:]).replace(' ', ''), output)

        ## Deal with last bytes
        if order == 'last':

            ## Deal with not chop and not compress
            if not chop and not compress:
                return pktFlow(' '.join(streamList[streamLen - qty:]), output)

            ## Deal with chop and not compress
            if chop and not compress:
                return pktFlow(' '.join(streamList[:-qty]), output)

            ## Deal with compress and not chop
            if compress and not chop:
                return pktFlow(' '.join(streamList[streamLen - qty:]).replace(' ', ''), output)

            ## Deal with chop and compress
            if chop and compress:
                return pktFlow(' '.join(streamList[:-qty]).replace(' ', ''), output)


    def endSwap(self, value):
        """Takes an object and reverse Endians the bytes
        Useful for crc32 within 802.11:
        Autodetection logic built in for the following situations:
        Will take the stryng '0xaabbcc' and return string '0xccbbaa'
        Will take the integer 12345 and return integer 14640
        Will take the bytestream string of 'aabbcc' and return string 'ccbbaa'
        """
        try:
            value = hex(value).replace('0x', '')
            sType = 'int'
        except:
            if '0x' in value:
                sType = 'hStr'
            else:
                sType = 'bStr'
            value = value.replace('0x', '')

        start = 0
        end = 2
        swapList = []
        for i in range(len(value)/2):
            swapList.append(value[start:end])
            start += 2
            end += 2
        swapList.reverse()
        s = ''
        for i in swapList:
            s += i

        if sType == 'int':
            s = int(s, 16)
        elif sType == 'hStr':
            s = '0x' + s
        return s


    def fcsGen(self, frame, start = None, end = None, mLength = 0, output = 'bytes'):
        """Return the FCS for a given frame"""
        frame = str(frame)
        frame = frame[start:end]
        frame = crc32(frame) & 0xffffffff
        fcs = hex(frame).replace('0x', '')
        while len(fcs) < mLength:
            fcs = '0' + fcs
        fcs = self.endSwap(fcs)
        if output == 'bytes':
            return fcs
        elif output == 'str':
            return binascii.unhexlify(fcs)
        else:
            return fcs

