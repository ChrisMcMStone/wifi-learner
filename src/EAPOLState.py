from scapy.all import *
from binascii import *
import hmac, hashlib
from utility.pbkdf2 import *
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Maintains state of and constructs EAPOL messages in 4-Way handshake
class EAPOLState:
    def __init__(self, RSNinfo, psk, ssid, staMac, apMac):

		# Fixed supplicant nonce
		self.Snonce = a2b_hex('10'*32)

		# WPA Key data
		self.RSNinfo = RSNinfo

		# SSID
		self.ssid = ssid

		# Pairwise Master Key generated using Pre-Shared Key
		self.pmk = pbkdf2_bin(psk, ssid, 4096, 32)

		# MAC addresses of AP and STA
		self.apMacbin = a2b_hex(apMac.lower().replace(":",""))
		self.staMacbin = a2b_hex(staMac.lower().replace(":",""))

		# Initialize keys ready to be calculated after AP has sent it's nonce
		self.ptk = '00'*64
		self.kck = '00'*16
		self.kek = '00'*16
		self.tk = '00'*16
		self.mmitxk	= None	# Michael MIC Authenticator Tx Key
		self.mmirxk	= None	# Michael MIC Authenticator Rx Key

		# Initialize 4-way handshake eapol frames
		self.frame2 = None
		self.frame4 = None

		# Initialize packet number counter
		self.PN = 0

    def buildFrame2(self, Anonce, ReplayCounter, invalidMic=False, rsnInfo=None, kd=None, cipher=None, kf=None):

		# Calculate Pairwise Transient Key
		A = "Pairwise key expansion"
		B = min(self.apMacbin,self.staMacbin)+max(self.apMacbin,self.staMacbin) \
			+min(Anonce,self.Snonce)+max(Anonce,self.Snonce)
		self.ptk = customPRF512(self.pmk, A, B)

		# Extract Keys from the pairwise transient key
		self.kck = self.ptk[0:16]
		self.kek = self.ptk[16:32]
		self.tk = self.ptk[32:48]
		self.mmitxk = self.ptk[48:56]
		self.mmirxk = self.ptk[56:64]

		# Set up 2nd EAPOL frame with zero-ed out MIC
		frameToMIC = None
		frameToMIC = self.buildEapolFrame(ReplayCounter=ReplayCounter,rsnInfo=rsnInfo, kd=kd, cipher=cipher, kf=kf)

		mic = None
		if cipher == None or cipher == '0a' or cipher == '02':
			# Calculate MIC over entire EAPOL frame using KCK
			mic = hmac.new(self.kck, str(frameToMIC), hashlib.sha1).hexdigest()[0:32]
		else:
			# Calculate MIC over entire EAPOL frame using KCK
			mic = hmac.new(self.kck, str(frameToMIC), hashlib.md5).hexdigest()[0:32]

		if(invalidMic):
			mic = '1'*32

		# Insert MIC into previously zero-ed out field of frame
		self.frame2 = RadioTap()/Dot11(FCfield="to-DS")/LLC()/SNAP()/\
			self.insertMIC(frameToMIC, mic)
		return self.frame2
				# message4 = sul.eapol.buildFrame4(Snonce=nonce, \
						# ReplayCounter=rc, invalidMic=invalidMic, \
						# rsnInfo=rsne, kd=kd, cipher=cipher)

    def buildFrame4(self, ReplayCounter, Snonce=None, invalidMic=False, rsnInfo=None, kd=None, cipher=None, kf=None):

		frameToMIC = None
		# Set up 4th EAPOL frame with zero-ed out MIC
		frameToMIC = self.buildEapolFrame(messageNo=4, ReplayCounter=ReplayCounter, rsnInfo=rsnInfo, kd=kd, cipher=cipher, nonce=Snonce, kf=kf)

		mic = None
		if cipher == None or cipher == '0a' or cipher == '02':
			# Calculate MIC over entire EAPOL frame using KCK
			mic = hmac.new(self.kck, str(frameToMIC), hashlib.sha1).hexdigest()[0:32]
		else:
			# Calculate MIC over entire EAPOL frame using KCK
			mic = hmac.new(self.kck, str(frameToMIC), hashlib.md5).hexdigest()[0:32]

		if(invalidMic):
			mic = '1'*32

		# Insert MIC into previously zero-ed out field of frame
		self.frame4 = RadioTap()/Dot11(FCfield="to-DS")/LLC()/SNAP()/\
			self.insertMIC(frameToMIC, mic)

		return self.frame4

    def insertMIC(self, frame, mic):

		frame_hex = b2a_hex(str(frame))
		done = frame_hex[8:162] + mic + frame_hex[194:]
		return EAPOL(type="EAPOL-Key")/Raw(load=a2b_hex(done))

    def buildEapolFrame(self, messageNo = 2, MIC = '00'*16,\
	ReplayCounter='00'*8, randomPayload=False, rsnInfo=None, kd=None, cipher=None, nonce=None,kf=None):

		RSN_KEY = ''
		if kd == None:
			RSN_KEY  += '02'                                # RSN Key type
		else:
			RSN_KEY += kd

		if(messageNo == 2 and not kf):
			RSN_KEY += '01'                               # pairwise set + mic set
		elif(messageNo == 4 and not kf):
			RSN_KEY += '03'                               # secure set + mic set
		else:
			RSN_KEY += kf

		if cipher == None:
			RSN_KEY += '0a'                               # HMAC_SHA1_AES
		else:
			RSN_KEY += cipher

		RSN_KEY += '0000'                                   # Key Length

		zeroAppend = 16 - len(str(ReplayCounter))
		rc = ('0'*zeroAppend) + str(ReplayCounter)
		RSN_KEY += rc                                       # ReplayCounter

		if(messageNo == 2):
			RSN_KEY +=  b2a_hex(self.Snonce)                # Snonce
		else:
			if nonce == None:
				RSN_KEY += '00'*32                              # Zero-ed out nonce
			else:
				RSN_KEY += nonce                              # Zero-ed out nonce

		RSN_KEY += '00'*16                                   # Key IV
		RSN_KEY += '00'*8                                   # WPA Key RSC
		RSN_KEY += '00'*8                                   # WPA Key ID 
		RSN_KEY += MIC                                      # WPA Key MIC (Initially zero-ed out)

		if(messageNo == 2):
			if rsnInfo == None: 
				rsnInfo = self.RSNinfo

			RSN_KEY += '00' + \
				hex((len(rsnInfo)/2)+2)[2:] \
				+ '3014' + rsnInfo
		else:
			RSN_KEY += '0000'

		return EAPOL(type="EAPOL-Key")/Raw(load=a2b_hex(RSN_KEY))
