#!/usr/bin/env python2.7
from scapy.all import *
from crypto.michael import Michael
from crypto.tkip_key_mixing import TKIP_Mixer
from crypto.util import calculateCRC , hasFCS , assertDot11FCS
from utility.utils import setBit
import binascii

# Author: Domien Schepers
# Modified: Chris McMahon Stone

class HandleTKIP:
	""" Handles Temporal Key Integrity Protocol (TKIP) encapsulation and decapsulation.
	"""

	######################################################################################
	### Initializer ######################################################################
	######################################################################################
	
	def __init__( self  ):
		""" Initializer.
		"""
		# Initialize the Initialization Vector (IV).
		self.iv = 0
		self.pt = Packet()
		
	def __getIV( self ):
		""" Get the Initialization Vector (IV) for encapsulation.
			FIXME: Bounds checking.
		"""
		self.iv += 1
		return self.iv
		
	######################################################################################
	### Helpers ##########################################################################
	######################################################################################
		
	def __getTKIPParameters( self , keyid = 0 , extendedIV = 0 ):
		""" Get the TKIP Parameters (Key Identifier, IV, and Extended IV) in the required
			format. The default values for the Key Identifier and Extended IV are zero.
			Ref. IEEE 802.11i specification; TKIP MPDU formats.
		"""
	
		# Pad the extended IV to six octets.
		paddedIV 	= '{0:0{1}x}'.format( extendedIV , 12 )
		tsc		= struct.unpack( '6B' , paddedIV.decode('hex') )
		tsc 		= tuple( reversed( tsc ) ) # Change byte order.
	
		# Set the Extended IV flag in the key identifier.
		keyid 		= setBit( keyid , 5 )
	
		# Construct the IV.
		iv0 		= tsc[1]
		iv1 		= (tsc[1] | 0x20) & 0x7f
		iv2 		= tsc[0]
		iv 		= struct.pack( '3B' , iv0 , iv1 , iv2 )
	
		# Construct the extended IV.
		extIV0 		= tsc[2]
		extIV1 		= tsc[3]
		extIV2 		= tsc[4]
		extIV3 		= tsc[5]
		extendedIV 	= struct.pack( '4B' , extIV0 , extIV1 , extIV2 , extIV3 )

		# Return the Key Identifier, the IV, and the Extended IV.
		return keyid , iv , extendedIV

	def __getTSC( self , iv , keyid , extendedIV ):
		""" Retrieve the TKIP Sequence Counter (TSC) from the IV, Key ID, and Extended IV.
			Ref. IEEE 802.11i specification; Construction of expanded TKIP MPDU.
		"""
		iv8 	= struct.unpack( '8B' , iv + keyid + extendedIV )
		tsc0 	= iv8[2]
		tsc1 	= iv8[0]
		tsc2 	= iv8[4]
		tsc3 	= iv8[5]
		tsc4 	= iv8[6]
		tsc5 	= iv8[7]
		tsc 	= struct.pack( '6B' , tsc0 , tsc1 , tsc2 , tsc3 , tsc4 , tsc5 )
		return tsc
	
	######################################################################################
	### Encapsulation and Decapsulation ##################################################
	######################################################################################
	
	def encapsulate( self , plaintext , sa , da , priority , MMICRxK , TK ):
		""" Encapsulate TKIP and return the encapsulated message.
			Ref. IEEE 802.11i specification; Temporal Key Integrity Protocol (TKIP).
		"""
	
		# Calculate the Michael MIC over the plaintext.
		michael 	= Michael( MMICRxK , sa , da , priority , plaintext )
		plaintext	= plaintext + michael.hash()
	
		# Generate the TKIP parameters and the encryption key.
		keyid , iv , extendedIV = self.__getTKIPParameters( extendedIV=self.__getIV() )
		tsc 		= self.__getTSC( iv , format(keyid,'x').decode('hex') , extendedIV )
		mixer 		= TKIP_Mixer( TK , sa )
		key 		= mixer.newKey( tsc  )
	
		# Encrypt the plaintext and calculate the ICV.
		arc4		= ARC4.new( key )
		wepdata		= extendedIV + arc4.encrypt( plaintext )
		icv 		= calculateCRC( arc4 , plaintext )
	
		# Return the encapsulated TKIP message.
		return Dot11WEP( iv=iv , keyid=keyid , wepdata=wepdata , icv=icv )

	def decapsulate( self , packet , TK , MichealMIC ):
		""" Decapsulate TKIP and return the plaintext.
			Ref. IEEE 802.11i specification; Temporal Key Integrity Protocol (TKIP).
		"""
		assert( packet.haslayer( Dot11WEP ) ), \
			'The given packet does not contain a Dot11WEP message (decapsulating TKIP).'
		dot11wep = packet.getlayer( Dot11WEP )
	
		# Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header.
		# If true assert the correctness of the FCS, and remove the FCS by shifting
		# the packet ICV and wepdata accordingly to keep consistency with non-FCS
		# implementations.
		radiotapFCSFlag	= hasFCS( packet )
		if radiotapFCSFlag is True:
			assertDot11FCS( packet , expectedFCS=dot11wep.icv )
			dot11wep.icv 		= int( dot11wep.wepdata[-4:].encode('hex') , 16 ) # Integer for consistency.
			dot11wep.wepdata 	= dot11wep.wepdata[:-4]
	
		# Retrieve the Dot11 Packet Information.
		packet		= packet.getlayer( Dot11 )
		addr1 		= binascii.a2b_hex( packet.addr1.replace( ':' , '' ) )
		addr2 		= binascii.a2b_hex( packet.addr2.replace( ':' , '' ) )
		addr3 		= binascii.a2b_hex( packet.addr3.replace( ':' , '' ) )
		
		# Retrieve the Dot11WEP Packet Information.
		packet 		= packet.getlayer( Dot11WEP )
		iv		= packet.iv
		keyid 		= packet.keyid
		keyid		= format(keyid,'x').decode('hex')
		icv 		= packet.icv
		ciphertext	= packet.wepdata
		extendedIV 	= ciphertext[:4]
		ciphertext	= ciphertext[4:]
		tsc 		= self.__getTSC( iv , keyid , extendedIV )
		priority	= 0
	
		# Generate the key and decrypt the ciphertext.
		mixer 		= TKIP_Mixer( TK , addr2 )
		key 		= mixer.newKey( tsc )
		arc4 		= ARC4.new( key )
		plaintext 	= arc4.decrypt( ciphertext )
	
		# Calculate the ICV and assert its correctness on the received ICV.
		icvCalculated 	= calculateCRC( arc4 , plaintext )
		assert( icv == icvCalculated ), \
			'The received ICV "0x%x" does not match the calculated ICV "0x%x".' \
			% ( icv , icvCalculated )
		
		# Remove the Michael MIC from the plaintext, and recalculate the Michael MIC over the
		# plaintext.
		michaelReceived 	= plaintext[-8:]
		plaintext 		= plaintext[:-8]
		michael 		= Michael( MichealMIC , addr3 , addr1 , priority , plaintext )
		michaelCalculated 	= michael.hash()
	
		# Assert that the Michael MIC's match.
		assert( michaelReceived == michaelCalculated ), \
			'The received Michael MIC "%s" does not match the calculated Michael MIC "%s".' \
			% ( michaelReceived.encode('hex') , michaelCalculated.encode('hex') )
				
		# Return the plaintext.
		return plaintext
		
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
