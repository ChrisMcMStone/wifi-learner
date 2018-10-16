#!/usr/bin/env python2.7
from scapy.all import *
from Crypto.Cipher import AES
from crypto.util import hasFCS , assertDot11FCS
from crypto.key_wrap import aes_unwrap_key
from utility.utils import setBit
from utility.utils import Packet
import binascii

# Author: Domien Schepers
# Modified: Chris McMahon Stone

class HandleAES:
	""" Handles CTR with CBC-MAC Protocol (CCMP) encapsulation and decapsulation under
		Advanced Encryption Standard (AES).
	"""

	######################################################################################
	### Initializer ######################################################################
	######################################################################################
	
	def __init__( self  ):
		""" Initializer.
		"""
		# Initialize the Packet Number (PN).
		self.pn = 0

		self.pt = Packet()
		
	def __getPN( self ):
		""" Get the next Packet Number (PN) for encapsulation.
			FIXME: Bounds checking.
		"""
		self.pn += 1
		return self.pn	
		
	######################################################################################
	### Helpers ##########################################################################
	######################################################################################
		
	def __getPNFromCCMPHeader( self , ccmpHeader ):
		""" Retrieve the Packet Number from the CCMP Header.
			Ref. IEEE 802.11i specification; CCMP MPDU format.
		"""
		ccmpHeader 	= struct.unpack( '8B' , ccmpHeader )
		pn0 		= ccmpHeader[7]
		pn1 		= ccmpHeader[6]
		pn2 		= ccmpHeader[5]
		pn3 		= ccmpHeader[4]
		pn4 		= ccmpHeader[1]
		pn5 		= ccmpHeader[0]
		pn		= struct.pack( '6B' , pn0 , pn1 , pn2 , pn3 , pn4 , pn5 )
		return pn
	
	def __getNonce( self , priority , address , pn ):
		""" Retrieve the Nonce from the priority, address and packet number.
			Ref. IEEE 802.11i specification; Construct CCM nonce.
		"""
		address = binascii.a2b_hex( address.replace( ':' , '' ) )
		nonce 	= priority + address + pn
		return nonce
	
	def __getAAD( self , fc , addr1 , addr2 , addr3 , sc ):
		""" Retrieve the Additional Authentication Data (AAD) from the Frame Control
			field, addresses, and Sequence Number.
			Ref. IEEE 802.11i specification; Construct AAD.
		
			The length of the AAD varies depending on the presence or absence of the QC
			and A4 fields. The QC and A4 field are currently not supported.
		"""
		addr1 	= binascii.a2b_hex( addr1.replace( ':' , '' ) )
		addr2 	= binascii.a2b_hex( addr2.replace( ':' , '' ) )
		addr3 	= binascii.a2b_hex( addr3.replace( ':' , '' ) )
		aad 	= fc + addr1 + addr2 + addr3 + sc
		return aad

	def __getFrameControlField( self , protocol , type , subtype , flags ):
		""" Get the Frame Control Field from the protocol, type, subtype and flags.
			The result is a string of two characters merging the given data.
			Ref. IEEE 802.11i specification; Frame Control field.
		"""
		result = (protocol << 2) + type
		result = (result << 2 ) + subtype
		return chr( result ) + chr( flags )

	def __getCCMPHeader( self , keyid , pn ):
		""" Get the CCMP Header from a given Key Identifier and Packet Number.
			Ref. IEEE 802.11i specification; CCMP MPDU format.
		"""
	
		# Pad the Packet Number to six octets.
		paddedPN 	= '{0:0{1}x}'.format( pn , 12 )
		pn		= struct.unpack( '6B' , paddedPN.decode('hex') )
		pn 		= tuple( reversed( pn ) ) # Change byte order.
	
		# Set the Extended IV flag in the key identifier.
		keyid 		= setBit( keyid , 5 )
	
		# Construct the CCMP Header.
		h0 = pn[0]
		h1 = pn[1]
		h2 = 0 # Reserved
		h3 = keyid
		h4 = pn[2]
		h5 = pn[3]
		h6 = pn[4]
		h7 = pn[5]
	
		# Pack and return the CCMP Header.
		ccmpHeader = struct.pack( '8B' , h0 , h1 , h2 , h3 , h4 , h5 , h6 , h7 )
		return ccmpHeader

	def __getSequenceControl( self , fragmentNumber , sequenceNumber ):
		""" Get the Sequence Control field. The Sequence Control field is 16 bits in
			length and consists of two subfields, the Fragment Number (4-bit) and the
			Sequence Number (12-bit). 
			Ref. IEEE 802.11i specification; Sequence Control field structure.
		"""
		assert( 0 <= fragmentNumber <= 15 ), \
			'The fragment number %d must be a value between 0 and 15 inclusive.' % ( fragmentNumber )
		assert( 0 <= sequenceNumber <= 143 ), \
			'The sequence number %d must be a value between 0 and 143 inclusive.' % ( sequenceNumber )
		return ( ( sequenceNumber << 4 ) + fragmentNumber )

	######################################################################################
	### Encapsulation, Decapsulation and Key Unwrapping ##################################
	######################################################################################

	def encapsulate( self , plaintext , TK , addr1 , addr2 , addr3 ):
		""" Encapsulate AES and return the encapsulated message.
			Ref. IEEE 802.11i specification; CTR with CBC-MAC Protocol (CCMP).
			NOTE: 	Wireshark does not automatically decrypt when SC has non-zero parameters?
				Currently assumed to be zero (if not SC should be returned for Dot11).
		"""
	
		# Generate the CCMP Header and AAD for encryption.
		ccmpHeader	= self.__getCCMPHeader( keyid=0 , pn=self.__getPN() )
		pn 		= self.__getPNFromCCMPHeader( ccmpHeader )
		nonce 		= self.__getNonce( chr(0) , addr2 , pn )
		fc 		= self.__getFrameControlField( protocol=0x0 , type=0x2 , subtype=0x0 , flags=0x41 )
		sc		= self.__getSequenceControl( fragmentNumber=0 , sequenceNumber=0 )
		scFormatted	= binascii.a2b_hex( '{:04x}'.format( sc ) )
		aad 		= self.__getAAD( fc , addr1 , addr2 , addr3 , scFormatted )
	
		# Encrypt the plaintext under AES in CCM Mode.
		# We have to transmit the CCMP Header + Cipher Text + Digest. Because of the
		# Dot11WEP structure (three octet iv, one octet keyid, four octet icv) we
		# assign the first three octets of the CCMP Header to the iv, and the fourth
		# octet to the keyid. Then we assign to wepdata the last four octets of the
		# CCMP Header, the cipher text and the first four octets of the digest.
		# Finally we use the last four octets of the digest for the MIC value.
		cipher 		= AES.new( TK , AES.MODE_CCM , nonce , mac_len=8 )
		cipher.update( aad )
		ciphertext	= cipher.encrypt( plaintext )
		mic 		= cipher.digest()
		iv		= ccmpHeader[0:3]
		keyid		= int( ccmpHeader[3:4].encode('hex') , 16 ) # Parse to int.
		wepdata		= ccmpHeader[4:8] + ciphertext + mic[0:4]
		mic 		= int( mic[4:8].encode('hex') , 16 ) # Parse to int.
	
		# Return the encapsulated AES message.
		return Dot11WEP( iv=iv , keyid=keyid , wepdata=wepdata, icv=mic )

	def decapsulate( self , packet , TK ):
		""" Decapsulate AES and return the plaintext.
			Ref. IEEE 802.11i specification; CTR with CBC-MAC Protocol (CCMP).
			TODO/FIXME: Should perform CCMP MIC verification.
		"""
		assert( packet.haslayer( Dot11WEP ) ), \
			'The given packet does not contain a Dot11WEP message (decapsulating AES).'
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
		dot11		= packet.getlayer( Dot11 )
		sc		= '%x' % dot11.SC
		fc 		= self.__getFrameControlField( dot11.proto , dot11.type , dot11.subtype , dot11.FCfield )
	
		# Retrieve the Dot11WEP Packet Information.
		iv		= dot11wep.iv
		keyid 		= dot11wep.keyid
		keyid		= format(keyid,'x').decode('hex')
		icv		= '{0:0{1}x}'.format( dot11wep.icv , 8 ) # Padding for leading zero.
		cipher		= dot11wep.wepdata
		extendedIV 	= cipher[:4]
		ciphertext	= cipher[4:-4]
		mic 		= cipher[-4:] + icv # FIXME: MIC currently not in use.	
	
		# Retrieve the Packet Number, Nonce and Additional Authentication Data (AAD).
		ccmpHeader	= iv + keyid + extendedIV
		pn 		= self.__getPNFromCCMPHeader( ccmpHeader )
		nonce		= self.__getNonce( chr(0) , dot11.addr2 , pn )
		aad		= self.__getAAD( fc , dot11.addr1 , dot11.addr2 , dot11.addr3 , sc )
	
		# Decrypt the cipher using AES in CCM Mode.
		cipher 		= AES.new( TK , AES.MODE_CCM , nonce , mac_len=8 )
		cipher.update( aad )
		plaintext 	= cipher.decrypt( ciphertext )
	
		# Return the plaintext.
		return plaintext
	
	def unwrapKey( self , plaintext , key ):
		""" Unwrap keys as defined in RFC 3394 (http://www.ietf.org/rfc/rfc3394.txt).
		"""
		return aes_unwrap_key( key , plaintext )
	
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


