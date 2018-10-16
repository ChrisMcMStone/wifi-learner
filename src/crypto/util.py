#!/usr/bin/env python2.7
from scapy.all import *
from Crypto.Hash import HMAC

from utility.radiotap import radiotap_parse
from utility.utils import getBit

import os
import binascii
import hmac
import hashlib
from struct import Struct
from operator import xor
from itertools import izip, starmap
from hashlib import sha1

def calculateCRC( arc4state , plaintext ):
	""" Calculate the CRC as RC4( CRC32( plaintext ) ).
		Return an integer representation.
	"""
	crc = crc32( plaintext ) % (1<<32) 	# CRC and signed to unsigned
	crc = struct.pack( '<L' , crc ) 	# Change endianness
	crc = arc4state.encrypt( crc ) 		# Encrypt
	crc = crc.encode('hex') 		# Change to hexadecimal notation without 0x
	crc = int( crc , 16 ) 			# Change to integer
	return crc
	
def getVendorInfo( type ):
	""" Get the vendor specific information.
	"""
	supported  = ( 'TKIP_TKIP_PSK' , 'TKIP_AES_PSK' , 'TKIP_TKIPAES_PSK' )
	supported += ( 'AES_TKIP_PSK'  , 'AES_AES_PSK'  , 'AES_TKIPAES_PSK'  )
	assert type in supported, \
		'Vendor Specific Info "%s" Not Supported' % (type)
	
	# Some default settings.
	oui 		= '\x00\x50\xf2'
	ouiType 	= '\x01'
	wpaVersion 	= '\x01\x00'
		
	# Split the type into multicast, unicast and key management.
	type 		= type.split( '_' )
	typeMulticast 	= type[0]
	typeUnicast 	= type[1]
	typeKeyMgmt 	= type[2]
	
	# Complete the vendor specific information.
	if typeMulticast == 'TKIP':
		multicastCipherSuite 		= '\x00\x50\xf2\x02'	# TKIP
	if typeMulticast == 'AES':
		multicastCipherSuite 		= '\x00\x50\xf2\x04'	# AES (CCM)
	if typeUnicast == 'TKIP':
		unicastCipherSuiteCount		= '\x01\x00'
		unicastCipherSuiteList 		= '\x00\x50\xf2\x02'	# TKIP
	if typeUnicast == 'AES':
		unicastCipherSuiteCount 	= '\x01\x00'
		unicastCipherSuiteList 		= '\x00\x50\xf2\x04'	# AES (CCM)
	if typeUnicast == 'TKIPAES':
		unicastCipherSuiteCount 	= '\x02\x00'
		unicastCipherSuiteList 		= '\x00\x50\xf2\x02'	# TKIP
		unicastCipherSuiteList 	       += '\x00\x50\xf2\x04'	# AES (CCM)
	if typeKeyMgmt == 'PSK':
		authKeyManagementSuiteCount 	= '\x01\x00'
		authKeyManagementSuiteList 	= '\x00\x50\xf2\x02'	# PSK
		
	# Create the return value.
	rv  = oui + ouiType + wpaVersion + multicastCipherSuite
	rv += unicastCipherSuiteCount + unicastCipherSuiteList
	rv += authKeyManagementSuiteCount + authKeyManagementSuiteList
	return rv

def hasFCS( packet ):
	""" Check if the Frame Check Sequence (FCS) flag is set in the Radiotap header.
	"""
	assert( packet.haslayer( RadioTap ) ), \
		'The packet does not have a Radiotap header.'
	_ , radiotap 	= radiotap_parse( str(packet) )
	radiotapFCSFlag	= False
	if getBit( radiotap['flags'] , 4 ) == 1:
		radiotapFCSFlag = True
	return radiotapFCSFlag
	
def assertDot11FCS( packet , expectedFCS = None ):
	""" Validates the Frame Check Sequence (FCS) over a Dot11 layer. It is possible to 
		pass an expected FCS; this is necessary when there is no padding layer available,
		usually in the case of encrypted packets.
	"""
	if expectedFCS is None:
		fcsDot11	= str(packet.getlayer( Padding ))
	else:
		fcsDot11	= '{0:0{1}x}'.format( expectedFCS , 8 ) # Padding for leading zero.
		fcsDot11	= fcsDot11.decode('hex')
	dataDot11 		= str(packet.getlayer(Dot11))[:-4]
	# Calculate the ICV over the Dot11 data, parse it from signed to unsigned, and
	# change the endianness.
	fcsDot11Calculated = struct.pack( '<L' , crc32( dataDot11 ) % (1<<32) )
	
	# Assert that we have received a valid FCS by comparing the ICV's.
	assert( fcsDot11 == fcsDot11Calculated ), \
		'The received FCS "0x%s" does not match the calculated FCS "0x%s".' \
		% ( fcsDot11.encode('hex') , fcsDot11Calculated.encode('hex') )
		
