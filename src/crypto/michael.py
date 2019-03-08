#!/usr/bin/env python2.7
from scapy.all import *

# This implementation is based on the official IEEE 802.11i standard, and
# https://github.com/Fugiman/Servrhe/blob/master/crypto/keyedHash/michael.py

class Michael:
    """ Implementation for the IEEE 802.11i Michael Message Integrity Code.
    """
    
    def __init__( self , key , sa , da , priority , data ):
    	""" Initializer.
    	"""
    	
    	# Make assertions on the given inputs.
    	assert( len(key) == 8 ), \
    		'The length of the key must be eight octets.'
        assert( len(sa) == 6 ), \
        	'The lenght of the source address must be six octets.'
        assert( len(da) == 6 ), \
        	'The lenght of the destination address must be six octets.'
        assert( 0 <= priority <= 15 ), \
        	'The priority must be between zero and fifteen.'
        
        # Hold the digest, avoiding calculating it multiple times.
        self.digest 	= None
        
        # Unpack the given key into two 32-bit integers, and construct the data format.
        # Ref. IEEE 802.11i specification; TKIP MIC processing format.
        self.key 	= struct.unpack( '<II' , key )
        self.data	= da + sa + chr( priority ) + 3*chr(0) + data
        
    def hash( self ):
        """ Generate the Michael MIC digest.
        """
        
        # Return the digest if we have already calculated it before.
        if self.digest is not None:
        	return self.digest 
        
        # Add padding to the data if necessary and generate the Michael MIC digest.
        # https://github.com/Fugiman/Servrhe/blob/master/crypto/keyedHash/michael.py
        # Ref. IEEE 802.11i specification; Definition of the TKIP MIC.
        fullBlocks, extraOctets = divmod( len(self.data) , 4 )
        paddedData 	= self.data + chr(0x5a) + chr(0)*(7-extraOctets)
        l, r 		= self.key
        for i in range( fullBlocks + 2 ):
            mSub_i 	= struct.unpack('<I', paddedData[i*4:i*4+4])[0]
            l 		= l ^ mSub_i
            l,r 	= b(l,r)
        
        # Save and return the calculated digest.
        self.digest = struct.pack( '<II' , l , r )
        return self.digest

def b(l,r):
    """ The block function for the IEEE 802.11i Michael Integrity Check.
    	https://github.com/Fugiman/Servrhe/blob/master/crypto/keyedHash/michael.py
    	Ref. IEEE 802.11i specification; Definition of the TKIP MIC.
    """
    r ^= (((l<<17) & 0xffffffffL)|((l>>15) & 0x1ffffL))       # r = r ^ (l <<< 17)
    l  = (l+r) & 0xffffffffL                                  # l = (l+r) mod 2**32
    r ^= ((l & 0xff00ff00L)>>8)|((l & 0x00ff00ffL)<<8)        # r = r ^ XSWAP(l)
    l  = (l+r) & 0xffffffffL                                  # l = (l+r) mod 2**32
    r ^= (((l<<3) & 0xffffffffL) | ((l>>29)& 0x7))            # r  = r ^ (l <<< 3)
    l  = (l+r) & 0xffffffffL                                  # l = (l+r) mod 2**32
    r ^= (((l<<30L) & 0xffffffffL)|((l>>2) & 0x3fffffff))     # r  = r ^ (l >>> 2)
    l  = (l+r) & 0xffffffffL                                  # l = (l+r) mod 2**32
    return (l,r)
    
