#
# Author: Oliver Xu
# Date: 2018.03.14
# Version:  1.0
#
# myTLV.py - to perform the decoding for Signed Data Structure 
# Type: 1-byte unsigned length
#     - 0x4 Phone Number. The phone number registered for the iPhone in canonical format
#           (E.164). E.g. +14085551234
#
#     - 0x5 TrustFlag value as calculated by Apple Registration Server
#
#     - 0x6 Carrier Authorization Nonce. This is the value returned by the Entitlements Server in
#           the getCarrierAuthorizationNonce response.
#
#     - 0x7 The IMEI of the iPhone
#           (E.164). E.g. +14085551234
#
# Length: 4-byte unsigned length
# Value: Variable length

'''
e.g.
TrustFlag            True  

Authorization Nonce  
                      ae3bf92cf2603e6a671b5c7962da74dc6e00dc09b
                      087ee91b60cf1a70c1b6e1a 

PhoneNumber           +14085551234

IMEI                  35940908000271001

Signed Data          
                      0500000001010600000020ae3bf92cf2603e6a67
                      1b5c7962da74dc6e00dc09b087ee91b60cf1a70c
                      1b6e1a070000001133353934303930383030303
                      23731303031040000000c2b3134303835353531
                      323334
'''