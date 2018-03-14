#!/usr/bin/python

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

import sys
import time




def decode_value(type, value):
  # IMEI, 3335393430393038303030323732323232 
  # PhoneNumber, 2b3134303835353535363738 
  # TrustFlag, 00 
  if type == 'IMEI':
    mylist = list(value)[1::2]
    new_value = ''.join(mylist)
    return new_value
    
  elif type == 'PhoneNumber':
    mylist = list(value)
    if ''.join(mylist[:2]) == '2b': # starting with '2b'
      new_value = ''.join(mylist[3::2])
      new_value = '+' + new_value
    else:
      new_value = ''.join(mylist[1::2])
    
    return new_value

  elif type == "TrustFlag":
    if len(value) == 2:
      if value == '00':
        return 'False'
      elif value == '01':
        return 'True'
      else:
        return value
    else :
      return value
    
  elif type == 'Auth_Nonce':
    return value
    
  else:
    return value
  
  
"""
raw_data = '''0500000001010600000020ae3bf92cf2603e6a67
1b5c7962da74dc6e00dc09b087ee91b60cf1a70c
1b6e1a070000001133353934303930383030303
23731303031040000000c2b3134303835353531
323334'''
"""

# get the raw_data from input
# e.g. echo '0500000001010600000020ae3bf92cf2603e6a6' | python myTLV.py

raw_data = ''
try:
   for line in iter(sys.stdin.readline, b''):
      raw_data += line
except KeyboardInterrupt:
   sys.stdout.flush()
   pass



my_dict = {'04': 'PhoneNumber', '05': 'TrustFlag', '06': 'Auth_Nonce', '07': 'IMEI'}

print '~'*80
print raw_data

mylst = raw_data.split('\n')
#print mylst
signedData = ''
for item in mylst:
  signedData += item

#print signedData

total_len = len(signedData)  # the length of the signedData

print '\n' + '~'*80 + '\n'

# to parse the TLV format of string type signedData
# '0500000001010600000020ae3bf92cf2603e6a671b5c7962da74dc6e00dc09b087ee91b60cf1a70c1b6e1a07000000113335393430393038303030323731303031040000000c2b3134303835353531323334'
# t_len = 1 Byte (2 letters from string type data) '05'
# l_len = 4 Byte (8 letters from string type data) '00000001' -> '0x' + '00000001'
# v_len = variable, depends on the l_len '0x00000001' -> 1   int(l_len, 16)

# length of the tag, length, value (variable, based on value of length)
start_number = 0
t_len = 2
l_len = 8

# get the 1st v_len
l_value_raw = '0x' + signedData[start_number + t_len : (start_number + t_len + l_len)] # '0x00000001'
l_value = int(l_value_raw, 16)  # convert '0x00000001' to 1
v_len = l_value*2 

# get the 1st TLV
if True:
  l_value_raw = '0x' + signedData[start_number + t_len : (start_number + t_len + l_len)]
  l_value = int(l_value_raw, 16)
  v_len = l_value*2
    
  #print "\nstart_number: %d, t_len: %d, l_len:%d, v_len:%d" %(start_number, t_len, l_len, v_len)
    
  t_value = signedData[start_number : (start_number + t_len)]
  l_value = signedData[(start_number + t_len) : (start_number + t_len + l_len)]
  v_value = signedData[(start_number + t_len + l_len) : (start_number + t_len + l_len + v_len)]
    
  #print "T: %s, L:%s, V:%s \n" %(t_value, l_value, v_value)
  print "%s, %s, %s " %(t_value, l_value, v_value) 
  #print "%s, %s \n" %(my_dict[t_value], v_value)
  
  type =  my_dict[t_value]
  decoded_value = decode_value(type, v_value)
  print "%s, %s \n" %(my_dict[t_value], decoded_value)
  
tlv_end = start_number + t_len + l_len + v_len

# decode the subsequent TLV
while tlv_end < total_len:  
  start_number += t_len + l_len + v_len
  
  l_value_raw = '0x' + signedData[start_number + t_len : (start_number + t_len + l_len)]
  l_value = int(l_value_raw, 16)
  v_len = l_value*2
  
  #print "\nstart_number: %d, t_len: %d, l_len:%d, v_len:%d" %(start_number, t_len, l_len, v_len)
  
  t_value = signedData[start_number : (start_number + t_len)]
  l_value = signedData[(start_number + t_len) : (start_number + t_len + l_len)]
  v_value = signedData[(start_number + t_len + l_len) : (start_number + t_len + l_len + v_len)]
  
  #print "T: %s, L:%s, V:%s \n" %(t_value, l_value, v_value)
  print "%s, %s, %s " %(t_value, l_value, v_value)
  
  type =  my_dict[t_value]
  decoded_value = decode_value(type, v_value)
  print "%s, %s \n" %(my_dict[t_value], decoded_value)

  
  tlv_end = start_number + t_len + l_len + v_len


