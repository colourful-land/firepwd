# decode Firefox passwords (https://github.com/lclevy/firepwd)
# lclevy@free.fr (28 Aug 2013: initial version, Oct 2016: support for logins.json, Feb 2018: support for key4.db)
# for educational purpose only, not production level
# now integrated into https://github.com/AlessandroZ/LaZagne
# tested with python 2.7
# key3.db is read directly, the 3rd party bsddb python module is NOT needed
# NSS library is NOT needed

from struct import unpack
import sys
from binascii import hexlify, unhexlify 
import sqlite3
from base64 import b64decode
#https://pypi.python.org/pypi/pyasn1/
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import Sequence, OctetString, ObjectIdentifier
from pyasn1.type.namedtype import NamedTypes, NamedType
from hashlib import sha1
import hmac
from Crypto.Cipher import DES3
from Crypto.Util.number import long_to_bytes
from Cryptodome.Util.Padding import pad, unpad
from optparse import OptionParser
import json
from logging import debug
import logging

class Cypher(Sequence):
   componentType = NamedTypes(NamedType('oid',ObjectIdentifier()), NamedType('iv',OctetString()))
   
class LoginData(Sequence):
   componentType = NamedTypes(NamedType('key_id', OctetString()),NamedType('cypher', Cypher()),NamedType('cypherText', OctetString()))

def getShortLE(d, a):
   return unpack('<H',(d)[a:a+2])[0]

def getLongBE(d, a):
   return unpack('>L',(d)[a:a+4])[0]

#minimal 'ASN1 to string' function for displaying Key3.db contents
asn1Types = { 0x30: 'SEQUENCE',  4:'OCTETSTRING', 6:'OBJECTIDENTIFIER', 2: 'INTEGER', 5:'NULL' }   
oidValues = { '2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3',
              '2a864886f70d0307':'1.2.840.113549.3.7',
              '2a864886f70d010101':'1.2.840.113549.1.1.1' }   

def decrypt3DES( globalSalt, masterPassword, entrySalt, encryptedData ):
  #see http://www.drh-consultancy.demon.co.uk/key3.html
  hp = sha1( globalSalt+bytes(masterPassword, "UTF-8")).digest()
  pes = entrySalt + B'\x00'*(20-len(entrySalt))
  chp = sha1( hp+entrySalt ).digest()
  k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
  tk = hmac.new(chp, pes, sha1).digest()
  k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
  k = k1+k2
  iv = k[-8:]
  key = k[:24]
  if options.verbose>0:
    print('key='+hexlify(key), 'iv='+hexlify(iv))
  return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

def decodeLoginData(data):
  asn1data = decoder.decode(data) #first base64 decoding, then ASN1DERdecode
  return asn1data[0][0].asOctets(), asn1data[0][1][1].asOctets(), asn1data[0][2].asOctets() #for login and password, keep :(key_id, iv, ciphertext)

def encodeLoginData(data):
  loginData = LoginData()
  loginData['key_id'] = unhexlify('f8000000000000000000000000000001')
  loginData['cypher']['oid'] = [1,2,840,113549,3,7]
  loginData['cypher']['iv'] = iv
  loginData['cypherText'] = des.encrypt(data)
  return encoder.encode(loginData)
 
def getLoginData():
    logins = []
    loginf = open(options.directory+'logins.json','r').read()
    jsonLogins = json.loads(loginf)
    if 'logins' not in jsonLogins:
      print('error: no \'logins\' key in logins.json')
      return []
    for row in jsonLogins['logins']:
      encUsername = b64decode(row['encryptedUsername'])
      encPassword = b64decode(row['encryptedPassword'])
      logins.append( (encUsername, encPassword, row['hostname']) )
    return logins

def extractSecretKey(masterPassword, keyData):
  #see http://www.drh-consultancy.demon.co.uk/key3.html
  pwdCheck = keyData['password-check']
  if options.verbose>1:
    print('password-check='+hexlify(pwdCheck))
  entrySaltLen = ord(pwdCheck[1])
  entrySalt = pwdCheck[3: 3+entrySaltLen]
  if options.verbose>1:
    print('entrySalt=%s' % hexlify(entrySalt))
  encryptedPasswd = pwdCheck[-16:]
  globalSalt = keyData['global-salt']
  if options.verbose>1:
    print('globalSalt=%s' % hexlify(globalSalt))
  cleartextData = decrypt3DES( globalSalt, masterPassword, entrySalt, encryptedPasswd )
  if cleartextData != 'password-check\x02\x02':
    print('password check error, Master Password is certainly used, please provide it with -p option')
    sys.exit()

  if unhexlify('f8000000000000000000000000000001') not in keyData:
    return None
  privKeyEntry = keyData[ unhexlify('f8000000000000000000000000000001') ]
  saltLen = ord( privKeyEntry[1] )
  nameLen = ord( privKeyEntry[2] )
  #print 'saltLen=%d nameLen=%d' % (saltLen, nameLen)
  privKeyEntryASN1 = decoder.decode( privKeyEntry[3+saltLen+nameLen:] )
  data = privKeyEntry[3+saltLen+nameLen:]
  #see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
  entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
  if options.verbose>0:
    print('entrySalt=%s' % hexlify(entrySalt))
  privKeyData = privKeyEntryASN1[0][1].asOctets()
  if options.verbose>0:
    print('privKeyData=%s' % hexlify(privKeyData))
  privKey = decrypt3DES( globalSalt, masterPassword, entrySalt, privKeyData )
  print('decrypting privKeyData')
  if options.verbose>0:
    print('decrypted=%s' % hexlify(privKey))

  privKeyASN1 = decoder.decode( privKey )
  prKey= privKeyASN1[0][2].asOctets()
  print('decoding %s' % hexlify(prKey))
  prKeyASN1 = decoder.decode( prKey )
  id = prKeyASN1[0][1]
  key = long_to_bytes( prKeyASN1[0][3] )
  if options.verbose>0:
    print('key=%s' % ( hexlify(key) ))
  return key

def getKey():  
    conn = sqlite3.connect(options.directory+'key4.db') #firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
    c = conn.cursor()
    #first check password
    c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
    row = next(c)
    globalSalt = row[0] #item1
    item2 = row[1]
    """
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
         SEQUENCE {
           OCTETSTRING entry_salt_for_passwd_check
           INTEGER 01
         }
       }
       OCTETSTRING encrypted_password_check
     }
    """
    decodedItem2 = decoder.decode( item2 ) 
    entrySalt = decodedItem2[0][0][1][0].asOctets()
    cipherT = decodedItem2[0][1].asOctets()
    clearText = decrypt3DES( globalSalt, options.masterPassword, entrySalt, cipherT ) #usual Mozilla PBE
    print('password check?', clearText == b'password-check\x02\x02')
    if clearText == b'password-check\x02\x02': 
      #decrypt 3des key to decrypt "logins.json" content
      c.execute("SELECT a11,a102 FROM nssPrivate;")
      for row in c:
        if row[0] != None:
            break
      a11 = row[0] #CKA_VALUE
      a102 = row[1] #f8000000000000000000000000000001, CKA_ID
      """
       SEQUENCE {
         SEQUENCE {
           OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
           SEQUENCE {
             OCTETSTRING entry_salt_for_3des_key
             INTEGER 01
           }
         }
         OCTETSTRING encrypted_3des_key (with 8 bytes of PKCS#7 padding)
       }
      """
      decodedA11 = decoder.decode( a11 ) 
      entrySalt = decodedA11[0][0][1][0].asOctets()
      cipherT = decodedA11[0][1].asOctets()
      
      key = decrypt3DES( globalSalt, options.masterPassword, entrySalt, cipherT )
      print('3deskey', hexlify(key))
      return key[:24]

logging.basicConfig(level=logging.DEBUG)
parser = OptionParser(usage="usage: %prog [options]")
parser.add_option("-v", "--verbose", type="int", dest="verbose", help="verbose level", default=0)
parser.add_option("-p", "--password", type="string", dest="masterPassword", help="masterPassword", default='')
parser.add_option("-d", "--dir", type="string", dest="directory", help="directory", default='')
(options, args) = parser.parse_args()
# this one works, but using unpad from Cryptodome for safety
#unpad8 = lambda x: x[0:-x[-1]] if all([i==x[-1] for i in x[-x[-1]:]]) else x

key = getKey()
logins = getLoginData()
if len(logins)==0:
  print('no stored passwords')
else:
  print('decrypting login/password pairs')

for (username, password, site) in logins:
  key_id, iv, ciphertext = decodeLoginData(username) # username
  username = unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8)
  debug("encrypted   password: " + str(hexlify(password)))
  key_id, iv, ciphertext = decodeLoginData(password) # passwd 
  des = DES3.new( key, DES3.MODE_CBC, iv)
  password = unpad( DES3.new( key, DES3.MODE_CBC, iv).decrypt(ciphertext),8)
  debug("reëncrypted password: " + str(hexlify(encodeLoginData(pad(password,8)))))
  print('%20s: %s,%s' % (site, username, password)) #site URL

