#!/usr/bin/env python3

# (c) 2021-2023 HvA f.h.schippers@hva.nl
__version__ = '1.0 2023-06-11'
__author__ = 'Valentijn Keijser 500852414'

import os, sys
import getopt
import json
import base64
import textwrap
import traceback

from cryptography import exceptions
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend

import pprint

def readMesg(fname: str) ->str:
    """ The message is a unicode-string """
    if fname:
        with open(fname, 'r') as fp:
            mesg = fp.read()
    else:
        mesg = input('Mesg? ')
    return mesg

def writeMesg(fname: str, mesg: str) -> None:
    """ The message is a unicode-string """
    if fname:
        with open(fname, 'w') as fp:
            fp.write(mesg)
    else:
        print(mesg)

class HvaCryptoMail:
    """ Class to encrypt/decrypt, hash/verifyHash and sign/verifySign messages.
        We this class to store all relevant parameters used in this process.
    """ 
    _mark = '--- HvA Crypto Mail ---'

    def __init__(self) -> None:
        """ Initilalise the used variables """
        self.version = '1.0'    # Version number
        self.modes   = []       # Specifies the used algorithms
        self.snds    = {}       # keys: names of senders, values: relevant data
        self.rcvs    = {}       # keys: names of receivers, values: relevant data
        self.sesIv   = None     # (optional) session Iv (bytes)
        self.sesKey  = None     # (optional) session key (bytes)
        self.prvs    = {}       # keys: names of user, values: prvKey-object
        self.pubs    = {}       # keys: names of user, values: pubKey-object
        self.code    = None     # (optional) the encrypted message  (bytes)
        self.mesg    = None     # (optional) the uncoded message    (bytes)
        self.dgst    = None     # (optional) the hash the message   (bytes)


    def dump(self, cmFname:str , vbs: bool=False) -> None:
        """ Export internal state to a guarded 'HvaCryptoMail'
            cmFname: string; Name of the file to save to.
        """
        if gDbg: print(f"DEBUG: HvaCryptoMail:save cmFname={cmFname}")
        jdct = {}
        if self.version: jdct['vers'] = self.version
        if self.modes:   jdct['mods'] = self.modes
        if self.mesg:    jdct['mesg'] = self.mesg.decode('utf-8')
        if self.code:    jdct['code'] = self.code.hex()
        if self.dgst:    jdct['dgst'] = self.dgst.hex()
        if self.sesKey:  jdct['sKey'] = self.sesKey.hex()
        if self.sesIv:   jdct['sIv']  = self.sesIv.hex()
        if self.rcvs:    jdct['rcvs'] = { user: data.hex() \
                for user, data in self.rcvs.items() if data }
        if self.snds:    jdct['snds'] = { user: data.hex() \
                for user, data in self.snds.items() if data }
        if self.prvs: jdct['prvs'] = {
                name: str(prvKey.private_bytes(
                                               encoding=serialization.Encoding.PEM,
                                               format=serialization.PrivateFormat.TraditionalOpenSSL,
                                               encryption_algorithm=serialization.NoEncryption()),
                          encoding='ascii') \
                for name, prvKey in self.prvs.items() }
        if self.pubs:    jdct['pubs'] = {
                name: str(pubKey.public_bytes(
                                                    encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo),
                          encoding='ascii')
                for name, pubKey in self.pubs.items() }
    


        if vbs: print(json.dumps(jdct, indent=4, sort_keys=True))
        payload = base64.b64encode(bytes(json.dumps(jdct), encoding='utf-8'))
        data = self._mark + '\n' + \
               '\n'.join(textwrap.wrap(str(payload, encoding='ascii'))) + '\n' + \
               self._mark + '\n'
        if cmFname:
            with open(cmFname, 'w') as fp:
                fp.write(data)
        return


    def load(self, cmFname:str, vbs:bool=False) -> None:
        """ Import internal state from a guarded 'HvaCryptoMail'
            cmFname: string; Name of the file to load from.
        """
        if gDbg: print(f"DEBUG: HvaCryptoMail:load cmFname={cmFname}")
        with open(cmFname, 'r') as fp:
            data = fp.read()
        data = data.strip()

        if not (data.startswith(self._mark) and data.endswith(self._mark)):
            raise Exception('Invalid HvaCryptoMail')

        payload = data[len(self._mark):-len(self._mark)]

        jdct = json.loads(base64.b64decode(payload))
        if vbs: print(json.dumps(jdct, indent=4, sort_keys=True))

        self.version = jdct.get('vers', '')
        self.modes   = jdct.get('mods', [])
        self.mesg    = jdct.get('mesg').encode('utf-8') if 'mesg' in jdct else None
        self.code    = bytes.fromhex(jdct['code']) if 'code' in jdct else None
        self.dgst    = bytes.fromhex(jdct['dgst']) if 'dgst' in jdct else None
        self.sesKey  = bytes.fromhex(jdct['sKey']) if 'sKey' in jdct else None
        self.sesIv   = bytes.fromhex(jdct['sIv'])  if 'sIv'  in jdct else None
        self.rcvs    = { user: bytes.fromhex(data)  \
                for user, data in jdct.get('rcvs', {}).items() }
        self.snds    = { user: bytes.fromhex(data)  \
                for user, data in jdct.get('snds', {}).items() }
        self.prvs    = { user: serialization.load_pem_private_key(data.encode('ascii'), password=None, backend=default_backend()) \
                for user, data in jdct.get('prvs', {}).items() }
        self.pubs    = { user: serialization.load_pem_public_key(data.encode('ascii'), backend=default_backend()) \
                for user, data in jdct.get('pubs', {}).items() }
        return

    def addMode(self, mode: str) -> None:
        """ Add the use mode to the mode-list
            Only one type crypted and Only one type of signed """
        if mode not in [
                'crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256',
                'signed:rsa-pss-mgf1-sha384',
                'hashed:sha384' ]:
            # crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256
            #   Message padded with pkcs7
            #   Message Encrypted with AES-128 met CFB
            #   Key protected with RSA with OAEP, MGF1 and SHA256
            # signed:rsa-pss-mgf1-sha384
            #   Message Signed with with RSA with PSS, MGF1 and SHA384
            # hashed:sha384
            #   Message Hash with SHA384
            # Andere modes hoeven niet geimplementeerd te worden.
            Exception('Unexptected mode:{}'.format(mode))
        if gDbg: print(f"DEDUG: HvaCryptoMail::addMode: mode={mode}, self.modes={self.modes}")
        self.modes.append(mode)


    def hasMode(self, mode: str) -> bool:
        """ Check whether a mode is supported this HvaCryptoMessage """
        for _mode in self.modes:
            if _mode.startswith(mode): return True
        return False


    def loadPrvKey(self, name: str) -> None:
        """ Load a Private key for user `name` """
        prvKey = self.prvs.get(name)

        fname = name+'.prv'
        # Load the prv-key from file `fname` into prvKey
        if prvKey is None and os.path.exists(fname):
# Student work {{
            with open(fname, 'rb') as file:
                prvKeyData = file.read()
                prvKey = serialization.load_pem_private_key(prvKeyData, password=None, backend=default_backend())
                self.prvs[name] = prvKey
# Student work }}
        if prvKey is not None: self.prvs[name] = prvKey
        return


    def loadPubKey(self, name: str) -> None:
        """ Load a public key for user `name`,
            either from certificate-file or public key-file """
        pubKey = self.pubs.get(name)

        fname = name+'.crt'
        # Load the pub-key from certificate `fname` into pubKey
        if pubKey is None and os.path.exists(fname):
            data = open(fname, 'rb').read()
            crt = x509.load_pem_x509_certificate(data,
                    backend=default_backend())
            pubKey = crt.public_key()

        fname = name +'.pub'
        # Load the pub-key from public key-file `fname` into pubKey
        if pubKey is None and os.path.exists(fname):
# Student work {{
            with open(fname, 'rb') as file:
                pubKeyData = file.read()
                pubKey = serialization.load_pem_public_key(pubKeyData, backend=default_backend())
                self.pubs[name] = pubKey
# Student work }}
        if pubKey: self.pubs[name] = pubKey
        return


    def genSesKey(self, n: int) -> None:
        """ Generate a (secure) session key for symmetric encryption. """
        # set self.sesKey with an usable key
        sesKey = b'' # Initialize variable
# Student work {{
        sesKey = os.urandom(n)
# Student work }}
        self.sesKey = sesKey
        return


    def genSesIv(self, n: int) -> None:
        """ Generate a (secure) intial-vector key for symmetric encryption. """
        # set self.sesIv with an usable intial vector
        sesIv = b'' # Initialize variable
# Student work {{
        sesIv = os.urandom(n)
# Student work }}
        self.sesIv = sesIv
        return


    def encryptSesKey(self, user: str) -> bool:
        """ Encrypt the session-key for `user` in `self.rcvs` """
        # Implememt encryption using RSA with OAEP, MGF1 and SHA256
        assert 'crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"

        encKey = None # Initialise variable
# Student work {{
        # Encrypt the session key for the user
        if user in self.pubs:
            pubKey = self.pubs[user]
            if isinstance(pubKey, bytes):
                # public_key is in bytes
                public_key = serialization.load_pem_public_key(
                    pubKey,
                    backend=default_backend()
                )
            else:
                public_key = pubKey
                # public_key is in _RSAPublicKey
                
            encKey = public_key.encrypt(
                self.sesKey,
                asympadding.OAEP(
                    mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
# Student work }}
        if encKey: self.rcvs[user] = encKey
        return encKey is not None


    def decryptSesKey(self, user: str) -> bool:
        """ Decrypt the session-key saved in `self.rcvs` for `user` """
        # Implememt decryption using RSA with OAEP, MGF1 and SHA256
        assert 'crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"
        sesKey = None # Initialise variable
        # Student work {{
        # user is in self.rcvs
        if user in self.rcvs:
            encKey = self.rcvs[user]

            # de private key voor decryption
            if user in self.prvs:
                privKey = self.prvs[user]
                if isinstance(privKey, bytes):
                    # private_key is in bytes
                    private_key = serialization.load_pem_private_key(
                        privKey,
                        password=None,
                        backend=default_backend()
                    )
                else:
                    private_key = privKey
                    # private_key is een _RSAPrivateKey

                try:
                    # Decrypt de encrypted session key
                    sesKey = private_key.decrypt(
                        encKey,
                        asympadding.OAEP(
                            mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                except ValueError:
                    print('Decryption failed')
                    # Decryption failed

        # Student work }}
        if sesKey: self.sesKey = sesKey
        return sesKey is not None


    def encryptMesg(self) -> bool:
        """ Encrypt the message (self.mesg) result in self.code"""
        assert 'crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"
        code = None # Initialize variable
# Student work {{
        if self.mesg and self.sesKey and self.sesIv:
            cipher = ciphers.Cipher(algorithms.AES(self.sesKey), modes.CBC(self.sesIv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sympadding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(self.mesg.encode('utf-8')) + padder.finalize()
            code = encryptor.update(padded_data) + encryptor.finalize()
# Student work }}
        if code is not None: self.code = code
        return code is not None

    def decryptMesg(self) -> bool:
        """ Decrypt the message """
        assert 'crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"

        mesg = None # Initalise variable
# Student work {{
        symm_algo = self.modes[0].split(':')[2]  # Get the symmetric algorithm
        symm_mode = self.modes[0].split(':')[3]  # Get the symmetric mode

        if 'rsa' in self.modes:
            private_key = self.prvs['user1']
            cipher_rsa = ciphers.asymmetric.rsa.RSACipher(private_key)
            decrypted_rsa = cipher_rsa.decrypt(self.code, asympadding.OAEP(
                mgf=asympadding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
            symm_algo = self.modes.split(':')[2]  # Get the symmetric algorithm
            symm_mode = self.modes.split(':')[3]  # Get the symmetric mode

        # Decrypt the symmetrically encrypted message
        if symm_algo == 'aes256-cbf' and symm_mode == 'pkcs7':
            symmetric_key = decrypted_rsa[:32]  # Extract the symmetric key
            symmetric_iv = decrypted_rsa[32:48]  # Extract the initialization vector
            cipher_symm = ciphers.Cipher(algorithms.AES(symmetric_key), modes.CBC(symmetric_iv), backend=default_backend())
            decryptor = cipher_symm.decryptor()
            decrypted_symm = decryptor.update(decrypted_rsa[48:]) + decryptor.finalize()
            mesg = decrypted_symm
# Student work }}
        if mesg is not None: self.mesg = mesg
        return mesg is not None


    def signMesg(self, user: str) -> bool:
        """ Sign the message """
        # Implement signing using RSA with PSS, MGF1 and SHA384
        assert 'signed:rsa:pss-mgf1:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        signature = None # Initialize variable
# Student work {{
        if self.sesKey is not None and self.prvs is not None:
            if user in self.sesKey:
                private_key = serialization.load_pem_private_key(self.prvs, password=None, backend=default_backend())
                message = self.mesg.encode('utf-8')
                signature = private_key.sign(
                    message,
                    asympadding.PSS(
                        mgf=asympadding.MGF1(hashes.SHA384()),
                        salt_length=asympadding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA384()
                )
# Student work }}
        if signature: self.snds[user] = signature
        return signature is not None

    def verifyMesg(self, user: str) -> bool:
        """ Verify the message Return
            None is signature is incorrect, return True if correct """
        # Implement verification using RSA with PSS, MGF1 and SHA384
        assert 'signed:rsa:pss-mgf1:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        verified = None # Initialize variable
# Student work {{
        if user in self.snds:
                signature = self.snds[user]
                public_key = self.pubs[user]
                message = self.mesg  
                try:
                    public_key.verify(
                        signature,
                        message,
                        asympadding.PSS(
                            mgf=asympadding.MGF1(hashes.SHA384()),
                            salt_length=asympadding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA384()
                    )
                    verified = True
                except exceptions.InvalidSignature:
                    verified = None
# Student work }}
        return verified

    def calcHash(self) -> None:
        """ Calculate the hash-digest of the message (`self.mesg`)
            Assign the digest to `self.dgst` """
        # Implememt hash using SHA384
        assert 'hashed:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        dgst = b''
        # Calculate hash (SHA384) of self.mesg
# Student work {{
        message = self.mesg.encode('utf-8') if isinstance(self.mesg, str) else self.mesg
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
        digest.update(message)
        dgst = digest.finalize()
# Student work }}
        self.dgst = dgst

    def chckHash(self) -> bool:
        """ Calculate the hash of the message (`self.mesg`)
            Check is is corresponds to `self.dgst` """
        # Implememt hash using SHA384
        assert 'hashed:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        res = None  # Initialized variable
# Student work {{
        message = self.mesg  # No need to encode self.mesg again
        digest = hashes.Hash(hashes.SHA384(), backend=default_backend())
        digest.update(message)
        calculated_dgst = digest.finalize()
        res = calculated_dgst == self.dgst
# Student work }}
        return res

# end of class HvaCryptoMail


def encode(cmFname: str, mesg: str, senders: list, receivers: list) -> tuple:
    """ Encode (encrypt and/or sign) the message (`mesg`)
        for the `receivers` and `senders`.
        The receivers and senders list containe names of users.
        The coded message-structur (CryptoMail) is written to the file `cmFname`
    """

# Implemented modes:
#   cm.addMode('hashed:sha384')
#   cm.addMode('crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256')
#   cm.addMode('signed:rsa:pss-mgf1:sha384')

# Initialisation
    sendersState = {}
    receiversState = {}

    # Init cm
    cm = HvaCryptoMail()
    # Set cm.mesg
# Student work {{
    cm.mesg = mesg
# Student work }} Set

    # Calc Hash (don't forget addMode)
# Student work {{
    cm.addMode('hashed:sha384')
    cm.calcHash()
# Student work }} Hash

    # Sign (don't forget addMode)
# Student work {{
    cm.addMode('signed:rsa:pss-mgf1:sha384')
    if senders:
        for sender in senders:
            cm.signMesg(sender)
            sendersState[sender] = True
# Student work }} Sign

    # Encrypt (don't forget addMode)
# Student work {{
    cm.addMode('crypted:aes256-cbf:pkcs7:rsa-oaep-mgf1-sha256')
    if receivers:
        for receiver in receivers:
            cm.loadPubKey(receiver)
            cm.genSesKey(32)
            cm.genSesIv(16)
            cm.encryptSesKey(receiver)
            cm.encryptMesg()
            receiversState[receiver] = True
# Student work }} Encrypt

    # Remove secrets
    # Secrets should not be a part of the saved CryptoMail structure
# Student work {{
    cm.__init__()
# Student work }} Secrets

    # Save & Return
    cm.dump(cmFname)
    return receiversState, sendersState


def decode(cmFname: str, receivers: list=None, senders: list=None) -> tuple:
    """ Decode (decrypt and/or verify) found in de file named `cmFname`
        for the `receivers` en `senders`.
        The receivers and senders list containe names of users.
        Returns a tuple (msg, sendersState, receiversState).
    """

# Initialisation
    cm = HvaCryptoMail()
    cm.load(cmFname, gVbs)

    if receivers is None: receivers = cm.rcvs.keys()
    if senders is None: senders = cm.snds.keys()
    if gDbg: print(f"DEBUG: rcvs={receivers} snds={senders}")
    
    mesg = None
    sendersState = {}
    receiversState = {}
    hashState = None
    secretState = None

# Set secretState to True as no secrets are reveiled otherwise False
# Student work {{
    print('cmFname: ', cmFname, 'reciever: ', receivers, 'sender: ', senders)
    if cm.hasMode('secret'):
        secretState = False
    else:
        secretState = True
# Student work }} CheckSecrets

    if cm.hasMode('crypted'):
        if gVbs: print('Verbose: crypted')
        # Decrypt the message for receivers or senders
        # and update sendersState of receiversState
# Student work {{
        for receiver in receivers:
            if cm.decryptSesKey(receiver):
                if cm.decryptMesg():
                    receiversState[receiver] = True
                    secretState = True
                else:
                    receiversState[receiver] = False
            else:
                receiversState[receiver] = False
        
        for sender in senders:
            if cm.decryptSesKey(sender):
                if cm.decryptMesg():
                    sendersState[sender] = True
                    secretState = True
                else:
                    sendersState[sender] = False
            else:
                sendersState[sender] = False
# Student work }} Decrypt

    if cm.hasMode('hashed'):
        if gVbs: print('Verbose: hashed')
# Student work {{
    # Calculate hash and update hashState
        cm.calcHash()
        if cm.chckHash():
            hashState = True
        else:
            hashState = False
# Student work }} Hash

    if cm.hasMode('signed'):
        if gVbs: print('Verbose: signed')
        # Verify the message for receivers or senders
        # and update sendersState of receiversState
# Student work {{
    for receiver in receivers:
        if cm.verifyMesg(receiver):
            receiversState[receiver] = True
        else:
            receiversState[receiver] = False
    
    for sender in senders:
        if cm.verifyMesg(sender):
            sendersState[sender] = True
        else:
            sendersState[sender] = False
    # Student work }} Verify

# Convert bytes to str
    mesg = cm.mesg.decode('utf-8') if cm.mesg else None
    return mesg, receiversState, sendersState, hashState, secretState


def prState(state) -> str:
    return { None: 'no-info', True: 'success', False: 'failure' }.get(state, '???')

gVbs = False
gDbg = False
gSil = False

def main():
    global gVbs, gDbg, gSil
    autoLoad = True
    cmFname = ''
    mesgFname = ''
    receivers = None
    senders = None
    res = 0
    opts, args = getopt.getopt(sys.argv[1:], 'hVDSf:m:r:s:', [])
    for opt, arg in opts:
        if opt == '-h':
            print(f"Usage: {sys.argv[0]} -[HVDS] \\")
            print(f"\t\t[-f <cmFname>] \\   # {cmFname}")
            print(f"\t\t[-m <mesgFname>] \\ # {mesgFname}")
            print(f"\t\t[-r <receivers>] \\ # {receivers}")
            print(f"\t\t[-s <senders>] \\   # {senders}")
            print(f"\t\t encode|decode")
            sys.exit()
        if opt == '-V': gVbs = True
        if opt == '-D': gDbg = True
        if opt == '-S': gSil = True

        if opt == '-f': cmFname = arg
        if opt == '-m': mesgFname = arg
        if opt == '-r': receivers = arg.split(',') if arg else []
        if opt == '-s': senders = arg.split(',') if arg else []

    if gDbg: print(f"DEBUG: version={__version__}")

    if cmFname == '':
        print('Error: no <fname>.cm')
        sys.exit(2)

    cm = HvaCryptoMail()

    for cmd in args:

        if cmd == 'info':
            if autoLoad: cm.load(cmFname) 
            cm.dump(None, True)

        if cmd == 'encode':
            plainStr = readMesg(mesgFname)
            receiversState, sendersState = encode(cmFname, plainStr, senders, receivers)
            if True:
                sendersStr = ','.join([ name+'='+prState(state) for name, state in sendersState.items() ])
                receiversStr = ','.join([ name+'='+prState(state) for name, state in receiversState.items() ])
                print(f"Encoded:file:      {cmFname}")
                print(f"Encoded:receivers: {receiversStr}")
                print(f"Encoded:senders:   {sendersStr}")
                print(f"Encoded:mesg:      {plainStr}")
            else:
                print(f"Unable to encode {cmFname}")
                res = 1

        if cmd == 'decode':
            plainStr, receiversState, sendersState, hashState, secretState = \
                    decode(cmFname, receivers, senders)
            if plainStr:
                sendersStr = ','.join([ name+'='+prState(state) for name, state in sendersState.items() ])
                receiversStr = ','.join([ name+'='+prState(state) for name, state in receiversState.items() ])
                print(f"Decoded:file:      {cmFname}")
                print(f"Decoded:receivers: {receiversStr}")
                print(f"Decoded:senders:   {sendersStr}")
                print(f"Decoded:hash:      {prState(hashState)}")
                print(f"Decoded:secrets:   {prState(secretState)}")
                print(f"Decoded:mesg:      {plainStr}")
                if mesgFname: writeMesg(mesgFname, plainStr)
            else:
                print(f"Unable to decode {cmFname}")
                res = 1

    sys.exit(res)

if __name__ == '__main__':
    main()

# End of Program
