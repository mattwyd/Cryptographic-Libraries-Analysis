#!/usr/bin/env python

import nacl.utils
import nacl.secret

from nacl.public import PrivateKey, Box, SealedBox
from nacl.signing import SigningKey
from nacl.hash import blake2b


import tink
from tink import aead
from tink import hybrid
from tink import signature
from tink import mac


def generateSecretKeyNacl():
    """
    Generates a random symmetric key using nacl
         Returns:
        key (bytes)
    """

    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
         return key




def generateSecretKeyTink():
    """      Generates a random symmetric key using Tink.

    Notes:
        Use the AEAD primitive.
        Use the AES256_GCM key template
    Returns:
        keyset_handle (KeysetHandle)
    """
    aead.register()
    temp = aead.aead_key_templates.AES128_GCM
    keyset = tink.new_keyset_handle(temp)
    return keyset

def aeadEncryptNacl(key, message, associated_data, nonce):
    """
    Encrypts plaintext string "message" and associate data "aad" using key and a 24 byte nonce. Uses AEAD
         Notes: this function should return a ciphertext to be used as the first parameter of aeadDecryptNacl() below.      Parameters:
        key (bytes)
        message (string)
        associated_data (bytes)
        nonce (bytes)
             Returns:
        ciphertext (bytes)
    """
    message = bytes(message, 'utf-8')

    box = nacl.secret.Aead(key)
         encrypted = box.encrypt(message,associated_data, nonce)
         return encrypted.ciphertext


def aeadDecryptNacl(ciphertext, associated_data, key, nonce):
    """
    Decrypts a ciphertext using associated_data, key and nonce
         Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        key (bytes)
        nonce (bytes)
    Returns:
        message (string)
    """
    box = nacl.secret.Aead(key)
    decrypted = box.decrypt(ciphertext, associated_data, nonce)
    return decrypted.decode()

def aeadEncryptTink(keyset_handle, message, associated_data):
    """
    Encrypts plaintext message and associated data using XCHACHA20-POLY1305 and a provided keyset handle.

    Notes:          Function must ensure that the keyset handle is compatible with XCHACHA20-POLY1305. Should return a ciphertext that can be passed as the first parameter of aeadDecryptTink() below.      Parameters:
        keyset_handle (KeysetHandle)
        message (string)
        associated_data (bytes)
    Returns:
        ciphertext (bytes)
    """
    message = bytes(message, 'utf-8')
    if keyset_handle.keyset_info().key_info[0].type_url == 'type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key':
             aead_primitive = keyset_handle.primitive(aead.Aead)

        ct = aead_primitive.encrypt(message, associated_data)
        return ct
    else:
        return 'nah'
     
def aeadDecryptTink(ciphertext, associated_data, keyset_handle):
    """
    Decrypts a ciphertext using the keyset handle and associated data

    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        keyset_handle (KeysetHandle)
    Returns:
        plaintext (string)
    """
    aead_primitive = keyset_handle.primitive(aead.Aead)
    plaintext = aead_primitive.decrypt(ciphertext, associated_data)
         return plaintext.decode()
     
def generateKeyPairNacl():
    """
    Uses NaCl to generate a public/private key pair

    Returns:          Returns tuple of Curve25519 keys:
            privkey (PrivateKey)
            pubkey (PublicKey)
    """
    priv = PrivateKey.generate()
    pub = priv.public_key
    return(priv, pub)

def generateHybridEncryptionKeyPairTink():
    """
    Uses Tink to generate a keypair suitable for hybrid encryption
         Notes:
        Keys must use the ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 hybrid key template
    Returns:
        Tuple of keyset handles              private_keyset_handle (KeysetHandle)
            public_keyset_handle (KeysetHandle)
    """
    hybrid.register()
    priv_key_hndl = tink.new_keyset_handle(hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    pub_key_hndl = priv_key_hndl.public_keyset_handle()
    return(priv_key_hndl,pub_key_hndl)

def hybridEncryptNacl(message, pubkey):
    """
    Uses the public key to encrypt a random symmetric key, and then encrypts message using that symmetric key. MUST NOT ENCRYPT USING PUBKEY DIRECTLY!
         Notes: The returned ciphertext and encrypted_symmetric_key should be compatible with the hybridDecryptNacl() below.      Parameters:
        message (string)
        pubkey (PublicKey)
    Returns:
        Tuple containing:
            ciphertext (bytes)
            encrypted_symmetric_key (bytes)
    """
    message = bytes(message, 'utf-8')


    simkey = generateSecretKeyNacl()
    box = nacl.public.SealedBox(pubkey)
    encrypted_symmetric_key = box.encrypt(simkey)

    box2 = nacl.secret.SecretBox(simkey)
    ciphertext = box2.encrypt(message)
    return (ciphertext, encrypted_symmetric_key)


def hybridDecryptNacl(ciphertext, encrypted_key, privkey):
    """
    Uses the private key to first decrypt the shared symmetric key (generated in hybridEncryptNacl). Uses the symmetric key to decrypt the ciphertext.           Parameters:
        ciphertext (bytes)
        encrypted_symmetric_key (bytes)
        privkey (PrivateKey)
         Returns plaintext (string)
    """
    openbox = SealedBox(privkey)
    simkey = openbox.decrypt(encrypted_key)

    box = nacl.secret.SecretBox(simkey)
    plaintext = box.decrypt(ciphertext)

    return plaintext.decode()

def hybridEncryptTink(message, associated_data, public_keyset_handle):
    """
    Uses Tink to perform hybrid encryption on a plaintext message and associated data, and uses a public keyset handle to obtain the public key to use.           Notes: The ciphertext should be compatible as the first parameter of the hybridDecryptTink() function below.
    Parameters:
        message (string)
        associated_data (bytes)
        public_keyset_handle (KeysetHandle)
    Returns:
        ciphertext (bytes)
    """
    message = bytes(message, 'utf-8')

    hencrypt = public_keyset_handle.primitive(hybrid.HybridEncrypt)
    ciphertext = hencrypt.encrypt(message, associated_data)

    return ciphertext

def hybridDecryptTink(ciphertext, associated_data, private_keyset_handle):
    """
    Decrypts ciphertext using private key. Requires passing associated_data for authentication.  
    Parameters:
        ciphertext (bytes)
        associated_data (bytes)
        private_keyset_handle (KeysetHandle)
    Returns:
        plaintext (string)
    """

    hencrypt = private_keyset_handle.primitive(hybrid.HybridDecrypt)
    text = hencrypt.decrypt(ciphertext, associated_data)
    return text.decode()

def generateSignatureKeypairNacl():
    """
    Generates a signing key and a verification key using Nacl

    Returns:          Tuple of keys
            sigkey (SigningKey)
            verifykey (VerifyKey)
    """
         sk = SigningKey.generate()
    vk = sk.verify_key
    return (sk, vk)

def generateSignatureKeypairTink():
    """
    Generates a signing key and verification key using Tink.
         Notes: must use the ECDSA_P384 signature key template
    Returns:
        Tuple of keyset handles              signing_keyset_handle (KeysetHandle)
            verify_keyset_handle (KeysetHandle)
    """

    signature.register()
    key_hndl = tink.new_keyset_handle(signature.signature_key_templates.ECDSA_P384)
    pub = key_hndl.public_keyset_handle()
    return ( key_hndl , pub)

     
def signNacl(message, sigkey):
    """
    Uses NaCl to digitally sign a message using sigkey
         Notes: Should only return the signature data, not the message+signature. The retured signature should be compatible with the tag parameter of the verifyNacl() method.
    Parameters:
        message (string)
        sigkey (SigningKey)
         Returns:
        signature (bytes)
    """
    message = message.encode()

    signed = sigkey.sign(message)         return signed.signature

def signTink(message, signing_keyset_handle):
    """
    Digitally signs message using signing key in signing_keyset_handle
         Notes: Only return the signature, do not return the message. The signature should be compatible with the signature_data parameter of the verifyTink() method.
    Parameters:
        message (string)
        signing_keyset_handle (KeysetHandle)
    Returns:
        signature (bytes).      """
    signature.register()
    message = message.encode()
    signee = signing_keyset_handle.primitive(signature.PublicKeySign)
    siggy_data = signee.sign(message)
    return siggy_data
         
def verifyNacl(message, tag, verifykey):
    """
    Verify the signature tag on a message using the verification key
         Parameters:
        message (string)
        tag (bytes)
        verifykey (VerifyKey)
    Returns:
        verification_status (boolean): indicating verification status (true if verified, false if something failed)
    """
    message = message.encode()

    try:
        verifykey.verify(message, tag)
        return True
    except:
        return False



def verifyTink(message, signature_data, verifying_keyset_handle):
    """
    Verify the signature on a message using the verifying keyset handle

    Parameters:
        message (string)
        signature_data (bytes)
        verifying_keyset_handle (KeysetHandle)
    Returns:
        verification_status (boolean): indicating verification status (true if verified, false if something failed)
    """         message = message.encode()

    pow = verifying_keyset_handle.primitive(signature.PublicKeyVerify)
    try:
        (pow.verify(signature_data, message))
        return True
    except:
        return False


def computeMacNacl(message, key):
    """
    Computes a MAC using the provided key
         Notes: Use blake2b. Should be compatible with the verify method below.      Parameters:
        message (string)
        key (bytes)
    Returns:
        tag (bytes)
    """
    message = bytes(message, 'utf-8')


    return blake2b(message, key=key, encoder=nacl.encoding.HexEncoder)


def verifyMacNacl(message, tag, key):
    """
    Verifies whether the provided MAC tag is correct for the message and key
         Parameters:
        message (string)
        tag (bytes)
        key (bytes)
    Returns:
        verified (boolean) indicating verification status (true if verified, false if something failed)
    """
    message = bytes(message, 'utf-8')


    if(tag == computeMacNacl(message.decode(), key)):
        return True
    else:
        return False
     
def computeMacTink(message, mac_keyset_handle):
    """
    Computes a MAC on the message using the provided keyset handle           Notes: The returned tag should be compatible with the verifyMacTink() method below.
    Parameters:
        message (string)
        mac_keyset_handle (KeysetHandle)
    Returns:          tag (bytes)
    """
    message = message.encode()

    mac.register()
    mac_prim = mac_keyset_handle.primitive(mac.Mac)
    tag = mac_prim.compute_mac(message)
    return tag

def verifyMacTink(message, tag, mac_keyset_handle):
    """
    Verifies a mac using the provided tag and keyset handle
         Parameters:
        message (string)
        tag (bytes)
        mac_keyset_handle (KeysetHandle)
    Returns:
        verified (boolean) indicating verification status (true if verified, false if something failed)
    """
    message = bytes(message, 'utf-8')

    mac.register()
    mac_prim = mac_keyset_handle.primitive(mac.Mac)
    mac_prim.verify_mac(tag, message)

    try:
        return True
    except:
        print()
        return None

if __name__ == '__main__':
    print("Please implement the methods above using the appropriate cryptographic libraries. Assume library defaults if something is not specified")


