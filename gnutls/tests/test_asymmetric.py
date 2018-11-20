#!/usr/bin/env python

import hashlib
import os
import sys
import unittest

from gnutls.crypto import PrivateKey, RSAPrivateKey
from gnutls.errors import GNUTLSError
from gnutls.library.constants import GNUTLS_PK_RSA, \
    GNUTLS_DIG_SHA1, GNUTLS_DIG_SHA256, GNUTLS_DIG_SHA512, \
    GNUTLS_SIGN_RSA_SHA1, GNUTLS_SIGN_RSA_SHA256, GNUTLS_SIGN_RSA_SHA512, \
    GNUTLS_PK_DSA, \
    GNUTLS_SIGN_DSA_SHA1, GNUTLS_SIGN_DSA_SHA256, GNUTLS_SIGN_DSA_SHA512

def is_tpm_not_available_error(err_message):

    errors = ['TPM key was not found in persistent storage.',
              'Cannot initialize a session with the TPM.',
              'An unimplemented or disabled feature has been requested.']
    for error in errors:
        if err_message.find(error) >= 0:
            return True
    return False


class TestSigning(unittest.TestCase):

    def test_generate_rsa_and_sign(self):
        teststring = b'foobar'

        for bits in [1024, 2048]:
            privkey = PrivateKey.generate(algo=GNUTLS_PK_RSA, bits=bits)
            pubkey = privkey.get_public_key()
            for hash_algo, sign_algo, hashfunc in \
                    [(GNUTLS_DIG_SHA256, GNUTLS_SIGN_RSA_SHA256, hashlib.sha256),
                     (GNUTLS_DIG_SHA1,   GNUTLS_SIGN_RSA_SHA1,   hashlib.sha1),
                     (GNUTLS_DIG_SHA512, GNUTLS_SIGN_RSA_SHA512, hashlib.sha512)]:
                signature = privkey.sign_data(hash_algo, 0, teststring)
                self.assertEqual(len(signature), bits / 8)
                pubkey.verify_data2(sign_algo, 0, teststring, signature)

                myhash = hashfunc(teststring).digest()
                pubkey.verify_hash2(sign_algo, 0, myhash, signature)

                signature2 = privkey.sign_hash(hash_algo, 0, myhash)
                self.assertEqual(len(signature2), bits / 8)
                pubkey.verify_hash2(sign_algo, 0, myhash, signature2)

    def test_generate_dsa_and_sign(self):
        teststring = b'foobar'

        for bits in [2048]:
            privkey = PrivateKey.generate(GNUTLS_PK_DSA, bits)
            pubkey = privkey.get_public_key()
            for hash_algo, sign_algo, hashfunc in \
                    [(GNUTLS_DIG_SHA256, GNUTLS_SIGN_DSA_SHA256, hashlib.sha256),
                     (GNUTLS_DIG_SHA1,   GNUTLS_SIGN_DSA_SHA1,   hashlib.sha1),
                     (GNUTLS_DIG_SHA512, GNUTLS_SIGN_DSA_SHA512, hashlib.sha512)]:
                signature = privkey.sign_data(hash_algo, 0, teststring)
                pubkey.verify_data2(sign_algo, 0, teststring, signature)

                myhash = hashfunc(teststring).digest()
                pubkey.verify_hash2(sign_algo, 0, myhash, signature)

                signature2 = privkey.sign_hash(hash_algo, 0, myhash)
                pubkey.verify_hash2(sign_algo, 0, myhash, signature2)

    def test_tpmkey_sign(self):
        teststring = b'foobar'

        try:
            privkey = PrivateKey.import_uri(
                'tpmkey:uuid=e93a2bc9-6777-467c-8704-c7b25ca7c45b;storage=system')
        except GNUTLSError as ex:
            if is_tpm_not_available_error(str(ex)):
                return unittest.skip("Key not available")
            raise ex
        signature = privkey.sign_data(GNUTLS_DIG_SHA1, 0, teststring)
        self.assertEqual(len(signature), 256)
        pubkey = privkey.get_public_key()
        pubkey.verify_data2(GNUTLS_SIGN_RSA_SHA1, 0, teststring, signature)


class TestEncryption(unittest.TestCase):

    def test_generate_rsa_and_encrypt(self):
        teststring = b'foobar'

        for bits in [1024, 2048]:
            privkey = RSAPrivateKey.generate(bits=bits)
            pubkey = privkey.get_public_key()

            enc_data = pubkey.encrypt_data(0, teststring)
            self.assertEqual(len(enc_data), bits / 8)
            plaintext = privkey.decrypt_data(0, enc_data)
            self.assertEqual(plaintext, teststring)
