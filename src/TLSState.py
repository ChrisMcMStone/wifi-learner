#!/bin/usr/env python

import scapy.all as sc
import utility.utils as utils
from Cryptodome.PublicKey import RSA

class TLSState:
    '''
    Holds the TLS connection info and create packets
    '''


    def __init__(self, client_hello, sul):
        self.client_hello = client_hello
        self.tls_version = 'TLS_1_2'
        self.sul = sul
        self.private = RSA.generate(1024)
        self.public = self.private.publickey()

    def server_key(self):
        return (self.server_hello
                .records[1]
                .handshakes[0][TLSCertificate]
                .data
                .tbsCertificate
                .subjectPublicKeyInfo
                .subjectPublicKey)

    def server_hello(self, server_hello):
        self.server_hello = server_hello

    def encrypt(self, message):
        return server_key().encrypt(message)

    def decrypt(self, ciphertext):
        return self.private.decrypt(ciphertext)

    def client_key_exchange(self):
        pac = self.sul.queries['HEADER']

        handshake = (sc.TLSRecord(content_type='handshake',
                                  version=self.tls_version) /
                     sc.TLSHandshakes(handshakes=[
                         sc.TLSHandshake(type='client_key_exchange') /
                         sc.TLSClientKeyExchange() /
                         sc.TLSClientRSAParams(data=
                                               utils.long2bytes(self.public.n))]))

        change_cipher_spec = (sc.TLSRecord(content_type='change_cipher_spec',
                                           version=self.tls_version) /
                              sc.TLSChangeCipherSpec(message=b'\x01'))

        ciphertext = (sc.TLSRecord(content_type='handshake',
                                   version=self.tls_version) /
                      sc.TLSCiphertext(data=''))

        pac = pac / sc.SSL(records=[
            handshake,
            change_cipher_spec,
            ciphertext
        ])

        return pac
