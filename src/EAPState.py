#!/bin/usr/env python

import scapy.all as sc
import TLSState

class EAPState:
    '''
    Holds the state of EAP
    '''

    # SULState is only used here for the base packet header
    def __init__(self, staMac, apMac, user_id, sul, anon_id=None):
        '''
        Constructor for EAP state machine

        _

        :param staMac: static MAC, for injector card
        :param apMac: access point MAC
        :param anon_id: radius logon anonymous id
        :param user_id: radius logon user id
        '''
        self.staMac = staMac
        self.apMac = apMac
        self.user_id = user_id
        self.anon_id = anon_id
        self.count_id = 1
        self.sul = sul

    def id_resp(self):
        '''
        Create optionally anonymous user id response packet
        '''
        if self.anon_id:
            pac = (
                self.sul.queries['HEADER'] /
                sc.EAP(code='Response',
                       id=self.count_id, type='Identity', identity=self.anon_id))
        else:
            pac = (
                self.sul.queries['HEADER'] /
                sc.EAP(code='Response',
                       id=self.count_id, type='Identity', identity=self.user_id))

        return pac


    def enc_resp(self, enc_type):
        '''
        Create EAP implementation method

        _

        :param enc_type: EAP encryption type
        '''

        # Supported auth types
        auth_types = {
            'TTLS':21
        }

        self.enc_type = enc_type
        pac = (
            self.sul.queries['HEADER'] /
            sc.EAP(code='Response',
                   id=self.count_id, type='Legacy Nak', desired_auth_type=auth_types[enc_type]))
        pac[sc.EAP].len = len(pac[sc.EAP])
        pac[sc.EAPOL].len = pac[sc.EAP].len
        return pac


    def client_hello(self):
        '''
        Create the client hello packet
        '''
        self.ch = sc.TLSClientHello(
            version='TLS_1_2',
            #cipher_suites=[sc.TLSCipherSuite.TLS_AES_128_CCM_SHA256, 0xc030])
            #cipher_suites=[0xc030])
            cipher_suites=list(range(0xff)))

        data = sc.SSL(records=[
            sc.TLSRecord(content_type='handshake', version='TLS_1_2')
            / sc.TLSHandshake(type='client_hello')
            / self.ch])

        pac = (
            self.sul.queries['HEADER'] /
            sc.EAP_TTLS(code='Response',
                        id=self.count_id, type='EAP-TTLS',
                        L=0, M=0, S=0, reserved=0, version=0,
                        data=data))
        return pac

    def sh_resp(self):
        '''
        Create response to client hello parts
        '''
        # Type 21 - TTLS
        pac = (
            self.sul.queries['HEADER'] /
            sc.EAP(code='Response',
                   id=self.count_id, type=21))
        return pac
