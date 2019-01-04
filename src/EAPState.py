#!/bin/usr/env python

import scapy.all as sc
import TLS

class EAPState:
    """
    Holds the state of EAP
    """

    def __init__(self, staMac, apMac):
        """
        Constructor for EAP state machine

        _

        :param staMac: static MAC, for injector card
        :param apMac: access point MAC
        :param anon_iden: radius logon anonymous identity
        :param iden: radius logon identity
        """
        self.staMac = staMac
        self.apMac = apMac

        # Base header packet for EAPOL communication
        self.base_packet = (
            sc.Ether(dst=self.apMac, src=self.staMac, type=0x888e) /
            sc.EAPOL(version='802.1X-2001', type='EAP-Packet'))


    def id_resp(self, iden, anon_iden):
        self.iden = iden
        self.anon_iden = anon_iden
        """
        Create optionally anonymous identity response packet
        """
        pac = (
            self.base_packet /
            sc.EAP(code='Response',
                   id=1, type='Identity', identity=self.anon_iden))
        pac[sc.EAP].len = len(pac[sc.EAP])
        pac[sc.EAPOL].len = pac[sc.EAP].len
        return pac


    def enc_resp(self, enc_type):
        """
        Create EAP implementation method

        _

        :param enc_type: EAP encryption type
        """
        self.enc_type = enc_type
        pac = (
            self.base_packet /
            sc.EAP(code='Response',
                   id=2, type='Legacy Nak', desired_auth_type=enc_type))
        pac[sc.EAP].len = len(pac[sc.EAP])
        pac[sc.EAPOL].len = pac[sc.EAP].len
        return pac


    def client_hello(self):
        """
        Create the client hello packet
        """
        pac = (
            self.base_packet /
            sc.EAP_TTLS(code='Response',
                        id=3, type='EAP-TTLS',
                        L=0, M=0, S=0, reserved=0, verion=0,
                        data=TLS.client_hello()))

