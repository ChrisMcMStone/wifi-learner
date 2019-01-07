#!/bin/usr/env python

import scapy.all as sc
import TLS

class EAPState:
    """
    Holds the state of EAP
    """

    def __init__(self, staMac, apMac, user_id, anon_id=None):
        """
        Constructor for EAP state machine

        _

        :param staMac: static MAC, for injector card
        :param apMac: access point MAC
        :param anon_id: radius logon anonymous id
        :param user_id: radius logon user id
        """
        self.staMac = staMac
        self.apMac = apMac
        self.user_id = user_id
        self.anon_id = anon_id

        # Base header packet for EAPOL communication
        self.base_packet = (sc.RadioTap()
                            / sc.Dot11(FCfield='to-DS')
                            / sc.LLC()
                            / sc.SNAP()
                            / sc.EAPOL(version='802.1X-2001', type='EAP-Packet'))


    def id_resp(self):
        """
        Create optionally anonymous user id response packet
        """
        if self.anon_id:
            pac = (
                self.base_packet /
                sc.EAP(code='Response',
                       id=1, type='Identity', identity=self.anon_id))
        else:
            pac = (
                self.base_packet /
                sc.EAP(code='Response',
                       id=1, type='Identity', identity=self.user_id))

        pac[sc.EAP].len = len(pac[sc.EAP])
        pac[sc.EAPOL].len = pac[sc.EAP].len
        return pac


    def enc_resp(self, enc_type):
        """
        Create EAP implementation method

        _

        :param enc_type: EAP encryption type
        """

        # Supported auth types
        auth_types = {
            'TTLS':21
        }

        self.enc_type = enc_type
        pac = (
            self.base_packet /
            sc.EAP(code='Response',
                   id=2, type='Legacy Nak', desired_auth_type=auth_types[enc_type]))
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

