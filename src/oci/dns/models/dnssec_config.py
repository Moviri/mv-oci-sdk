# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20180115


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DnssecConfig(object):
    """
    DNSSEC configuration data.

    A zone may have a maximum of 10 `DnssecKeyVersions`, regardless of signing key type.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DnssecConfig object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param ksk_dnssec_key_versions:
            The value to assign to the ksk_dnssec_key_versions property of this DnssecConfig.
        :type ksk_dnssec_key_versions: list[oci.dns.models.KskDnssecKeyVersion]

        :param zsk_dnssec_key_versions:
            The value to assign to the zsk_dnssec_key_versions property of this DnssecConfig.
        :type zsk_dnssec_key_versions: list[oci.dns.models.ZskDnssecKeyVersion]

        """
        self.swagger_types = {
            'ksk_dnssec_key_versions': 'list[KskDnssecKeyVersion]',
            'zsk_dnssec_key_versions': 'list[ZskDnssecKeyVersion]'
        }

        self.attribute_map = {
            'ksk_dnssec_key_versions': 'kskDnssecKeyVersions',
            'zsk_dnssec_key_versions': 'zskDnssecKeyVersions'
        }

        self._ksk_dnssec_key_versions = None
        self._zsk_dnssec_key_versions = None

    @property
    def ksk_dnssec_key_versions(self):
        """
        Gets the ksk_dnssec_key_versions of this DnssecConfig.
        A read-only array of key signing key (KSK) versions.


        :return: The ksk_dnssec_key_versions of this DnssecConfig.
        :rtype: list[oci.dns.models.KskDnssecKeyVersion]
        """
        return self._ksk_dnssec_key_versions

    @ksk_dnssec_key_versions.setter
    def ksk_dnssec_key_versions(self, ksk_dnssec_key_versions):
        """
        Sets the ksk_dnssec_key_versions of this DnssecConfig.
        A read-only array of key signing key (KSK) versions.


        :param ksk_dnssec_key_versions: The ksk_dnssec_key_versions of this DnssecConfig.
        :type: list[oci.dns.models.KskDnssecKeyVersion]
        """
        self._ksk_dnssec_key_versions = ksk_dnssec_key_versions

    @property
    def zsk_dnssec_key_versions(self):
        """
        Gets the zsk_dnssec_key_versions of this DnssecConfig.
        A read-only array of zone signing key (ZSK) versions.


        :return: The zsk_dnssec_key_versions of this DnssecConfig.
        :rtype: list[oci.dns.models.ZskDnssecKeyVersion]
        """
        return self._zsk_dnssec_key_versions

    @zsk_dnssec_key_versions.setter
    def zsk_dnssec_key_versions(self, zsk_dnssec_key_versions):
        """
        Sets the zsk_dnssec_key_versions of this DnssecConfig.
        A read-only array of zone signing key (ZSK) versions.


        :param zsk_dnssec_key_versions: The zsk_dnssec_key_versions of this DnssecConfig.
        :type: list[oci.dns.models.ZskDnssecKeyVersion]
        """
        self._zsk_dnssec_key_versions = zsk_dnssec_key_versions

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
