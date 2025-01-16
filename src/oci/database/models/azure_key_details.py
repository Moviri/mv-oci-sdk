# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918

from .autonomous_database_encryption_key_details import AutonomousDatabaseEncryptionKeyDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AzureKeyDetails(AutonomousDatabaseEncryptionKeyDetails):
    """
    Details for Azure encryption key.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new AzureKeyDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.database.models.AzureKeyDetails.provider` attribute
        of this class is ``AZURE`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param provider:
            The value to assign to the provider property of this AzureKeyDetails.
            Allowed values for this property are: "AWS", "AZURE", "OCI", "ORACLE_MANAGED", "OKV"
        :type provider: str

        :param vault_uri:
            The value to assign to the vault_uri property of this AzureKeyDetails.
        :type vault_uri: str

        :param key_name:
            The value to assign to the key_name property of this AzureKeyDetails.
        :type key_name: str

        """
        self.swagger_types = {
            'provider': 'str',
            'vault_uri': 'str',
            'key_name': 'str'
        }

        self.attribute_map = {
            'provider': 'provider',
            'vault_uri': 'vaultUri',
            'key_name': 'keyName'
        }

        self._provider = None
        self._vault_uri = None
        self._key_name = None
        self._provider = 'AZURE'

    @property
    def vault_uri(self):
        """
        **[Required]** Gets the vault_uri of this AzureKeyDetails.
        Azure vault URI


        :return: The vault_uri of this AzureKeyDetails.
        :rtype: str
        """
        return self._vault_uri

    @vault_uri.setter
    def vault_uri(self, vault_uri):
        """
        Sets the vault_uri of this AzureKeyDetails.
        Azure vault URI


        :param vault_uri: The vault_uri of this AzureKeyDetails.
        :type: str
        """
        self._vault_uri = vault_uri

    @property
    def key_name(self):
        """
        **[Required]** Gets the key_name of this AzureKeyDetails.
        Azure key name


        :return: The key_name of this AzureKeyDetails.
        :rtype: str
        """
        return self._key_name

    @key_name.setter
    def key_name(self, key_name):
        """
        Sets the key_name of this AzureKeyDetails.
        Azure key name


        :param key_name: The key_name of this AzureKeyDetails.
        :type: str
        """
        self._key_name = key_name

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other