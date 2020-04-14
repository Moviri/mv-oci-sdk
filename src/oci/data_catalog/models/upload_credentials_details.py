# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates. All rights reserved.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UploadCredentialsDetails(object):
    """
    Upload credential file and connection metadata.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UploadCredentialsDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param connection_detail:
            The value to assign to the connection_detail property of this UploadCredentialsDetails.
        :type connection_detail: UpdateConnectionDetails

        :param credential_payload:
            The value to assign to the credential_payload property of this UploadCredentialsDetails.
        :type credential_payload: str

        """
        self.swagger_types = {
            'connection_detail': 'UpdateConnectionDetails',
            'credential_payload': 'str'
        }

        self.attribute_map = {
            'connection_detail': 'connectionDetail',
            'credential_payload': 'credentialPayload'
        }

        self._connection_detail = None
        self._credential_payload = None

    @property
    def connection_detail(self):
        """
        Gets the connection_detail of this UploadCredentialsDetails.

        :return: The connection_detail of this UploadCredentialsDetails.
        :rtype: UpdateConnectionDetails
        """
        return self._connection_detail

    @connection_detail.setter
    def connection_detail(self, connection_detail):
        """
        Sets the connection_detail of this UploadCredentialsDetails.

        :param connection_detail: The connection_detail of this UploadCredentialsDetails.
        :type: UpdateConnectionDetails
        """
        self._connection_detail = connection_detail

    @property
    def credential_payload(self):
        """
        **[Required]** Gets the credential_payload of this UploadCredentialsDetails.
        Information used in updating connection credentials.


        :return: The credential_payload of this UploadCredentialsDetails.
        :rtype: str
        """
        return self._credential_payload

    @credential_payload.setter
    def credential_payload(self, credential_payload):
        """
        Sets the credential_payload of this UploadCredentialsDetails.
        Information used in updating connection credentials.


        :param credential_payload: The credential_payload of this UploadCredentialsDetails.
        :type: str
        """
        self._credential_payload = credential_payload

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other