# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220615


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class IngressListenerTlsConfig(object):
    """
    TLS enforcement config for the ingress listener.
    """

    #: A constant which can be used with the mode property of a IngressListenerTlsConfig.
    #: This constant has a value of "DISABLED"
    MODE_DISABLED = "DISABLED"

    #: A constant which can be used with the mode property of a IngressListenerTlsConfig.
    #: This constant has a value of "PERMISSIVE"
    MODE_PERMISSIVE = "PERMISSIVE"

    #: A constant which can be used with the mode property of a IngressListenerTlsConfig.
    #: This constant has a value of "TLS"
    MODE_TLS = "TLS"

    #: A constant which can be used with the mode property of a IngressListenerTlsConfig.
    #: This constant has a value of "MUTUAL_TLS"
    MODE_MUTUAL_TLS = "MUTUAL_TLS"

    def __init__(self, **kwargs):
        """
        Initializes a new IngressListenerTlsConfig object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param mode:
            The value to assign to the mode property of this IngressListenerTlsConfig.
            Allowed values for this property are: "DISABLED", "PERMISSIVE", "TLS", "MUTUAL_TLS", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type mode: str

        :param server_certificate:
            The value to assign to the server_certificate property of this IngressListenerTlsConfig.
        :type server_certificate: oci.service_mesh.models.TlsCertificate

        :param client_validation:
            The value to assign to the client_validation property of this IngressListenerTlsConfig.
        :type client_validation: oci.service_mesh.models.IngressListenerClientValidationConfig

        """
        self.swagger_types = {
            'mode': 'str',
            'server_certificate': 'TlsCertificate',
            'client_validation': 'IngressListenerClientValidationConfig'
        }

        self.attribute_map = {
            'mode': 'mode',
            'server_certificate': 'serverCertificate',
            'client_validation': 'clientValidation'
        }

        self._mode = None
        self._server_certificate = None
        self._client_validation = None

    @property
    def mode(self):
        """
        **[Required]** Gets the mode of this IngressListenerTlsConfig.
        DISABLED: Connection can only be plaintext.
        PERMISSIVE: Connection can be either plaintext or TLS/mTLS. If the clientValidation.trustedCaBundle property is configured for the listener, mTLS is performed and the client's certificates are validated by the gateway.
        TLS: Connection can only be TLS.
        MUTUAL_TLS: Connection can only be MTLS.

        Allowed values for this property are: "DISABLED", "PERMISSIVE", "TLS", "MUTUAL_TLS", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The mode of this IngressListenerTlsConfig.
        :rtype: str
        """
        return self._mode

    @mode.setter
    def mode(self, mode):
        """
        Sets the mode of this IngressListenerTlsConfig.
        DISABLED: Connection can only be plaintext.
        PERMISSIVE: Connection can be either plaintext or TLS/mTLS. If the clientValidation.trustedCaBundle property is configured for the listener, mTLS is performed and the client's certificates are validated by the gateway.
        TLS: Connection can only be TLS.
        MUTUAL_TLS: Connection can only be MTLS.


        :param mode: The mode of this IngressListenerTlsConfig.
        :type: str
        """
        allowed_values = ["DISABLED", "PERMISSIVE", "TLS", "MUTUAL_TLS"]
        if not value_allowed_none_or_none_sentinel(mode, allowed_values):
            mode = 'UNKNOWN_ENUM_VALUE'
        self._mode = mode

    @property
    def server_certificate(self):
        """
        Gets the server_certificate of this IngressListenerTlsConfig.

        :return: The server_certificate of this IngressListenerTlsConfig.
        :rtype: oci.service_mesh.models.TlsCertificate
        """
        return self._server_certificate

    @server_certificate.setter
    def server_certificate(self, server_certificate):
        """
        Sets the server_certificate of this IngressListenerTlsConfig.

        :param server_certificate: The server_certificate of this IngressListenerTlsConfig.
        :type: oci.service_mesh.models.TlsCertificate
        """
        self._server_certificate = server_certificate

    @property
    def client_validation(self):
        """
        Gets the client_validation of this IngressListenerTlsConfig.

        :return: The client_validation of this IngressListenerTlsConfig.
        :rtype: oci.service_mesh.models.IngressListenerClientValidationConfig
        """
        return self._client_validation

    @client_validation.setter
    def client_validation(self, client_validation):
        """
        Sets the client_validation of this IngressListenerTlsConfig.

        :param client_validation: The client_validation of this IngressListenerTlsConfig.
        :type: oci.service_mesh.models.IngressListenerClientValidationConfig
        """
        self._client_validation = client_validation

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
