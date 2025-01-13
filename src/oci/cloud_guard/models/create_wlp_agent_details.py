# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200131


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateWlpAgentDetails(object):
    """
    On-premise resource agent registration request resource.
    Example: `{\"compartmentId\": \"ocid1.compartment.oc1..exampleawwcufihrc62gpbcvbjizswgoj4w7rg5q4fwbg2fauxvlcxbtliaa\",
    \"agentVersion\": \"1.0.11\",
    \"certificateSignedRequest\": \"MIIGwjCCBaqgAwIBAgIVAK8hJCS/5Hu0dEMQ2ud\"}`
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateWlpAgentDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateWlpAgentDetails.
        :type compartment_id: str

        :param agent_version:
            The value to assign to the agent_version property of this CreateWlpAgentDetails.
        :type agent_version: str

        :param certificate_signed_request:
            The value to assign to the certificate_signed_request property of this CreateWlpAgentDetails.
        :type certificate_signed_request: str

        :param os_info:
            The value to assign to the os_info property of this CreateWlpAgentDetails.
        :type os_info: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateWlpAgentDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateWlpAgentDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'compartment_id': 'str',
            'agent_version': 'str',
            'certificate_signed_request': 'str',
            'os_info': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'compartment_id': 'compartmentId',
            'agent_version': 'agentVersion',
            'certificate_signed_request': 'certificateSignedRequest',
            'os_info': 'osInfo',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._compartment_id = None
        self._agent_version = None
        self._certificate_signed_request = None
        self._os_info = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateWlpAgentDetails.
        Compartment OCID of the host


        :return: The compartment_id of this CreateWlpAgentDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateWlpAgentDetails.
        Compartment OCID of the host


        :param compartment_id: The compartment_id of this CreateWlpAgentDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def agent_version(self):
        """
        **[Required]** Gets the agent_version of this CreateWlpAgentDetails.
        The version of the agent making the request


        :return: The agent_version of this CreateWlpAgentDetails.
        :rtype: str
        """
        return self._agent_version

    @agent_version.setter
    def agent_version(self, agent_version):
        """
        Sets the agent_version of this CreateWlpAgentDetails.
        The version of the agent making the request


        :param agent_version: The agent_version of this CreateWlpAgentDetails.
        :type: str
        """
        self._agent_version = agent_version

    @property
    def certificate_signed_request(self):
        """
        **[Required]** Gets the certificate_signed_request of this CreateWlpAgentDetails.
        The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key


        :return: The certificate_signed_request of this CreateWlpAgentDetails.
        :rtype: str
        """
        return self._certificate_signed_request

    @certificate_signed_request.setter
    def certificate_signed_request(self, certificate_signed_request):
        """
        Sets the certificate_signed_request of this CreateWlpAgentDetails.
        The certificate signed request containing domain, organization names, organization units, city, state, country, email and public key, among other certificate details, signed by private key


        :param certificate_signed_request: The certificate_signed_request of this CreateWlpAgentDetails.
        :type: str
        """
        self._certificate_signed_request = certificate_signed_request

    @property
    def os_info(self):
        """
        **[Required]** Gets the os_info of this CreateWlpAgentDetails.
        Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.


        :return: The os_info of this CreateWlpAgentDetails.
        :rtype: str
        """
        return self._os_info

    @os_info.setter
    def os_info(self, os_info):
        """
        Sets the os_info of this CreateWlpAgentDetails.
        Concatenated OS name, OS version and agent architecture; for example, ubuntu_22.0_amd64.


        :param os_info: The os_info of this CreateWlpAgentDetails.
        :type: str
        """
        self._os_info = os_info

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateWlpAgentDetails.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`

        Avoid entering confidential information.


        :return: The freeform_tags of this CreateWlpAgentDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateWlpAgentDetails.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`

        Avoid entering confidential information.


        :param freeform_tags: The freeform_tags of this CreateWlpAgentDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateWlpAgentDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this CreateWlpAgentDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateWlpAgentDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this CreateWlpAgentDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
