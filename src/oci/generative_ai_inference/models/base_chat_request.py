# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20231130


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class BaseChatRequest(object):
    """
    The base class to use for the chat inference request.
    """

    #: A constant which can be used with the api_format property of a BaseChatRequest.
    #: This constant has a value of "COHERE"
    API_FORMAT_COHERE = "COHERE"

    #: A constant which can be used with the api_format property of a BaseChatRequest.
    #: This constant has a value of "GENERIC"
    API_FORMAT_GENERIC = "GENERIC"

    def __init__(self, **kwargs):
        """
        Initializes a new BaseChatRequest object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.generative_ai_inference.models.GenericChatRequest`
        * :class:`~oci.generative_ai_inference.models.CohereChatRequest`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param api_format:
            The value to assign to the api_format property of this BaseChatRequest.
            Allowed values for this property are: "COHERE", "GENERIC"
        :type api_format: str

        """
        self.swagger_types = {
            'api_format': 'str'
        }

        self.attribute_map = {
            'api_format': 'apiFormat'
        }

        self._api_format = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['apiFormat']

        if type == 'GENERIC':
            return 'GenericChatRequest'

        if type == 'COHERE':
            return 'CohereChatRequest'
        else:
            return 'BaseChatRequest'

    @property
    def api_format(self):
        """
        **[Required]** Gets the api_format of this BaseChatRequest.
        The API format for the model's family group.
        COHERE is for the Cohere family models such as the cohere.command-r-16k and cohere.command-r-plus models.
        GENERIC is for other model families such as the meta.llama-3-70b-instruct model.

        Allowed values for this property are: "COHERE", "GENERIC"


        :return: The api_format of this BaseChatRequest.
        :rtype: str
        """
        return self._api_format

    @api_format.setter
    def api_format(self, api_format):
        """
        Sets the api_format of this BaseChatRequest.
        The API format for the model's family group.
        COHERE is for the Cohere family models such as the cohere.command-r-16k and cohere.command-r-plus models.
        GENERIC is for other model families such as the meta.llama-3-70b-instruct model.


        :param api_format: The api_format of this BaseChatRequest.
        :type: str
        """
        allowed_values = ["COHERE", "GENERIC"]
        if not value_allowed_none_or_none_sentinel(api_format, allowed_values):
            raise ValueError(
                f"Invalid value for `api_format`, must be None or one of {allowed_values}"
            )
        self._api_format = api_format

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
