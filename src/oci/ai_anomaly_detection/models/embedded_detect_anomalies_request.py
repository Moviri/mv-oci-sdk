# coding: utf-8
# Copyright (c) 2016, 2021, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .detect_anomalies_details import DetectAnomaliesDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class EmbeddedDetectAnomaliesRequest(DetectAnomaliesDetails):
    """
    The request body when the user selects to provide byte data in detect call which is Base64 encoded.
    The default type of the data is CSV and can be JSON by setting the 'contentType'.
    """

    #: A constant which can be used with the content_type property of a EmbeddedDetectAnomaliesRequest.
    #: This constant has a value of "CSV"
    CONTENT_TYPE_CSV = "CSV"

    #: A constant which can be used with the content_type property of a EmbeddedDetectAnomaliesRequest.
    #: This constant has a value of "JSON"
    CONTENT_TYPE_JSON = "JSON"

    def __init__(self, **kwargs):
        """
        Initializes a new EmbeddedDetectAnomaliesRequest object with values from keyword arguments. The default value of the :py:attr:`~oci.ai_anomaly_detection.models.EmbeddedDetectAnomaliesRequest.request_type` attribute
        of this class is ``BASE64_ENCODED`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param model_id:
            The value to assign to the model_id property of this EmbeddedDetectAnomaliesRequest.
        :type model_id: str

        :param request_type:
            The value to assign to the request_type property of this EmbeddedDetectAnomaliesRequest.
            Allowed values for this property are: "INLINE", "BASE64_ENCODED"
        :type request_type: str

        :param content_type:
            The value to assign to the content_type property of this EmbeddedDetectAnomaliesRequest.
            Allowed values for this property are: "CSV", "JSON"
        :type content_type: str

        :param content:
            The value to assign to the content property of this EmbeddedDetectAnomaliesRequest.
        :type content: str

        """
        self.swagger_types = {
            'model_id': 'str',
            'request_type': 'str',
            'content_type': 'str',
            'content': 'str'
        }

        self.attribute_map = {
            'model_id': 'modelId',
            'request_type': 'requestType',
            'content_type': 'contentType',
            'content': 'content'
        }

        self._model_id = None
        self._request_type = None
        self._content_type = None
        self._content = None
        self._request_type = 'BASE64_ENCODED'

    @property
    def content_type(self):
        """
        Gets the content_type of this EmbeddedDetectAnomaliesRequest.
        Allowed values for this property are: "CSV", "JSON"


        :return: The content_type of this EmbeddedDetectAnomaliesRequest.
        :rtype: str
        """
        return self._content_type

    @content_type.setter
    def content_type(self, content_type):
        """
        Sets the content_type of this EmbeddedDetectAnomaliesRequest.

        :param content_type: The content_type of this EmbeddedDetectAnomaliesRequest.
        :type: str
        """
        allowed_values = ["CSV", "JSON"]
        if not value_allowed_none_or_none_sentinel(content_type, allowed_values):
            raise ValueError(
                "Invalid value for `content_type`, must be None or one of {0}"
                .format(allowed_values)
            )
        self._content_type = content_type

    @property
    def content(self):
        """
        **[Required]** Gets the content of this EmbeddedDetectAnomaliesRequest.

        :return: The content of this EmbeddedDetectAnomaliesRequest.
        :rtype: str
        """
        return self._content

    @content.setter
    def content(self, content):
        """
        Sets the content of this EmbeddedDetectAnomaliesRequest.

        :param content: The content of this EmbeddedDetectAnomaliesRequest.
        :type: str
        """
        self._content = content

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
