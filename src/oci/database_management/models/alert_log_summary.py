# coding: utf-8
# Copyright (c) 2016, 2022, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AlertLogSummary(object):
    """
    The detail for one alert log entry.
    """

    #: A constant which can be used with the message_level property of a AlertLogSummary.
    #: This constant has a value of "CRITICAL"
    MESSAGE_LEVEL_CRITICAL = "CRITICAL"

    #: A constant which can be used with the message_level property of a AlertLogSummary.
    #: This constant has a value of "SEVERE"
    MESSAGE_LEVEL_SEVERE = "SEVERE"

    #: A constant which can be used with the message_level property of a AlertLogSummary.
    #: This constant has a value of "IMPORTANT"
    MESSAGE_LEVEL_IMPORTANT = "IMPORTANT"

    #: A constant which can be used with the message_level property of a AlertLogSummary.
    #: This constant has a value of "NORMAL"
    MESSAGE_LEVEL_NORMAL = "NORMAL"

    #: A constant which can be used with the message_type property of a AlertLogSummary.
    #: This constant has a value of "UNKNOWN"
    MESSAGE_TYPE_UNKNOWN = "UNKNOWN"

    #: A constant which can be used with the message_type property of a AlertLogSummary.
    #: This constant has a value of "INCIDENT_ERROR"
    MESSAGE_TYPE_INCIDENT_ERROR = "INCIDENT_ERROR"

    #: A constant which can be used with the message_type property of a AlertLogSummary.
    #: This constant has a value of "ERROR"
    MESSAGE_TYPE_ERROR = "ERROR"

    #: A constant which can be used with the message_type property of a AlertLogSummary.
    #: This constant has a value of "WARNING"
    MESSAGE_TYPE_WARNING = "WARNING"

    #: A constant which can be used with the message_type property of a AlertLogSummary.
    #: This constant has a value of "NOTIFICATION"
    MESSAGE_TYPE_NOTIFICATION = "NOTIFICATION"

    #: A constant which can be used with the message_type property of a AlertLogSummary.
    #: This constant has a value of "TRACE"
    MESSAGE_TYPE_TRACE = "TRACE"

    def __init__(self, **kwargs):
        """
        Initializes a new AlertLogSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param message_level:
            The value to assign to the message_level property of this AlertLogSummary.
            Allowed values for this property are: "CRITICAL", "SEVERE", "IMPORTANT", "NORMAL", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type message_level: str

        :param message_type:
            The value to assign to the message_type property of this AlertLogSummary.
            Allowed values for this property are: "UNKNOWN", "INCIDENT_ERROR", "ERROR", "WARNING", "NOTIFICATION", "TRACE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type message_type: str

        :param message_content:
            The value to assign to the message_content property of this AlertLogSummary.
        :type message_content: str

        :param timestamp:
            The value to assign to the timestamp property of this AlertLogSummary.
        :type timestamp: datetime

        :param supplemental_detail:
            The value to assign to the supplemental_detail property of this AlertLogSummary.
        :type supplemental_detail: str

        :param file_location:
            The value to assign to the file_location property of this AlertLogSummary.
        :type file_location: str

        """
        self.swagger_types = {
            'message_level': 'str',
            'message_type': 'str',
            'message_content': 'str',
            'timestamp': 'datetime',
            'supplemental_detail': 'str',
            'file_location': 'str'
        }

        self.attribute_map = {
            'message_level': 'messageLevel',
            'message_type': 'messageType',
            'message_content': 'messageContent',
            'timestamp': 'timestamp',
            'supplemental_detail': 'supplementalDetail',
            'file_location': 'fileLocation'
        }

        self._message_level = None
        self._message_type = None
        self._message_content = None
        self._timestamp = None
        self._supplemental_detail = None
        self._file_location = None

    @property
    def message_level(self):
        """
        **[Required]** Gets the message_level of this AlertLogSummary.
        The level of the alert log.

        Allowed values for this property are: "CRITICAL", "SEVERE", "IMPORTANT", "NORMAL", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The message_level of this AlertLogSummary.
        :rtype: str
        """
        return self._message_level

    @message_level.setter
    def message_level(self, message_level):
        """
        Sets the message_level of this AlertLogSummary.
        The level of the alert log.


        :param message_level: The message_level of this AlertLogSummary.
        :type: str
        """
        allowed_values = ["CRITICAL", "SEVERE", "IMPORTANT", "NORMAL"]
        if not value_allowed_none_or_none_sentinel(message_level, allowed_values):
            message_level = 'UNKNOWN_ENUM_VALUE'
        self._message_level = message_level

    @property
    def message_type(self):
        """
        **[Required]** Gets the message_type of this AlertLogSummary.
        The type of alert log message.

        Allowed values for this property are: "UNKNOWN", "INCIDENT_ERROR", "ERROR", "WARNING", "NOTIFICATION", "TRACE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The message_type of this AlertLogSummary.
        :rtype: str
        """
        return self._message_type

    @message_type.setter
    def message_type(self, message_type):
        """
        Sets the message_type of this AlertLogSummary.
        The type of alert log message.


        :param message_type: The message_type of this AlertLogSummary.
        :type: str
        """
        allowed_values = ["UNKNOWN", "INCIDENT_ERROR", "ERROR", "WARNING", "NOTIFICATION", "TRACE"]
        if not value_allowed_none_or_none_sentinel(message_type, allowed_values):
            message_type = 'UNKNOWN_ENUM_VALUE'
        self._message_type = message_type

    @property
    def message_content(self):
        """
        Gets the message_content of this AlertLogSummary.
        The contents of the alert log message.


        :return: The message_content of this AlertLogSummary.
        :rtype: str
        """
        return self._message_content

    @message_content.setter
    def message_content(self, message_content):
        """
        Sets the message_content of this AlertLogSummary.
        The contents of the alert log message.


        :param message_content: The message_content of this AlertLogSummary.
        :type: str
        """
        self._message_content = message_content

    @property
    def timestamp(self):
        """
        Gets the timestamp of this AlertLogSummary.
        The date and time the alert log was created.


        :return: The timestamp of this AlertLogSummary.
        :rtype: datetime
        """
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        """
        Sets the timestamp of this AlertLogSummary.
        The date and time the alert log was created.


        :param timestamp: The timestamp of this AlertLogSummary.
        :type: datetime
        """
        self._timestamp = timestamp

    @property
    def supplemental_detail(self):
        """
        Gets the supplemental_detail of this AlertLogSummary.
        The supplemental details of the alert log.


        :return: The supplemental_detail of this AlertLogSummary.
        :rtype: str
        """
        return self._supplemental_detail

    @supplemental_detail.setter
    def supplemental_detail(self, supplemental_detail):
        """
        Sets the supplemental_detail of this AlertLogSummary.
        The supplemental details of the alert log.


        :param supplemental_detail: The supplemental_detail of this AlertLogSummary.
        :type: str
        """
        self._supplemental_detail = supplemental_detail

    @property
    def file_location(self):
        """
        Gets the file_location of this AlertLogSummary.
        The alert log file location.


        :return: The file_location of this AlertLogSummary.
        :rtype: str
        """
        return self._file_location

    @file_location.setter
    def file_location(self, file_location):
        """
        Sets the file_location of this AlertLogSummary.
        The alert log file location.


        :param file_location: The file_location of this AlertLogSummary.
        :type: str
        """
        self._file_location = file_location

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
