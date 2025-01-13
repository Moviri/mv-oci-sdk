# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220101


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class RealtimeMessage(object):
    """
    Websocket messages sent between client and service.
    """

    #: A constant which can be used with the event property of a RealtimeMessage.
    #: This constant has a value of "RESULT"
    EVENT_RESULT = "RESULT"

    #: A constant which can be used with the event property of a RealtimeMessage.
    #: This constant has a value of "ACKAUDIO"
    EVENT_ACKAUDIO = "ACKAUDIO"

    #: A constant which can be used with the event property of a RealtimeMessage.
    #: This constant has a value of "ERROR"
    EVENT_ERROR = "ERROR"

    #: A constant which can be used with the event property of a RealtimeMessage.
    #: This constant has a value of "CONNECT"
    EVENT_CONNECT = "CONNECT"

    def __init__(self, **kwargs):
        """
        Initializes a new RealtimeMessage object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.ai_speech.models.RealtimeMessageError`
        * :class:`~oci.ai_speech.models.RealtimeMessageAckAudio`
        * :class:`~oci.ai_speech.models.RealtimeMessageConnect`
        * :class:`~oci.ai_speech.models.RealtimeMessageResult`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param event:
            The value to assign to the event property of this RealtimeMessage.
            Allowed values for this property are: "RESULT", "ACKAUDIO", "ERROR", "CONNECT"
        :type event: str

        :param session_id:
            The value to assign to the session_id property of this RealtimeMessage.
        :type session_id: str

        """
        self.swagger_types = {
            'event': 'str',
            'session_id': 'str'
        }

        self.attribute_map = {
            'event': 'event',
            'session_id': 'sessionId'
        }

        self._event = None
        self._session_id = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['event']

        if type == 'ERROR':
            return 'RealtimeMessageError'

        if type == 'ACKAUDIO':
            return 'RealtimeMessageAckAudio'

        if type == 'CONNECT':
            return 'RealtimeMessageConnect'

        if type == 'RESULT':
            return 'RealtimeMessageResult'
        else:
            return 'RealtimeMessage'

    @property
    def event(self):
        """
        **[Required]** Gets the event of this RealtimeMessage.
        Incoming Types of message event sent from Service -> Client
        - RESULT - result
        - ACKAUDIO - ackAudio
        - ERROR - error
        - CONNECT - connect
        Outgoing Types of message event sent from Client -> Service
        - SEND_FINAL_RESULT - sendFinalResult

        Allowed values for this property are: "RESULT", "ACKAUDIO", "ERROR", "CONNECT"


        :return: The event of this RealtimeMessage.
        :rtype: str
        """
        return self._event

    @event.setter
    def event(self, event):
        """
        Sets the event of this RealtimeMessage.
        Incoming Types of message event sent from Service -> Client
        - RESULT - result
        - ACKAUDIO - ackAudio
        - ERROR - error
        - CONNECT - connect
        Outgoing Types of message event sent from Client -> Service
        - SEND_FINAL_RESULT - sendFinalResult


        :param event: The event of this RealtimeMessage.
        :type: str
        """
        allowed_values = ["RESULT", "ACKAUDIO", "ERROR", "CONNECT"]
        if not value_allowed_none_or_none_sentinel(event, allowed_values):
            raise ValueError(
                f"Invalid value for `event`, must be None or one of {allowed_values}"
            )
        self._event = event

    @property
    def session_id(self):
        """
        Gets the session_id of this RealtimeMessage.
        Session ID for the connected session.


        :return: The session_id of this RealtimeMessage.
        :rtype: str
        """
        return self._session_id

    @session_id.setter
    def session_id(self, session_id):
        """
        Sets the session_id of this RealtimeMessage.
        Session ID for the connected session.


        :param session_id: The session_id of this RealtimeMessage.
        :type: str
        """
        self._session_id = session_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
