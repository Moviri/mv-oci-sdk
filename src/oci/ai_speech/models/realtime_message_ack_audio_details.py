# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220101


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class RealtimeMessageAckAudioDetails(object):
    """
    Details object for the websocket ack message received from service.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new RealtimeMessageAckAudioDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param number:
            The value to assign to the number property of this RealtimeMessageAckAudioDetails.
        :type number: int

        :param offset:
            The value to assign to the offset property of this RealtimeMessageAckAudioDetails.
        :type offset: int

        :param length:
            The value to assign to the length property of this RealtimeMessageAckAudioDetails.
        :type length: int

        """
        self.swagger_types = {
            'number': 'int',
            'offset': 'int',
            'length': 'int'
        }

        self.attribute_map = {
            'number': 'number',
            'offset': 'offset',
            'length': 'length'
        }

        self._number = None
        self._offset = None
        self._length = None

    @property
    def number(self):
        """
        **[Required]** Gets the number of this RealtimeMessageAckAudioDetails.
        Sequence number of the acknowledged packet.


        :return: The number of this RealtimeMessageAckAudioDetails.
        :rtype: int
        """
        return self._number

    @number.setter
    def number(self, number):
        """
        Sets the number of this RealtimeMessageAckAudioDetails.
        Sequence number of the acknowledged packet.


        :param number: The number of this RealtimeMessageAckAudioDetails.
        :type: int
        """
        self._number = number

    @property
    def offset(self):
        """
        **[Required]** Gets the offset of this RealtimeMessageAckAudioDetails.
        Offset of the acknowledged packet.


        :return: The offset of this RealtimeMessageAckAudioDetails.
        :rtype: int
        """
        return self._offset

    @offset.setter
    def offset(self, offset):
        """
        Sets the offset of this RealtimeMessageAckAudioDetails.
        Offset of the acknowledged packet.


        :param offset: The offset of this RealtimeMessageAckAudioDetails.
        :type: int
        """
        self._offset = offset

    @property
    def length(self):
        """
        **[Required]** Gets the length of this RealtimeMessageAckAudioDetails.
        Length in bytes of the acknowledged packet.


        :return: The length of this RealtimeMessageAckAudioDetails.
        :rtype: int
        """
        return self._length

    @length.setter
    def length(self, length):
        """
        Sets the length of this RealtimeMessageAckAudioDetails.
        Length in bytes of the acknowledged packet.


        :param length: The length of this RealtimeMessageAckAudioDetails.
        :type: int
        """
        self._length = length

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
