# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220101


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class Pronunciation(object):
    """
    Pronunciation Object Reference
    """

    def __init__(self, **kwargs):
        """
        Initializes a new Pronunciation object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param sounds_like:
            The value to assign to the sounds_like property of this Pronunciation.
        :type sounds_like: str

        :param audio:
            The value to assign to the audio property of this Pronunciation.
        :type audio: oci.ai_speech.models.LocationDetails

        """
        self.swagger_types = {
            'sounds_like': 'str',
            'audio': 'LocationDetails'
        }

        self.attribute_map = {
            'sounds_like': 'soundsLike',
            'audio': 'audio'
        }

        self._sounds_like = None
        self._audio = None

    @property
    def sounds_like(self):
        """
        Gets the sounds_like of this Pronunciation.
        Written phonetic representation of entity value


        :return: The sounds_like of this Pronunciation.
        :rtype: str
        """
        return self._sounds_like

    @sounds_like.setter
    def sounds_like(self, sounds_like):
        """
        Sets the sounds_like of this Pronunciation.
        Written phonetic representation of entity value


        :param sounds_like: The sounds_like of this Pronunciation.
        :type: str
        """
        self._sounds_like = sounds_like

    @property
    def audio(self):
        """
        Gets the audio of this Pronunciation.

        :return: The audio of this Pronunciation.
        :rtype: oci.ai_speech.models.LocationDetails
        """
        return self._audio

    @audio.setter
    def audio(self, audio):
        """
        Sets the audio of this Pronunciation.

        :param audio: The audio of this Pronunciation.
        :type: oci.ai_speech.models.LocationDetails
        """
        self._audio = audio

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
