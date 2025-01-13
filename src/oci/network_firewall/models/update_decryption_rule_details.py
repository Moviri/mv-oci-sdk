# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230501


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateDecryptionRuleDetails(object):
    """
    Request for updating Decryption Rule used in the firewall policy rules.
    A Decryption Rule is used to define which traffic should be decrypted by the firewall, and how it should do so.
    """

    #: A constant which can be used with the action property of a UpdateDecryptionRuleDetails.
    #: This constant has a value of "NO_DECRYPT"
    ACTION_NO_DECRYPT = "NO_DECRYPT"

    #: A constant which can be used with the action property of a UpdateDecryptionRuleDetails.
    #: This constant has a value of "DECRYPT"
    ACTION_DECRYPT = "DECRYPT"

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateDecryptionRuleDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param condition:
            The value to assign to the condition property of this UpdateDecryptionRuleDetails.
        :type condition: oci.network_firewall.models.DecryptionRuleMatchCriteria

        :param action:
            The value to assign to the action property of this UpdateDecryptionRuleDetails.
            Allowed values for this property are: "NO_DECRYPT", "DECRYPT"
        :type action: str

        :param decryption_profile:
            The value to assign to the decryption_profile property of this UpdateDecryptionRuleDetails.
        :type decryption_profile: str

        :param secret:
            The value to assign to the secret property of this UpdateDecryptionRuleDetails.
        :type secret: str

        :param position:
            The value to assign to the position property of this UpdateDecryptionRuleDetails.
        :type position: oci.network_firewall.models.RulePosition

        """
        self.swagger_types = {
            'condition': 'DecryptionRuleMatchCriteria',
            'action': 'str',
            'decryption_profile': 'str',
            'secret': 'str',
            'position': 'RulePosition'
        }

        self.attribute_map = {
            'condition': 'condition',
            'action': 'action',
            'decryption_profile': 'decryptionProfile',
            'secret': 'secret',
            'position': 'position'
        }

        self._condition = None
        self._action = None
        self._decryption_profile = None
        self._secret = None
        self._position = None

    @property
    def condition(self):
        """
        **[Required]** Gets the condition of this UpdateDecryptionRuleDetails.

        :return: The condition of this UpdateDecryptionRuleDetails.
        :rtype: oci.network_firewall.models.DecryptionRuleMatchCriteria
        """
        return self._condition

    @condition.setter
    def condition(self, condition):
        """
        Sets the condition of this UpdateDecryptionRuleDetails.

        :param condition: The condition of this UpdateDecryptionRuleDetails.
        :type: oci.network_firewall.models.DecryptionRuleMatchCriteria
        """
        self._condition = condition

    @property
    def action(self):
        """
        **[Required]** Gets the action of this UpdateDecryptionRuleDetails.
        Action:

        * NO_DECRYPT - Matching traffic is not decrypted.
        * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.

        Allowed values for this property are: "NO_DECRYPT", "DECRYPT"


        :return: The action of this UpdateDecryptionRuleDetails.
        :rtype: str
        """
        return self._action

    @action.setter
    def action(self, action):
        """
        Sets the action of this UpdateDecryptionRuleDetails.
        Action:

        * NO_DECRYPT - Matching traffic is not decrypted.
        * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.


        :param action: The action of this UpdateDecryptionRuleDetails.
        :type: str
        """
        allowed_values = ["NO_DECRYPT", "DECRYPT"]
        if not value_allowed_none_or_none_sentinel(action, allowed_values):
            raise ValueError(
                f"Invalid value for `action`, must be None or one of {allowed_values}"
            )
        self._action = action

    @property
    def decryption_profile(self):
        """
        Gets the decryption_profile of this UpdateDecryptionRuleDetails.
        The name of the decryption profile to use.


        :return: The decryption_profile of this UpdateDecryptionRuleDetails.
        :rtype: str
        """
        return self._decryption_profile

    @decryption_profile.setter
    def decryption_profile(self, decryption_profile):
        """
        Sets the decryption_profile of this UpdateDecryptionRuleDetails.
        The name of the decryption profile to use.


        :param decryption_profile: The decryption_profile of this UpdateDecryptionRuleDetails.
        :type: str
        """
        self._decryption_profile = decryption_profile

    @property
    def secret(self):
        """
        Gets the secret of this UpdateDecryptionRuleDetails.
        The name of a mapped secret. Its `type` must match that of the specified decryption profile.


        :return: The secret of this UpdateDecryptionRuleDetails.
        :rtype: str
        """
        return self._secret

    @secret.setter
    def secret(self, secret):
        """
        Sets the secret of this UpdateDecryptionRuleDetails.
        The name of a mapped secret. Its `type` must match that of the specified decryption profile.


        :param secret: The secret of this UpdateDecryptionRuleDetails.
        :type: str
        """
        self._secret = secret

    @property
    def position(self):
        """
        Gets the position of this UpdateDecryptionRuleDetails.

        :return: The position of this UpdateDecryptionRuleDetails.
        :rtype: oci.network_firewall.models.RulePosition
        """
        return self._position

    @position.setter
    def position(self, position):
        """
        Sets the position of this UpdateDecryptionRuleDetails.

        :param position: The position of this UpdateDecryptionRuleDetails.
        :type: oci.network_firewall.models.RulePosition
        """
        self._position = position

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
