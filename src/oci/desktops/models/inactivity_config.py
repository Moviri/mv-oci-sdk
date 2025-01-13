# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220618


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class InactivityConfig(object):
    """
    Action and grace period for inactivity
    """

    #: A constant which can be used with the action property of a InactivityConfig.
    #: This constant has a value of "NONE"
    ACTION_NONE = "NONE"

    #: A constant which can be used with the action property of a InactivityConfig.
    #: This constant has a value of "DISCONNECT"
    ACTION_DISCONNECT = "DISCONNECT"

    def __init__(self, **kwargs):
        """
        Initializes a new InactivityConfig object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param action:
            The value to assign to the action property of this InactivityConfig.
            Allowed values for this property are: "NONE", "DISCONNECT", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type action: str

        :param grace_period_in_minutes:
            The value to assign to the grace_period_in_minutes property of this InactivityConfig.
        :type grace_period_in_minutes: int

        """
        self.swagger_types = {
            'action': 'str',
            'grace_period_in_minutes': 'int'
        }

        self.attribute_map = {
            'action': 'action',
            'grace_period_in_minutes': 'gracePeriodInMinutes'
        }

        self._action = None
        self._grace_period_in_minutes = None

    @property
    def action(self):
        """
        **[Required]** Gets the action of this InactivityConfig.
        an inactivity action to be triggered

        Allowed values for this property are: "NONE", "DISCONNECT", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The action of this InactivityConfig.
        :rtype: str
        """
        return self._action

    @action.setter
    def action(self, action):
        """
        Sets the action of this InactivityConfig.
        an inactivity action to be triggered


        :param action: The action of this InactivityConfig.
        :type: str
        """
        allowed_values = ["NONE", "DISCONNECT"]
        if not value_allowed_none_or_none_sentinel(action, allowed_values):
            action = 'UNKNOWN_ENUM_VALUE'
        self._action = action

    @property
    def grace_period_in_minutes(self):
        """
        Gets the grace_period_in_minutes of this InactivityConfig.
        The period of time (in minutes) during which the session must remain inactive before any action occurs.
        If the value is not provided, a default value is used.


        :return: The grace_period_in_minutes of this InactivityConfig.
        :rtype: int
        """
        return self._grace_period_in_minutes

    @grace_period_in_minutes.setter
    def grace_period_in_minutes(self, grace_period_in_minutes):
        """
        Sets the grace_period_in_minutes of this InactivityConfig.
        The period of time (in minutes) during which the session must remain inactive before any action occurs.
        If the value is not provided, a default value is used.


        :param grace_period_in_minutes: The grace_period_in_minutes of this InactivityConfig.
        :type: int
        """
        self._grace_period_in_minutes = grace_period_in_minutes

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
