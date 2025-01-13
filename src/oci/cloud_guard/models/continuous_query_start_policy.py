# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200131


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ContinuousQueryStartPolicy(object):
    """
    Start policy for continuous query
    """

    #: A constant which can be used with the start_policy_type property of a ContinuousQueryStartPolicy.
    #: This constant has a value of "NO_DELAY_START_POLICY"
    START_POLICY_TYPE_NO_DELAY_START_POLICY = "NO_DELAY_START_POLICY"

    #: A constant which can be used with the start_policy_type property of a ContinuousQueryStartPolicy.
    #: This constant has a value of "ABSOLUTE_TIME_START_POLICY"
    START_POLICY_TYPE_ABSOLUTE_TIME_START_POLICY = "ABSOLUTE_TIME_START_POLICY"

    def __init__(self, **kwargs):
        """
        Initializes a new ContinuousQueryStartPolicy object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.cloud_guard.models.AbsoluteTimeStartPolicy`
        * :class:`~oci.cloud_guard.models.NoDelayStartPolicy`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param start_policy_type:
            The value to assign to the start_policy_type property of this ContinuousQueryStartPolicy.
            Allowed values for this property are: "NO_DELAY_START_POLICY", "ABSOLUTE_TIME_START_POLICY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type start_policy_type: str

        """
        self.swagger_types = {
            'start_policy_type': 'str'
        }

        self.attribute_map = {
            'start_policy_type': 'startPolicyType'
        }

        self._start_policy_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['startPolicyType']

        if type == 'ABSOLUTE_TIME_START_POLICY':
            return 'AbsoluteTimeStartPolicy'

        if type == 'NO_DELAY_START_POLICY':
            return 'NoDelayStartPolicy'
        else:
            return 'ContinuousQueryStartPolicy'

    @property
    def start_policy_type(self):
        """
        **[Required]** Gets the start_policy_type of this ContinuousQueryStartPolicy.
        Start policy delay timing

        Allowed values for this property are: "NO_DELAY_START_POLICY", "ABSOLUTE_TIME_START_POLICY", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The start_policy_type of this ContinuousQueryStartPolicy.
        :rtype: str
        """
        return self._start_policy_type

    @start_policy_type.setter
    def start_policy_type(self, start_policy_type):
        """
        Sets the start_policy_type of this ContinuousQueryStartPolicy.
        Start policy delay timing


        :param start_policy_type: The start_policy_type of this ContinuousQueryStartPolicy.
        :type: str
        """
        allowed_values = ["NO_DELAY_START_POLICY", "ABSOLUTE_TIME_START_POLICY"]
        if not value_allowed_none_or_none_sentinel(start_policy_type, allowed_values):
            start_policy_type = 'UNKNOWN_ENUM_VALUE'
        self._start_policy_type = start_policy_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
