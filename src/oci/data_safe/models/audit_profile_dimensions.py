# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181201


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AuditProfileDimensions(object):
    """
    Details of aggregation dimensions used for summarizing audit profiles.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new AuditProfileDimensions object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param is_paid_usage_enabled:
            The value to assign to the is_paid_usage_enabled property of this AuditProfileDimensions.
        :type is_paid_usage_enabled: bool

        """
        self.swagger_types = {
            'is_paid_usage_enabled': 'bool'
        }

        self.attribute_map = {
            'is_paid_usage_enabled': 'isPaidUsageEnabled'
        }

        self._is_paid_usage_enabled = None

    @property
    def is_paid_usage_enabled(self):
        """
        Gets the is_paid_usage_enabled of this AuditProfileDimensions.
        Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database,
        potentially incurring additional charges. The default value is inherited from the global settings.
        You can change at the global level or at the target level.


        :return: The is_paid_usage_enabled of this AuditProfileDimensions.
        :rtype: bool
        """
        return self._is_paid_usage_enabled

    @is_paid_usage_enabled.setter
    def is_paid_usage_enabled(self, is_paid_usage_enabled):
        """
        Sets the is_paid_usage_enabled of this AuditProfileDimensions.
        Indicates if you want to continue collecting audit records beyond the free limit of one million audit records per month per target database,
        potentially incurring additional charges. The default value is inherited from the global settings.
        You can change at the global level or at the target level.


        :param is_paid_usage_enabled: The is_paid_usage_enabled of this AuditProfileDimensions.
        :type: bool
        """
        self._is_paid_usage_enabled = is_paid_usage_enabled

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
