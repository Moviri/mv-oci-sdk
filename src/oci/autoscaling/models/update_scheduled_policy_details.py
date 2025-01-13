# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181001

from .update_auto_scaling_policy_details import UpdateAutoScalingPolicyDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateScheduledPolicyDetails(UpdateAutoScalingPolicyDetails):
    """
    UpdateScheduledPolicyDetails model.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateScheduledPolicyDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.autoscaling.models.UpdateScheduledPolicyDetails.policy_type` attribute
        of this class is ``scheduled`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this UpdateScheduledPolicyDetails.
        :type display_name: str

        :param capacity:
            The value to assign to the capacity property of this UpdateScheduledPolicyDetails.
        :type capacity: oci.autoscaling.models.Capacity

        :param policy_type:
            The value to assign to the policy_type property of this UpdateScheduledPolicyDetails.
        :type policy_type: str

        :param is_enabled:
            The value to assign to the is_enabled property of this UpdateScheduledPolicyDetails.
        :type is_enabled: bool

        :param execution_schedule:
            The value to assign to the execution_schedule property of this UpdateScheduledPolicyDetails.
        :type execution_schedule: oci.autoscaling.models.ExecutionSchedule

        :param resource_action:
            The value to assign to the resource_action property of this UpdateScheduledPolicyDetails.
        :type resource_action: oci.autoscaling.models.ResourceAction

        """
        self.swagger_types = {
            'display_name': 'str',
            'capacity': 'Capacity',
            'policy_type': 'str',
            'is_enabled': 'bool',
            'execution_schedule': 'ExecutionSchedule',
            'resource_action': 'ResourceAction'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'capacity': 'capacity',
            'policy_type': 'policyType',
            'is_enabled': 'isEnabled',
            'execution_schedule': 'executionSchedule',
            'resource_action': 'resourceAction'
        }

        self._display_name = None
        self._capacity = None
        self._policy_type = None
        self._is_enabled = None
        self._execution_schedule = None
        self._resource_action = None
        self._policy_type = 'scheduled'

    @property
    def execution_schedule(self):
        """
        Gets the execution_schedule of this UpdateScheduledPolicyDetails.
        The schedule for executing the autoscaling policy.


        :return: The execution_schedule of this UpdateScheduledPolicyDetails.
        :rtype: oci.autoscaling.models.ExecutionSchedule
        """
        return self._execution_schedule

    @execution_schedule.setter
    def execution_schedule(self, execution_schedule):
        """
        Sets the execution_schedule of this UpdateScheduledPolicyDetails.
        The schedule for executing the autoscaling policy.


        :param execution_schedule: The execution_schedule of this UpdateScheduledPolicyDetails.
        :type: oci.autoscaling.models.ExecutionSchedule
        """
        self._execution_schedule = execution_schedule

    @property
    def resource_action(self):
        """
        Gets the resource_action of this UpdateScheduledPolicyDetails.

        :return: The resource_action of this UpdateScheduledPolicyDetails.
        :rtype: oci.autoscaling.models.ResourceAction
        """
        return self._resource_action

    @resource_action.setter
    def resource_action(self, resource_action):
        """
        Sets the resource_action of this UpdateScheduledPolicyDetails.

        :param resource_action: The resource_action of this UpdateScheduledPolicyDetails.
        :type: oci.autoscaling.models.ResourceAction
        """
        self._resource_action = resource_action

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
