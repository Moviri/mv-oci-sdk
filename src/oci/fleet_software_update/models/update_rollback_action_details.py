# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220528

from .update_fsu_action_details import UpdateFsuActionDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateRollbackActionDetails(UpdateFsuActionDetails):
    """
    Rollback Exadata Fleet Update Action update details.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateRollbackActionDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.fleet_software_update.models.UpdateRollbackActionDetails.type` attribute
        of this class is ``ROLLBACK_AND_REMOVE_TARGET`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param type:
            The value to assign to the type property of this UpdateRollbackActionDetails.
            Allowed values for this property are: "STAGE", "PRECHECK", "APPLY", "ROLLBACK_AND_REMOVE_TARGET", "CLEANUP", "ROLLBACK_MAINTENANCE_CYCLE"
        :type type: str

        :param display_name:
            The value to assign to the display_name property of this UpdateRollbackActionDetails.
        :type display_name: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this UpdateRollbackActionDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this UpdateRollbackActionDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param schedule_details:
            The value to assign to the schedule_details property of this UpdateRollbackActionDetails.
        :type schedule_details: oci.fleet_software_update.models.UpdateScheduleDetails

        """
        self.swagger_types = {
            'type': 'str',
            'display_name': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'schedule_details': 'UpdateScheduleDetails'
        }

        self.attribute_map = {
            'type': 'type',
            'display_name': 'displayName',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'schedule_details': 'scheduleDetails'
        }

        self._type = None
        self._display_name = None
        self._freeform_tags = None
        self._defined_tags = None
        self._schedule_details = None
        self._type = 'ROLLBACK_AND_REMOVE_TARGET'

    @property
    def schedule_details(self):
        """
        Gets the schedule_details of this UpdateRollbackActionDetails.

        :return: The schedule_details of this UpdateRollbackActionDetails.
        :rtype: oci.fleet_software_update.models.UpdateScheduleDetails
        """
        return self._schedule_details

    @schedule_details.setter
    def schedule_details(self, schedule_details):
        """
        Sets the schedule_details of this UpdateRollbackActionDetails.

        :param schedule_details: The schedule_details of this UpdateRollbackActionDetails.
        :type: oci.fleet_software_update.models.UpdateScheduleDetails
        """
        self._schedule_details = schedule_details

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
