# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20240430


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateScheduleDetails(object):
    """
    This is the data to update a schedule.
    """

    #: A constant which can be used with the action property of a UpdateScheduleDetails.
    #: This constant has a value of "START_RESOURCE"
    ACTION_START_RESOURCE = "START_RESOURCE"

    #: A constant which can be used with the action property of a UpdateScheduleDetails.
    #: This constant has a value of "STOP_RESOURCE"
    ACTION_STOP_RESOURCE = "STOP_RESOURCE"

    #: A constant which can be used with the recurrence_type property of a UpdateScheduleDetails.
    #: This constant has a value of "CRON"
    RECURRENCE_TYPE_CRON = "CRON"

    #: A constant which can be used with the recurrence_type property of a UpdateScheduleDetails.
    #: This constant has a value of "ICAL"
    RECURRENCE_TYPE_ICAL = "ICAL"

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateScheduleDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this UpdateScheduleDetails.
        :type display_name: str

        :param description:
            The value to assign to the description property of this UpdateScheduleDetails.
        :type description: str

        :param action:
            The value to assign to the action property of this UpdateScheduleDetails.
            Allowed values for this property are: "START_RESOURCE", "STOP_RESOURCE"
        :type action: str

        :param recurrence_details:
            The value to assign to the recurrence_details property of this UpdateScheduleDetails.
        :type recurrence_details: str

        :param recurrence_type:
            The value to assign to the recurrence_type property of this UpdateScheduleDetails.
            Allowed values for this property are: "CRON", "ICAL"
        :type recurrence_type: str

        :param resource_filters:
            The value to assign to the resource_filters property of this UpdateScheduleDetails.
        :type resource_filters: list[oci.resource_scheduler.models.ResourceFilter]

        :param resources:
            The value to assign to the resources property of this UpdateScheduleDetails.
        :type resources: list[oci.resource_scheduler.models.Resource]

        :param time_starts:
            The value to assign to the time_starts property of this UpdateScheduleDetails.
        :type time_starts: datetime

        :param time_ends:
            The value to assign to the time_ends property of this UpdateScheduleDetails.
        :type time_ends: datetime

        :param freeform_tags:
            The value to assign to the freeform_tags property of this UpdateScheduleDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this UpdateScheduleDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'display_name': 'str',
            'description': 'str',
            'action': 'str',
            'recurrence_details': 'str',
            'recurrence_type': 'str',
            'resource_filters': 'list[ResourceFilter]',
            'resources': 'list[Resource]',
            'time_starts': 'datetime',
            'time_ends': 'datetime',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'description': 'description',
            'action': 'action',
            'recurrence_details': 'recurrenceDetails',
            'recurrence_type': 'recurrenceType',
            'resource_filters': 'resourceFilters',
            'resources': 'resources',
            'time_starts': 'timeStarts',
            'time_ends': 'timeEnds',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._display_name = None
        self._description = None
        self._action = None
        self._recurrence_details = None
        self._recurrence_type = None
        self._resource_filters = None
        self._resources = None
        self._time_starts = None
        self._time_ends = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def display_name(self):
        """
        Gets the display_name of this UpdateScheduleDetails.
        This is a user-friendly name for the schedule. It does not have to be unique, and it's changeable.


        :return: The display_name of this UpdateScheduleDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this UpdateScheduleDetails.
        This is a user-friendly name for the schedule. It does not have to be unique, and it's changeable.


        :param display_name: The display_name of this UpdateScheduleDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this UpdateScheduleDetails.
        This is the description of the schedule.


        :return: The description of this UpdateScheduleDetails.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this UpdateScheduleDetails.
        This is the description of the schedule.


        :param description: The description of this UpdateScheduleDetails.
        :type: str
        """
        self._description = description

    @property
    def action(self):
        """
        Gets the action of this UpdateScheduleDetails.
        This is the action that will be executed by the schedule.

        Allowed values for this property are: "START_RESOURCE", "STOP_RESOURCE"


        :return: The action of this UpdateScheduleDetails.
        :rtype: str
        """
        return self._action

    @action.setter
    def action(self, action):
        """
        Sets the action of this UpdateScheduleDetails.
        This is the action that will be executed by the schedule.


        :param action: The action of this UpdateScheduleDetails.
        :type: str
        """
        allowed_values = ["START_RESOURCE", "STOP_RESOURCE"]
        if not value_allowed_none_or_none_sentinel(action, allowed_values):
            raise ValueError(
                f"Invalid value for `action`, must be None or one of {allowed_values}"
            )
        self._action = action

    @property
    def recurrence_details(self):
        """
        Gets the recurrence_details of this UpdateScheduleDetails.
        This is the frequency of recurrence of a schedule. The frequency field can either conform to RFC-5545 formatting
        or UNIX cron formatting for recurrences, based on the value specified by the recurrenceType field.


        :return: The recurrence_details of this UpdateScheduleDetails.
        :rtype: str
        """
        return self._recurrence_details

    @recurrence_details.setter
    def recurrence_details(self, recurrence_details):
        """
        Sets the recurrence_details of this UpdateScheduleDetails.
        This is the frequency of recurrence of a schedule. The frequency field can either conform to RFC-5545 formatting
        or UNIX cron formatting for recurrences, based on the value specified by the recurrenceType field.


        :param recurrence_details: The recurrence_details of this UpdateScheduleDetails.
        :type: str
        """
        self._recurrence_details = recurrence_details

    @property
    def recurrence_type(self):
        """
        Gets the recurrence_type of this UpdateScheduleDetails.
        Type of recurrence of a schedule

        Allowed values for this property are: "CRON", "ICAL"


        :return: The recurrence_type of this UpdateScheduleDetails.
        :rtype: str
        """
        return self._recurrence_type

    @recurrence_type.setter
    def recurrence_type(self, recurrence_type):
        """
        Sets the recurrence_type of this UpdateScheduleDetails.
        Type of recurrence of a schedule


        :param recurrence_type: The recurrence_type of this UpdateScheduleDetails.
        :type: str
        """
        allowed_values = ["CRON", "ICAL"]
        if not value_allowed_none_or_none_sentinel(recurrence_type, allowed_values):
            raise ValueError(
                f"Invalid value for `recurrence_type`, must be None or one of {allowed_values}"
            )
        self._recurrence_type = recurrence_type

    @property
    def resource_filters(self):
        """
        Gets the resource_filters of this UpdateScheduleDetails.
        This is a list of resources filters.  The schedule will be applied to resources matching all of them.


        :return: The resource_filters of this UpdateScheduleDetails.
        :rtype: list[oci.resource_scheduler.models.ResourceFilter]
        """
        return self._resource_filters

    @resource_filters.setter
    def resource_filters(self, resource_filters):
        """
        Sets the resource_filters of this UpdateScheduleDetails.
        This is a list of resources filters.  The schedule will be applied to resources matching all of them.


        :param resource_filters: The resource_filters of this UpdateScheduleDetails.
        :type: list[oci.resource_scheduler.models.ResourceFilter]
        """
        self._resource_filters = resource_filters

    @property
    def resources(self):
        """
        Gets the resources of this UpdateScheduleDetails.
        This is the list of resources to which the scheduled operation is applied.


        :return: The resources of this UpdateScheduleDetails.
        :rtype: list[oci.resource_scheduler.models.Resource]
        """
        return self._resources

    @resources.setter
    def resources(self, resources):
        """
        Sets the resources of this UpdateScheduleDetails.
        This is the list of resources to which the scheduled operation is applied.


        :param resources: The resources of this UpdateScheduleDetails.
        :type: list[oci.resource_scheduler.models.Resource]
        """
        self._resources = resources

    @property
    def time_starts(self):
        """
        Gets the time_starts of this UpdateScheduleDetails.
        This is the date and time the schedule starts, in the format defined by `RFC 3339`__

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_starts of this UpdateScheduleDetails.
        :rtype: datetime
        """
        return self._time_starts

    @time_starts.setter
    def time_starts(self, time_starts):
        """
        Sets the time_starts of this UpdateScheduleDetails.
        This is the date and time the schedule starts, in the format defined by `RFC 3339`__

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_starts: The time_starts of this UpdateScheduleDetails.
        :type: datetime
        """
        self._time_starts = time_starts

    @property
    def time_ends(self):
        """
        Gets the time_ends of this UpdateScheduleDetails.
        This is the date and time the schedule ends, in the format defined by `RFC 3339`__

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_ends of this UpdateScheduleDetails.
        :rtype: datetime
        """
        return self._time_ends

    @time_ends.setter
    def time_ends(self, time_ends):
        """
        Sets the time_ends of this UpdateScheduleDetails.
        This is the date and time the schedule ends, in the format defined by `RFC 3339`__

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_ends: The time_ends of this UpdateScheduleDetails.
        :type: datetime
        """
        self._time_ends = time_ends

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this UpdateScheduleDetails.
        These are free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this UpdateScheduleDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this UpdateScheduleDetails.
        These are free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this UpdateScheduleDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this UpdateScheduleDetails.
        These are defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this UpdateScheduleDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this UpdateScheduleDetails.
        These are defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this UpdateScheduleDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
