# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220618


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UpdateDesktopPoolDetails(object):
    """
    Provides the details of a request to update the desktop pool.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UpdateDesktopPoolDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this UpdateDesktopPoolDetails.
        :type display_name: str

        :param description:
            The value to assign to the description property of this UpdateDesktopPoolDetails.
        :type description: str

        :param maximum_size:
            The value to assign to the maximum_size property of this UpdateDesktopPoolDetails.
        :type maximum_size: int

        :param standby_size:
            The value to assign to the standby_size property of this UpdateDesktopPoolDetails.
        :type standby_size: int

        :param device_policy:
            The value to assign to the device_policy property of this UpdateDesktopPoolDetails.
        :type device_policy: oci.desktops.models.DesktopDevicePolicy

        :param availability_policy:
            The value to assign to the availability_policy property of this UpdateDesktopPoolDetails.
        :type availability_policy: oci.desktops.models.DesktopAvailabilityPolicy

        :param contact_details:
            The value to assign to the contact_details property of this UpdateDesktopPoolDetails.
        :type contact_details: str

        :param time_start_scheduled:
            The value to assign to the time_start_scheduled property of this UpdateDesktopPoolDetails.
        :type time_start_scheduled: datetime

        :param time_stop_scheduled:
            The value to assign to the time_stop_scheduled property of this UpdateDesktopPoolDetails.
        :type time_stop_scheduled: datetime

        :param freeform_tags:
            The value to assign to the freeform_tags property of this UpdateDesktopPoolDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this UpdateDesktopPoolDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param session_lifecycle_actions:
            The value to assign to the session_lifecycle_actions property of this UpdateDesktopPoolDetails.
        :type session_lifecycle_actions: oci.desktops.models.UpdateDesktopPoolDesktopSessionLifecycleActions

        """
        self.swagger_types = {
            'display_name': 'str',
            'description': 'str',
            'maximum_size': 'int',
            'standby_size': 'int',
            'device_policy': 'DesktopDevicePolicy',
            'availability_policy': 'DesktopAvailabilityPolicy',
            'contact_details': 'str',
            'time_start_scheduled': 'datetime',
            'time_stop_scheduled': 'datetime',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'session_lifecycle_actions': 'UpdateDesktopPoolDesktopSessionLifecycleActions'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'description': 'description',
            'maximum_size': 'maximumSize',
            'standby_size': 'standbySize',
            'device_policy': 'devicePolicy',
            'availability_policy': 'availabilityPolicy',
            'contact_details': 'contactDetails',
            'time_start_scheduled': 'timeStartScheduled',
            'time_stop_scheduled': 'timeStopScheduled',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'session_lifecycle_actions': 'sessionLifecycleActions'
        }

        self._display_name = None
        self._description = None
        self._maximum_size = None
        self._standby_size = None
        self._device_policy = None
        self._availability_policy = None
        self._contact_details = None
        self._time_start_scheduled = None
        self._time_stop_scheduled = None
        self._freeform_tags = None
        self._defined_tags = None
        self._session_lifecycle_actions = None

    @property
    def display_name(self):
        """
        Gets the display_name of this UpdateDesktopPoolDetails.
        A user friendly display name. Avoid entering confidential information.


        :return: The display_name of this UpdateDesktopPoolDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this UpdateDesktopPoolDetails.
        A user friendly display name. Avoid entering confidential information.


        :param display_name: The display_name of this UpdateDesktopPoolDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this UpdateDesktopPoolDetails.
        A user friendly description providing additional information about the resource.
        Avoid entering confidential information.


        :return: The description of this UpdateDesktopPoolDetails.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this UpdateDesktopPoolDetails.
        A user friendly description providing additional information about the resource.
        Avoid entering confidential information.


        :param description: The description of this UpdateDesktopPoolDetails.
        :type: str
        """
        self._description = description

    @property
    def maximum_size(self):
        """
        Gets the maximum_size of this UpdateDesktopPoolDetails.
        The maximum number of desktops permitted in the desktop pool.


        :return: The maximum_size of this UpdateDesktopPoolDetails.
        :rtype: int
        """
        return self._maximum_size

    @maximum_size.setter
    def maximum_size(self, maximum_size):
        """
        Sets the maximum_size of this UpdateDesktopPoolDetails.
        The maximum number of desktops permitted in the desktop pool.


        :param maximum_size: The maximum_size of this UpdateDesktopPoolDetails.
        :type: int
        """
        self._maximum_size = maximum_size

    @property
    def standby_size(self):
        """
        Gets the standby_size of this UpdateDesktopPoolDetails.
        The maximum number of standby desktops available in the desktop pool.


        :return: The standby_size of this UpdateDesktopPoolDetails.
        :rtype: int
        """
        return self._standby_size

    @standby_size.setter
    def standby_size(self, standby_size):
        """
        Sets the standby_size of this UpdateDesktopPoolDetails.
        The maximum number of standby desktops available in the desktop pool.


        :param standby_size: The standby_size of this UpdateDesktopPoolDetails.
        :type: int
        """
        self._standby_size = standby_size

    @property
    def device_policy(self):
        """
        Gets the device_policy of this UpdateDesktopPoolDetails.

        :return: The device_policy of this UpdateDesktopPoolDetails.
        :rtype: oci.desktops.models.DesktopDevicePolicy
        """
        return self._device_policy

    @device_policy.setter
    def device_policy(self, device_policy):
        """
        Sets the device_policy of this UpdateDesktopPoolDetails.

        :param device_policy: The device_policy of this UpdateDesktopPoolDetails.
        :type: oci.desktops.models.DesktopDevicePolicy
        """
        self._device_policy = device_policy

    @property
    def availability_policy(self):
        """
        Gets the availability_policy of this UpdateDesktopPoolDetails.

        :return: The availability_policy of this UpdateDesktopPoolDetails.
        :rtype: oci.desktops.models.DesktopAvailabilityPolicy
        """
        return self._availability_policy

    @availability_policy.setter
    def availability_policy(self, availability_policy):
        """
        Sets the availability_policy of this UpdateDesktopPoolDetails.

        :param availability_policy: The availability_policy of this UpdateDesktopPoolDetails.
        :type: oci.desktops.models.DesktopAvailabilityPolicy
        """
        self._availability_policy = availability_policy

    @property
    def contact_details(self):
        """
        Gets the contact_details of this UpdateDesktopPoolDetails.
        Contact information of the desktop pool administrator.
        Avoid entering confidential information.


        :return: The contact_details of this UpdateDesktopPoolDetails.
        :rtype: str
        """
        return self._contact_details

    @contact_details.setter
    def contact_details(self, contact_details):
        """
        Sets the contact_details of this UpdateDesktopPoolDetails.
        Contact information of the desktop pool administrator.
        Avoid entering confidential information.


        :param contact_details: The contact_details of this UpdateDesktopPoolDetails.
        :type: str
        """
        self._contact_details = contact_details

    @property
    def time_start_scheduled(self):
        """
        Gets the time_start_scheduled of this UpdateDesktopPoolDetails.
        The start time of the desktop pool.


        :return: The time_start_scheduled of this UpdateDesktopPoolDetails.
        :rtype: datetime
        """
        return self._time_start_scheduled

    @time_start_scheduled.setter
    def time_start_scheduled(self, time_start_scheduled):
        """
        Sets the time_start_scheduled of this UpdateDesktopPoolDetails.
        The start time of the desktop pool.


        :param time_start_scheduled: The time_start_scheduled of this UpdateDesktopPoolDetails.
        :type: datetime
        """
        self._time_start_scheduled = time_start_scheduled

    @property
    def time_stop_scheduled(self):
        """
        Gets the time_stop_scheduled of this UpdateDesktopPoolDetails.
        The stop time of the desktop pool.


        :return: The time_stop_scheduled of this UpdateDesktopPoolDetails.
        :rtype: datetime
        """
        return self._time_stop_scheduled

    @time_stop_scheduled.setter
    def time_stop_scheduled(self, time_stop_scheduled):
        """
        Sets the time_stop_scheduled of this UpdateDesktopPoolDetails.
        The stop time of the desktop pool.


        :param time_stop_scheduled: The time_stop_scheduled of this UpdateDesktopPoolDetails.
        :type: datetime
        """
        self._time_stop_scheduled = time_stop_scheduled

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this UpdateDesktopPoolDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this UpdateDesktopPoolDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this UpdateDesktopPoolDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this UpdateDesktopPoolDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this UpdateDesktopPoolDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this UpdateDesktopPoolDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this UpdateDesktopPoolDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this UpdateDesktopPoolDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def session_lifecycle_actions(self):
        """
        Gets the session_lifecycle_actions of this UpdateDesktopPoolDetails.

        :return: The session_lifecycle_actions of this UpdateDesktopPoolDetails.
        :rtype: oci.desktops.models.UpdateDesktopPoolDesktopSessionLifecycleActions
        """
        return self._session_lifecycle_actions

    @session_lifecycle_actions.setter
    def session_lifecycle_actions(self, session_lifecycle_actions):
        """
        Sets the session_lifecycle_actions of this UpdateDesktopPoolDetails.

        :param session_lifecycle_actions: The session_lifecycle_actions of this UpdateDesktopPoolDetails.
        :type: oci.desktops.models.UpdateDesktopPoolDesktopSessionLifecycleActions
        """
        self._session_lifecycle_actions = session_lifecycle_actions

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
