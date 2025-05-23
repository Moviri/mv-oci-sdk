# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ComputeCapacityReservation(object):
    """
    A template that defines the settings to use when creating compute capacity reservations.
    """

    #: A constant which can be used with the lifecycle_state property of a ComputeCapacityReservation.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a ComputeCapacityReservation.
    #: This constant has a value of "CREATING"
    LIFECYCLE_STATE_CREATING = "CREATING"

    #: A constant which can be used with the lifecycle_state property of a ComputeCapacityReservation.
    #: This constant has a value of "UPDATING"
    LIFECYCLE_STATE_UPDATING = "UPDATING"

    #: A constant which can be used with the lifecycle_state property of a ComputeCapacityReservation.
    #: This constant has a value of "MOVING"
    LIFECYCLE_STATE_MOVING = "MOVING"

    #: A constant which can be used with the lifecycle_state property of a ComputeCapacityReservation.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the lifecycle_state property of a ComputeCapacityReservation.
    #: This constant has a value of "DELETING"
    LIFECYCLE_STATE_DELETING = "DELETING"

    def __init__(self, **kwargs):
        """
        Initializes a new ComputeCapacityReservation object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param availability_domain:
            The value to assign to the availability_domain property of this ComputeCapacityReservation.
        :type availability_domain: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ComputeCapacityReservation.
        :type compartment_id: str

        :param defined_tags:
            The value to assign to the defined_tags property of this ComputeCapacityReservation.
        :type defined_tags: dict(str, dict(str, object))

        :param display_name:
            The value to assign to the display_name property of this ComputeCapacityReservation.
        :type display_name: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this ComputeCapacityReservation.
        :type freeform_tags: dict(str, str)

        :param id:
            The value to assign to the id property of this ComputeCapacityReservation.
        :type id: str

        :param is_default_reservation:
            The value to assign to the is_default_reservation property of this ComputeCapacityReservation.
        :type is_default_reservation: bool

        :param instance_reservation_configs:
            The value to assign to the instance_reservation_configs property of this ComputeCapacityReservation.
        :type instance_reservation_configs: list[oci.core.models.InstanceReservationConfig]

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ComputeCapacityReservation.
            Allowed values for this property are: "ACTIVE", "CREATING", "UPDATING", "MOVING", "DELETED", "DELETING", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param reserved_instance_count:
            The value to assign to the reserved_instance_count property of this ComputeCapacityReservation.
        :type reserved_instance_count: int

        :param time_updated:
            The value to assign to the time_updated property of this ComputeCapacityReservation.
        :type time_updated: datetime

        :param time_created:
            The value to assign to the time_created property of this ComputeCapacityReservation.
        :type time_created: datetime

        :param used_instance_count:
            The value to assign to the used_instance_count property of this ComputeCapacityReservation.
        :type used_instance_count: int

        """
        self.swagger_types = {
            'availability_domain': 'str',
            'compartment_id': 'str',
            'defined_tags': 'dict(str, dict(str, object))',
            'display_name': 'str',
            'freeform_tags': 'dict(str, str)',
            'id': 'str',
            'is_default_reservation': 'bool',
            'instance_reservation_configs': 'list[InstanceReservationConfig]',
            'lifecycle_state': 'str',
            'reserved_instance_count': 'int',
            'time_updated': 'datetime',
            'time_created': 'datetime',
            'used_instance_count': 'int'
        }

        self.attribute_map = {
            'availability_domain': 'availabilityDomain',
            'compartment_id': 'compartmentId',
            'defined_tags': 'definedTags',
            'display_name': 'displayName',
            'freeform_tags': 'freeformTags',
            'id': 'id',
            'is_default_reservation': 'isDefaultReservation',
            'instance_reservation_configs': 'instanceReservationConfigs',
            'lifecycle_state': 'lifecycleState',
            'reserved_instance_count': 'reservedInstanceCount',
            'time_updated': 'timeUpdated',
            'time_created': 'timeCreated',
            'used_instance_count': 'usedInstanceCount'
        }

        self._availability_domain = None
        self._compartment_id = None
        self._defined_tags = None
        self._display_name = None
        self._freeform_tags = None
        self._id = None
        self._is_default_reservation = None
        self._instance_reservation_configs = None
        self._lifecycle_state = None
        self._reserved_instance_count = None
        self._time_updated = None
        self._time_created = None
        self._used_instance_count = None

    @property
    def availability_domain(self):
        """
        **[Required]** Gets the availability_domain of this ComputeCapacityReservation.
        The availability domain of the compute capacity reservation.

        Example: `Uocm:PHX-AD-1`


        :return: The availability_domain of this ComputeCapacityReservation.
        :rtype: str
        """
        return self._availability_domain

    @availability_domain.setter
    def availability_domain(self, availability_domain):
        """
        Sets the availability_domain of this ComputeCapacityReservation.
        The availability domain of the compute capacity reservation.

        Example: `Uocm:PHX-AD-1`


        :param availability_domain: The availability_domain of this ComputeCapacityReservation.
        :type: str
        """
        self._availability_domain = availability_domain

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ComputeCapacityReservation.
        The `OCID`__ of the compartment
        containing the compute capacity reservation.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this ComputeCapacityReservation.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ComputeCapacityReservation.
        The `OCID`__ of the compartment
        containing the compute capacity reservation.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this ComputeCapacityReservation.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this ComputeCapacityReservation.
        Defined tags for this resource. Each key is predefined and scoped to a
        namespace. For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this ComputeCapacityReservation.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this ComputeCapacityReservation.
        Defined tags for this resource. Each key is predefined and scoped to a
        namespace. For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this ComputeCapacityReservation.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def display_name(self):
        """
        Gets the display_name of this ComputeCapacityReservation.
        A user-friendly name. Does not have to be unique, and it's changeable.
        Avoid entering confidential information.


        :return: The display_name of this ComputeCapacityReservation.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ComputeCapacityReservation.
        A user-friendly name. Does not have to be unique, and it's changeable.
        Avoid entering confidential information.


        :param display_name: The display_name of this ComputeCapacityReservation.
        :type: str
        """
        self._display_name = display_name

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this ComputeCapacityReservation.
        Free-form tags for this resource. Each tag is a simple key-value pair with no
        predefined name, type, or namespace. For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this ComputeCapacityReservation.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this ComputeCapacityReservation.
        Free-form tags for this resource. Each tag is a simple key-value pair with no
        predefined name, type, or namespace. For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this ComputeCapacityReservation.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ComputeCapacityReservation.
        The `OCID`__ of the compute capacity reservation.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The id of this ComputeCapacityReservation.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ComputeCapacityReservation.
        The `OCID`__ of the compute capacity reservation.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param id: The id of this ComputeCapacityReservation.
        :type: str
        """
        self._id = id

    @property
    def is_default_reservation(self):
        """
        Gets the is_default_reservation of this ComputeCapacityReservation.
        Whether this capacity reservation is the default.
        For more information, see `Capacity Reservations`__.

        __ https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default


        :return: The is_default_reservation of this ComputeCapacityReservation.
        :rtype: bool
        """
        return self._is_default_reservation

    @is_default_reservation.setter
    def is_default_reservation(self, is_default_reservation):
        """
        Sets the is_default_reservation of this ComputeCapacityReservation.
        Whether this capacity reservation is the default.
        For more information, see `Capacity Reservations`__.

        __ https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default


        :param is_default_reservation: The is_default_reservation of this ComputeCapacityReservation.
        :type: bool
        """
        self._is_default_reservation = is_default_reservation

    @property
    def instance_reservation_configs(self):
        """
        Gets the instance_reservation_configs of this ComputeCapacityReservation.
        The capacity configurations for the capacity reservation.

        To use the reservation for the desired shape, specify the shape, count, and
        optionally the fault domain where you want this configuration.


        :return: The instance_reservation_configs of this ComputeCapacityReservation.
        :rtype: list[oci.core.models.InstanceReservationConfig]
        """
        return self._instance_reservation_configs

    @instance_reservation_configs.setter
    def instance_reservation_configs(self, instance_reservation_configs):
        """
        Sets the instance_reservation_configs of this ComputeCapacityReservation.
        The capacity configurations for the capacity reservation.

        To use the reservation for the desired shape, specify the shape, count, and
        optionally the fault domain where you want this configuration.


        :param instance_reservation_configs: The instance_reservation_configs of this ComputeCapacityReservation.
        :type: list[oci.core.models.InstanceReservationConfig]
        """
        self._instance_reservation_configs = instance_reservation_configs

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this ComputeCapacityReservation.
        The current state of the compute capacity reservation.

        Allowed values for this property are: "ACTIVE", "CREATING", "UPDATING", "MOVING", "DELETED", "DELETING", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this ComputeCapacityReservation.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ComputeCapacityReservation.
        The current state of the compute capacity reservation.


        :param lifecycle_state: The lifecycle_state of this ComputeCapacityReservation.
        :type: str
        """
        allowed_values = ["ACTIVE", "CREATING", "UPDATING", "MOVING", "DELETED", "DELETING"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def reserved_instance_count(self):
        """
        Gets the reserved_instance_count of this ComputeCapacityReservation.
        The number of instances for which capacity will be held with this
        compute capacity reservation. This number is the sum of the values of the `reservedCount` fields
        for all of the instance capacity configurations under this reservation.
        The purpose of this field is to calculate the percentage usage of the reservation.


        :return: The reserved_instance_count of this ComputeCapacityReservation.
        :rtype: int
        """
        return self._reserved_instance_count

    @reserved_instance_count.setter
    def reserved_instance_count(self, reserved_instance_count):
        """
        Sets the reserved_instance_count of this ComputeCapacityReservation.
        The number of instances for which capacity will be held with this
        compute capacity reservation. This number is the sum of the values of the `reservedCount` fields
        for all of the instance capacity configurations under this reservation.
        The purpose of this field is to calculate the percentage usage of the reservation.


        :param reserved_instance_count: The reserved_instance_count of this ComputeCapacityReservation.
        :type: int
        """
        self._reserved_instance_count = reserved_instance_count

    @property
    def time_updated(self):
        """
        Gets the time_updated of this ComputeCapacityReservation.
        The date and time the compute capacity reservation was updated, in the format defined by `RFC3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_updated of this ComputeCapacityReservation.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this ComputeCapacityReservation.
        The date and time the compute capacity reservation was updated, in the format defined by `RFC3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_updated: The time_updated of this ComputeCapacityReservation.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this ComputeCapacityReservation.
        The date and time the compute capacity reservation was created, in the format defined by `RFC3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_created of this ComputeCapacityReservation.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ComputeCapacityReservation.
        The date and time the compute capacity reservation was created, in the format defined by `RFC3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_created: The time_created of this ComputeCapacityReservation.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def used_instance_count(self):
        """
        Gets the used_instance_count of this ComputeCapacityReservation.
        The total number of instances currently consuming space in
        this compute capacity reservation. This number is the sum of the values of the `usedCount` fields
        for all of the instance capacity configurations under this reservation.
        The purpose of this field is to calculate the percentage usage of the reservation.


        :return: The used_instance_count of this ComputeCapacityReservation.
        :rtype: int
        """
        return self._used_instance_count

    @used_instance_count.setter
    def used_instance_count(self, used_instance_count):
        """
        Sets the used_instance_count of this ComputeCapacityReservation.
        The total number of instances currently consuming space in
        this compute capacity reservation. This number is the sum of the values of the `usedCount` fields
        for all of the instance capacity configurations under this reservation.
        The purpose of this field is to calculate the percentage usage of the reservation.


        :param used_instance_count: The used_instance_count of this ComputeCapacityReservation.
        :type: int
        """
        self._used_instance_count = used_instance_count

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
