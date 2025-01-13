# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20231130


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DedicatedAiClusterSummary(object):
    """
    Summary information about a dedicated AI cluster.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DedicatedAiClusterSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this DedicatedAiClusterSummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this DedicatedAiClusterSummary.
        :type display_name: str

        :param description:
            The value to assign to the description property of this DedicatedAiClusterSummary.
        :type description: str

        :param type:
            The value to assign to the type property of this DedicatedAiClusterSummary.
        :type type: str

        :param compartment_id:
            The value to assign to the compartment_id property of this DedicatedAiClusterSummary.
        :type compartment_id: str

        :param time_created:
            The value to assign to the time_created property of this DedicatedAiClusterSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this DedicatedAiClusterSummary.
        :type time_updated: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this DedicatedAiClusterSummary.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this DedicatedAiClusterSummary.
        :type lifecycle_details: str

        :param unit_count:
            The value to assign to the unit_count property of this DedicatedAiClusterSummary.
        :type unit_count: int

        :param unit_shape:
            The value to assign to the unit_shape property of this DedicatedAiClusterSummary.
        :type unit_shape: str

        :param capacity:
            The value to assign to the capacity property of this DedicatedAiClusterSummary.
        :type capacity: oci.generative_ai.models.DedicatedAiClusterCapacity

        :param freeform_tags:
            The value to assign to the freeform_tags property of this DedicatedAiClusterSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this DedicatedAiClusterSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this DedicatedAiClusterSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'description': 'str',
            'type': 'str',
            'compartment_id': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'unit_count': 'int',
            'unit_shape': 'str',
            'capacity': 'DedicatedAiClusterCapacity',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName',
            'description': 'description',
            'type': 'type',
            'compartment_id': 'compartmentId',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'unit_count': 'unitCount',
            'unit_shape': 'unitShape',
            'capacity': 'capacity',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._display_name = None
        self._description = None
        self._type = None
        self._compartment_id = None
        self._time_created = None
        self._time_updated = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._unit_count = None
        self._unit_shape = None
        self._capacity = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this DedicatedAiClusterSummary.
        The `OCID`__ of the dedicated AI cluster.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The id of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this DedicatedAiClusterSummary.
        The `OCID`__ of the dedicated AI cluster.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param id: The id of this DedicatedAiClusterSummary.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        Gets the display_name of this DedicatedAiClusterSummary.
        A user-friendly name. Does not have to be unique, and it's changeable.


        :return: The display_name of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this DedicatedAiClusterSummary.
        A user-friendly name. Does not have to be unique, and it's changeable.


        :param display_name: The display_name of this DedicatedAiClusterSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this DedicatedAiClusterSummary.
        An optional description of the dedicated AI cluster.


        :return: The description of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this DedicatedAiClusterSummary.
        An optional description of the dedicated AI cluster.


        :param description: The description of this DedicatedAiClusterSummary.
        :type: str
        """
        self._description = description

    @property
    def type(self):
        """
        **[Required]** Gets the type of this DedicatedAiClusterSummary.
        The dedicated AI cluster type indicating whether this is a fine-tuning/training processor or hosting/inference processor.

        Allowed values are:
        - HOSTING
        - FINE_TUNING


        :return: The type of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """
        Sets the type of this DedicatedAiClusterSummary.
        The dedicated AI cluster type indicating whether this is a fine-tuning/training processor or hosting/inference processor.

        Allowed values are:
        - HOSTING
        - FINE_TUNING


        :param type: The type of this DedicatedAiClusterSummary.
        :type: str
        """
        self._type = type

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this DedicatedAiClusterSummary.
        The compartment OCID to create the dedicated AI cluster in.


        :return: The compartment_id of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this DedicatedAiClusterSummary.
        The compartment OCID to create the dedicated AI cluster in.


        :param compartment_id: The compartment_id of this DedicatedAiClusterSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this DedicatedAiClusterSummary.
        The date and time the dedicated AI cluster was created, in the format defined by RFC 3339.


        :return: The time_created of this DedicatedAiClusterSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this DedicatedAiClusterSummary.
        The date and time the dedicated AI cluster was created, in the format defined by RFC 3339.


        :param time_created: The time_created of this DedicatedAiClusterSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        Gets the time_updated of this DedicatedAiClusterSummary.
        The date and time the dedicated AI cluster was updated, in the format defined by RFC 3339.


        :return: The time_updated of this DedicatedAiClusterSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this DedicatedAiClusterSummary.
        The date and time the dedicated AI cluster was updated, in the format defined by RFC 3339.


        :param time_updated: The time_updated of this DedicatedAiClusterSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this DedicatedAiClusterSummary.
        The current state of the dedicated AI cluster.

        Allowed values are:
        - CREATING
        - ACTIVE
        - UPDATING
        - DELETING
        - DELETED
        - FAILED
        - NEEDS_ATTENTION


        :return: The lifecycle_state of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this DedicatedAiClusterSummary.
        The current state of the dedicated AI cluster.

        Allowed values are:
        - CREATING
        - ACTIVE
        - UPDATING
        - DELETING
        - DELETED
        - FAILED
        - NEEDS_ATTENTION


        :param lifecycle_state: The lifecycle_state of this DedicatedAiClusterSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this DedicatedAiClusterSummary.
        A message describing the current state of the dedicated AI cluster in more detail that can provide actionable information.


        :return: The lifecycle_details of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this DedicatedAiClusterSummary.
        A message describing the current state of the dedicated AI cluster in more detail that can provide actionable information.


        :param lifecycle_details: The lifecycle_details of this DedicatedAiClusterSummary.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def unit_count(self):
        """
        **[Required]** Gets the unit_count of this DedicatedAiClusterSummary.
        The number of dedicated units in this AI cluster.


        :return: The unit_count of this DedicatedAiClusterSummary.
        :rtype: int
        """
        return self._unit_count

    @unit_count.setter
    def unit_count(self, unit_count):
        """
        Sets the unit_count of this DedicatedAiClusterSummary.
        The number of dedicated units in this AI cluster.


        :param unit_count: The unit_count of this DedicatedAiClusterSummary.
        :type: int
        """
        self._unit_count = unit_count

    @property
    def unit_shape(self):
        """
        **[Required]** Gets the unit_shape of this DedicatedAiClusterSummary.
        The shape of dedicated unit in this AI cluster. The underlying hardware configuration is hidden from customers.


        :return: The unit_shape of this DedicatedAiClusterSummary.
        :rtype: str
        """
        return self._unit_shape

    @unit_shape.setter
    def unit_shape(self, unit_shape):
        """
        Sets the unit_shape of this DedicatedAiClusterSummary.
        The shape of dedicated unit in this AI cluster. The underlying hardware configuration is hidden from customers.


        :param unit_shape: The unit_shape of this DedicatedAiClusterSummary.
        :type: str
        """
        self._unit_shape = unit_shape

    @property
    def capacity(self):
        """
        Gets the capacity of this DedicatedAiClusterSummary.

        :return: The capacity of this DedicatedAiClusterSummary.
        :rtype: oci.generative_ai.models.DedicatedAiClusterCapacity
        """
        return self._capacity

    @capacity.setter
    def capacity(self, capacity):
        """
        Sets the capacity of this DedicatedAiClusterSummary.

        :param capacity: The capacity of this DedicatedAiClusterSummary.
        :type: oci.generative_ai.models.DedicatedAiClusterCapacity
        """
        self._capacity = capacity

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this DedicatedAiClusterSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this DedicatedAiClusterSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this DedicatedAiClusterSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this DedicatedAiClusterSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this DedicatedAiClusterSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this DedicatedAiClusterSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this DedicatedAiClusterSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this DedicatedAiClusterSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this DedicatedAiClusterSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this DedicatedAiClusterSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this DedicatedAiClusterSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this DedicatedAiClusterSummary.
        :type: dict(str, dict(str, object))
        """
        self._system_tags = system_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
