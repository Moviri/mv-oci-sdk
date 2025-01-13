# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230831


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class FleetProperty(object):
    """
    Property to manage fleet metadata details in\u00A0Fleet Application Management.
    """

    #: A constant which can be used with the selection_type property of a FleetProperty.
    #: This constant has a value of "SINGLE_CHOICE"
    SELECTION_TYPE_SINGLE_CHOICE = "SINGLE_CHOICE"

    #: A constant which can be used with the selection_type property of a FleetProperty.
    #: This constant has a value of "MULTI_CHOICE"
    SELECTION_TYPE_MULTI_CHOICE = "MULTI_CHOICE"

    #: A constant which can be used with the selection_type property of a FleetProperty.
    #: This constant has a value of "DEFAULT_TEXT"
    SELECTION_TYPE_DEFAULT_TEXT = "DEFAULT_TEXT"

    #: A constant which can be used with the value_type property of a FleetProperty.
    #: This constant has a value of "STRING"
    VALUE_TYPE_STRING = "STRING"

    #: A constant which can be used with the value_type property of a FleetProperty.
    #: This constant has a value of "NUMERIC"
    VALUE_TYPE_NUMERIC = "NUMERIC"

    #: A constant which can be used with the lifecycle_state property of a FleetProperty.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a FleetProperty.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the lifecycle_state property of a FleetProperty.
    #: This constant has a value of "FAILED"
    LIFECYCLE_STATE_FAILED = "FAILED"

    def __init__(self, **kwargs):
        """
        Initializes a new FleetProperty object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this FleetProperty.
        :type id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this FleetProperty.
        :type compartment_id: str

        :param display_name:
            The value to assign to the display_name property of this FleetProperty.
        :type display_name: str

        :param time_created:
            The value to assign to the time_created property of this FleetProperty.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this FleetProperty.
        :type time_updated: datetime

        :param value:
            The value to assign to the value property of this FleetProperty.
        :type value: str

        :param property_id:
            The value to assign to the property_id property of this FleetProperty.
        :type property_id: str

        :param selection_type:
            The value to assign to the selection_type property of this FleetProperty.
            Allowed values for this property are: "SINGLE_CHOICE", "MULTI_CHOICE", "DEFAULT_TEXT", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type selection_type: str

        :param value_type:
            The value to assign to the value_type property of this FleetProperty.
            Allowed values for this property are: "STRING", "NUMERIC", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type value_type: str

        :param allowed_values:
            The value to assign to the allowed_values property of this FleetProperty.
        :type allowed_values: list[str]

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this FleetProperty.
            Allowed values for this property are: "ACTIVE", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param system_tags:
            The value to assign to the system_tags property of this FleetProperty.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'compartment_id': 'str',
            'display_name': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'value': 'str',
            'property_id': 'str',
            'selection_type': 'str',
            'value_type': 'str',
            'allowed_values': 'list[str]',
            'lifecycle_state': 'str',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'compartment_id': 'compartmentId',
            'display_name': 'displayName',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'value': 'value',
            'property_id': 'propertyId',
            'selection_type': 'selectionType',
            'value_type': 'valueType',
            'allowed_values': 'allowedValues',
            'lifecycle_state': 'lifecycleState',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._compartment_id = None
        self._display_name = None
        self._time_created = None
        self._time_updated = None
        self._value = None
        self._property_id = None
        self._selection_type = None
        self._value_type = None
        self._allowed_values = None
        self._lifecycle_state = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this FleetProperty.
        The unique id of the resource.


        :return: The id of this FleetProperty.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this FleetProperty.
        The unique id of the resource.


        :param id: The id of this FleetProperty.
        :type: str
        """
        self._id = id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this FleetProperty.
        Tenancy OCID


        :return: The compartment_id of this FleetProperty.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this FleetProperty.
        Tenancy OCID


        :param compartment_id: The compartment_id of this FleetProperty.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this FleetProperty.
        A user-friendly name. Does not have to be unique, and it's changeable.
        Avoid entering confidential information.

        Example: `My new resource`


        :return: The display_name of this FleetProperty.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this FleetProperty.
        A user-friendly name. Does not have to be unique, and it's changeable.
        Avoid entering confidential information.

        Example: `My new resource`


        :param display_name: The display_name of this FleetProperty.
        :type: str
        """
        self._display_name = display_name

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this FleetProperty.
        The time this resource was created. An RFC3339 formatted datetime string.


        :return: The time_created of this FleetProperty.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this FleetProperty.
        The time this resource was created. An RFC3339 formatted datetime string.


        :param time_created: The time_created of this FleetProperty.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        Gets the time_updated of this FleetProperty.
        The time this resource was last updated. An RFC3339 formatted datetime string.


        :return: The time_updated of this FleetProperty.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this FleetProperty.
        The time this resource was last updated. An RFC3339 formatted datetime string.


        :param time_updated: The time_updated of this FleetProperty.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def value(self):
        """
        Gets the value of this FleetProperty.
        Value of the Property.


        :return: The value of this FleetProperty.
        :rtype: str
        """
        return self._value

    @value.setter
    def value(self, value):
        """
        Sets the value of this FleetProperty.
        Value of the Property.


        :param value: The value of this FleetProperty.
        :type: str
        """
        self._value = value

    @property
    def property_id(self):
        """
        Gets the property_id of this FleetProperty.
        OCID referring to global level metadata property.


        :return: The property_id of this FleetProperty.
        :rtype: str
        """
        return self._property_id

    @property_id.setter
    def property_id(self, property_id):
        """
        Sets the property_id of this FleetProperty.
        OCID referring to global level metadata property.


        :param property_id: The property_id of this FleetProperty.
        :type: str
        """
        self._property_id = property_id

    @property
    def selection_type(self):
        """
        **[Required]** Gets the selection_type of this FleetProperty.
        Text selection of the property.

        Allowed values for this property are: "SINGLE_CHOICE", "MULTI_CHOICE", "DEFAULT_TEXT", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The selection_type of this FleetProperty.
        :rtype: str
        """
        return self._selection_type

    @selection_type.setter
    def selection_type(self, selection_type):
        """
        Sets the selection_type of this FleetProperty.
        Text selection of the property.


        :param selection_type: The selection_type of this FleetProperty.
        :type: str
        """
        allowed_values = ["SINGLE_CHOICE", "MULTI_CHOICE", "DEFAULT_TEXT"]
        if not value_allowed_none_or_none_sentinel(selection_type, allowed_values):
            selection_type = 'UNKNOWN_ENUM_VALUE'
        self._selection_type = selection_type

    @property
    def value_type(self):
        """
        **[Required]** Gets the value_type of this FleetProperty.
        Format of the value.

        Allowed values for this property are: "STRING", "NUMERIC", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The value_type of this FleetProperty.
        :rtype: str
        """
        return self._value_type

    @value_type.setter
    def value_type(self, value_type):
        """
        Sets the value_type of this FleetProperty.
        Format of the value.


        :param value_type: The value_type of this FleetProperty.
        :type: str
        """
        allowed_values = ["STRING", "NUMERIC"]
        if not value_allowed_none_or_none_sentinel(value_type, allowed_values):
            value_type = 'UNKNOWN_ENUM_VALUE'
        self._value_type = value_type

    @property
    def allowed_values(self):
        """
        Gets the allowed_values of this FleetProperty.
        Values of the property (must be a single value if selectionType = 'SINGLE_CHOICE').


        :return: The allowed_values of this FleetProperty.
        :rtype: list[str]
        """
        return self._allowed_values

    @allowed_values.setter
    def allowed_values(self, allowed_values):
        """
        Sets the allowed_values of this FleetProperty.
        Values of the property (must be a single value if selectionType = 'SINGLE_CHOICE').


        :param allowed_values: The allowed_values of this FleetProperty.
        :type: list[str]
        """
        self._allowed_values = allowed_values

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this FleetProperty.
        The current state of the FleetProperty.

        Allowed values for this property are: "ACTIVE", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this FleetProperty.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this FleetProperty.
        The current state of the FleetProperty.


        :param lifecycle_state: The lifecycle_state of this FleetProperty.
        :type: str
        """
        allowed_values = ["ACTIVE", "DELETED", "FAILED"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def system_tags(self):
        """
        Gets the system_tags of this FleetProperty.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this FleetProperty.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this FleetProperty.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this FleetProperty.
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
