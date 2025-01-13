# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230831


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class Group(object):
    """
    The group of the runbook.
    """

    #: A constant which can be used with the type property of a Group.
    #: This constant has a value of "PARALLEL_TASK_GROUP"
    TYPE_PARALLEL_TASK_GROUP = "PARALLEL_TASK_GROUP"

    #: A constant which can be used with the type property of a Group.
    #: This constant has a value of "PARALLEL_RESOURCE_GROUP"
    TYPE_PARALLEL_RESOURCE_GROUP = "PARALLEL_RESOURCE_GROUP"

    #: A constant which can be used with the type property of a Group.
    #: This constant has a value of "ROLLING_RESOURCE_GROUP"
    TYPE_ROLLING_RESOURCE_GROUP = "ROLLING_RESOURCE_GROUP"

    def __init__(self, **kwargs):
        """
        Initializes a new Group object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param type:
            The value to assign to the type property of this Group.
            Allowed values for this property are: "PARALLEL_TASK_GROUP", "PARALLEL_RESOURCE_GROUP", "ROLLING_RESOURCE_GROUP", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type type: str

        :param name:
            The value to assign to the name property of this Group.
        :type name: str

        :param properties:
            The value to assign to the properties property of this Group.
        :type properties: oci.fleet_apps_management.models.ComponentProperties

        """
        self.swagger_types = {
            'type': 'str',
            'name': 'str',
            'properties': 'ComponentProperties'
        }

        self.attribute_map = {
            'type': 'type',
            'name': 'name',
            'properties': 'properties'
        }

        self._type = None
        self._name = None
        self._properties = None

    @property
    def type(self):
        """
        **[Required]** Gets the type of this Group.
        The type of the group.
        PARALLEL_TASK_GROUP : Helps to execute tasks parallelly inside a resource.
        PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly.
        ROLLING_RESOURCE_GROUP : Executes tasks across resources in a rolling order.

        Allowed values for this property are: "PARALLEL_TASK_GROUP", "PARALLEL_RESOURCE_GROUP", "ROLLING_RESOURCE_GROUP", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The type of this Group.
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """
        Sets the type of this Group.
        The type of the group.
        PARALLEL_TASK_GROUP : Helps to execute tasks parallelly inside a resource.
        PARALLEL_RESOURCE_GROUP : Executes tasks across resources parallelly.
        ROLLING_RESOURCE_GROUP : Executes tasks across resources in a rolling order.


        :param type: The type of this Group.
        :type: str
        """
        allowed_values = ["PARALLEL_TASK_GROUP", "PARALLEL_RESOURCE_GROUP", "ROLLING_RESOURCE_GROUP"]
        if not value_allowed_none_or_none_sentinel(type, allowed_values):
            type = 'UNKNOWN_ENUM_VALUE'
        self._type = type

    @property
    def name(self):
        """
        **[Required]** Gets the name of this Group.
        The name of the group.


        :return: The name of this Group.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this Group.
        The name of the group.


        :param name: The name of this Group.
        :type: str
        """
        self._name = name

    @property
    def properties(self):
        """
        Gets the properties of this Group.

        :return: The properties of this Group.
        :rtype: oci.fleet_apps_management.models.ComponentProperties
        """
        return self._properties

    @properties.setter
    def properties(self, properties):
        """
        Sets the properties of this Group.

        :param properties: The properties of this Group.
        :type: oci.fleet_apps_management.models.ComponentProperties
        """
        self._properties = properties

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
