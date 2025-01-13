# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230831


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class Rule(object):
    """
    Rule for DYNAMIC selection.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new Rule object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param basis:
            The value to assign to the basis property of this Rule.
        :type basis: str

        :param compartment_id:
            The value to assign to the compartment_id property of this Rule.
        :type compartment_id: str

        :param resource_compartment_id:
            The value to assign to the resource_compartment_id property of this Rule.
        :type resource_compartment_id: str

        :param conditions:
            The value to assign to the conditions property of this Rule.
        :type conditions: list[oci.fleet_apps_management.models.Condition]

        """
        self.swagger_types = {
            'basis': 'str',
            'compartment_id': 'str',
            'resource_compartment_id': 'str',
            'conditions': 'list[Condition]'
        }

        self.attribute_map = {
            'basis': 'basis',
            'compartment_id': 'compartmentId',
            'resource_compartment_id': 'resourceCompartmentId',
            'conditions': 'conditions'
        }

        self._basis = None
        self._compartment_id = None
        self._resource_compartment_id = None
        self._conditions = None

    @property
    def basis(self):
        """
        Gets the basis of this Rule.
        Based on what the rule is created.
        It can be based on a resourceProperty or a tag.
        If based on a tag, basis will be 'definedTagEquals'
        If based on a resource property, basis will be 'inventoryProperties'


        :return: The basis of this Rule.
        :rtype: str
        """
        return self._basis

    @basis.setter
    def basis(self, basis):
        """
        Sets the basis of this Rule.
        Based on what the rule is created.
        It can be based on a resourceProperty or a tag.
        If based on a tag, basis will be 'definedTagEquals'
        If based on a resource property, basis will be 'inventoryProperties'


        :param basis: The basis of this Rule.
        :type: str
        """
        self._basis = basis

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this Rule.
        Tenancy Id (Root Compartment Id)for which the rule is created.


        :return: The compartment_id of this Rule.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this Rule.
        Tenancy Id (Root Compartment Id)for which the rule is created.


        :param compartment_id: The compartment_id of this Rule.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def resource_compartment_id(self):
        """
        **[Required]** Gets the resource_compartment_id of this Rule.
        The Compartment ID to dynamically search resources.
        Provide the compartment ID to which the rule is applicable.


        :return: The resource_compartment_id of this Rule.
        :rtype: str
        """
        return self._resource_compartment_id

    @resource_compartment_id.setter
    def resource_compartment_id(self, resource_compartment_id):
        """
        Sets the resource_compartment_id of this Rule.
        The Compartment ID to dynamically search resources.
        Provide the compartment ID to which the rule is applicable.


        :param resource_compartment_id: The resource_compartment_id of this Rule.
        :type: str
        """
        self._resource_compartment_id = resource_compartment_id

    @property
    def conditions(self):
        """
        **[Required]** Gets the conditions of this Rule.
        Rule Conditions


        :return: The conditions of this Rule.
        :rtype: list[oci.fleet_apps_management.models.Condition]
        """
        return self._conditions

    @conditions.setter
    def conditions(self, conditions):
        """
        Sets the conditions of this Rule.
        Rule Conditions


        :param conditions: The conditions of this Rule.
        :type: list[oci.fleet_apps_management.models.Condition]
        """
        self._conditions = conditions

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
