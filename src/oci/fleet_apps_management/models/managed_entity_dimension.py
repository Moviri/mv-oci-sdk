# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230831


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ManagedEntityDimension(object):
    """
    Aggregated summary information for ComplianceRecord
    """

    #: A constant which can be used with the entity property of a ManagedEntityDimension.
    #: This constant has a value of "RESOURCE"
    ENTITY_RESOURCE = "RESOURCE"

    #: A constant which can be used with the entity property of a ManagedEntityDimension.
    #: This constant has a value of "TARGET"
    ENTITY_TARGET = "TARGET"

    def __init__(self, **kwargs):
        """
        Initializes a new ManagedEntityDimension object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param entity:
            The value to assign to the entity property of this ManagedEntityDimension.
            Allowed values for this property are: "RESOURCE", "TARGET", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type entity: str

        """
        self.swagger_types = {
            'entity': 'str'
        }

        self.attribute_map = {
            'entity': 'entity'
        }

        self._entity = None

    @property
    def entity(self):
        """
        **[Required]** Gets the entity of this ManagedEntityDimension.
        Level at which the compliance is calculated.

        Allowed values for this property are: "RESOURCE", "TARGET", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The entity of this ManagedEntityDimension.
        :rtype: str
        """
        return self._entity

    @entity.setter
    def entity(self, entity):
        """
        Sets the entity of this ManagedEntityDimension.
        Level at which the compliance is calculated.


        :param entity: The entity of this ManagedEntityDimension.
        :type: str
        """
        allowed_values = ["RESOURCE", "TARGET"]
        if not value_allowed_none_or_none_sentinel(entity, allowed_values):
            entity = 'UNKNOWN_ENUM_VALUE'
        self._entity = entity

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
