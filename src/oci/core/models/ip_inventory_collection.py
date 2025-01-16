# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class IpInventoryCollection(object):
    """
    The results returned by a `ListIpInventory` operation.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new IpInventoryCollection object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param count:
            The value to assign to the count property of this IpInventoryCollection.
        :type count: int

        :param last_updated_timestamp:
            The value to assign to the last_updated_timestamp property of this IpInventoryCollection.
        :type last_updated_timestamp: datetime

        :param compartments_per_tenant:
            The value to assign to the compartments_per_tenant property of this IpInventoryCollection.
        :type compartments_per_tenant: int

        :param inventory_vcn_collection:
            The value to assign to the inventory_vcn_collection property of this IpInventoryCollection.
        :type inventory_vcn_collection: list[oci.core.models.InventoryVcnSummary]

        :param message:
            The value to assign to the message property of this IpInventoryCollection.
        :type message: str

        """
        self.swagger_types = {
            'count': 'int',
            'last_updated_timestamp': 'datetime',
            'compartments_per_tenant': 'int',
            'inventory_vcn_collection': 'list[InventoryVcnSummary]',
            'message': 'str'
        }

        self.attribute_map = {
            'count': 'count',
            'last_updated_timestamp': 'lastUpdatedTimestamp',
            'compartments_per_tenant': 'compartmentsPerTenant',
            'inventory_vcn_collection': 'inventoryVcnCollection',
            'message': 'message'
        }

        self._count = None
        self._last_updated_timestamp = None
        self._compartments_per_tenant = None
        self._inventory_vcn_collection = None
        self._message = None

    @property
    def count(self):
        """
        Gets the count of this IpInventoryCollection.
        Species the count for the number of results for the response.


        :return: The count of this IpInventoryCollection.
        :rtype: int
        """
        return self._count

    @count.setter
    def count(self, count):
        """
        Sets the count of this IpInventoryCollection.
        Species the count for the number of results for the response.


        :param count: The count of this IpInventoryCollection.
        :type: int
        """
        self._count = count

    @property
    def last_updated_timestamp(self):
        """
        Gets the last_updated_timestamp of this IpInventoryCollection.
        The timestamp of the latest update from the database in the format defined by `RFC3339`__.
        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The last_updated_timestamp of this IpInventoryCollection.
        :rtype: datetime
        """
        return self._last_updated_timestamp

    @last_updated_timestamp.setter
    def last_updated_timestamp(self, last_updated_timestamp):
        """
        Sets the last_updated_timestamp of this IpInventoryCollection.
        The timestamp of the latest update from the database in the format defined by `RFC3339`__.
        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param last_updated_timestamp: The last_updated_timestamp of this IpInventoryCollection.
        :type: datetime
        """
        self._last_updated_timestamp = last_updated_timestamp

    @property
    def compartments_per_tenant(self):
        """
        Gets the compartments_per_tenant of this IpInventoryCollection.
        The number of compartments per compartments per tenant.


        :return: The compartments_per_tenant of this IpInventoryCollection.
        :rtype: int
        """
        return self._compartments_per_tenant

    @compartments_per_tenant.setter
    def compartments_per_tenant(self, compartments_per_tenant):
        """
        Sets the compartments_per_tenant of this IpInventoryCollection.
        The number of compartments per compartments per tenant.


        :param compartments_per_tenant: The compartments_per_tenant of this IpInventoryCollection.
        :type: int
        """
        self._compartments_per_tenant = compartments_per_tenant

    @property
    def inventory_vcn_collection(self):
        """
        Gets the inventory_vcn_collection of this IpInventoryCollection.
        Lists `IpInventoryVcnSummary` objects.


        :return: The inventory_vcn_collection of this IpInventoryCollection.
        :rtype: list[oci.core.models.InventoryVcnSummary]
        """
        return self._inventory_vcn_collection

    @inventory_vcn_collection.setter
    def inventory_vcn_collection(self, inventory_vcn_collection):
        """
        Sets the inventory_vcn_collection of this IpInventoryCollection.
        Lists `IpInventoryVcnSummary` objects.


        :param inventory_vcn_collection: The inventory_vcn_collection of this IpInventoryCollection.
        :type: list[oci.core.models.InventoryVcnSummary]
        """
        self._inventory_vcn_collection = inventory_vcn_collection

    @property
    def message(self):
        """
        Gets the message of this IpInventoryCollection.
        Indicates the status of the data.


        :return: The message of this IpInventoryCollection.
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """
        Sets the message of this IpInventoryCollection.
        Indicates the status of the data.


        :param message: The message of this IpInventoryCollection.
        :type: str
        """
        self._message = message

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other