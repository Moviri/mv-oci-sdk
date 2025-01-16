# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class IpInventoryCidrUtilizationCollection(object):
    """
    The IP Inventory CIDR utilization details of a subnet.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new IpInventoryCidrUtilizationCollection object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param count:
            The value to assign to the count property of this IpInventoryCidrUtilizationCollection.
        :type count: int

        :param last_updated_timestamp:
            The value to assign to the last_updated_timestamp property of this IpInventoryCidrUtilizationCollection.
        :type last_updated_timestamp: datetime

        :param ip_inventory_cidr_utilization_summary:
            The value to assign to the ip_inventory_cidr_utilization_summary property of this IpInventoryCidrUtilizationCollection.
        :type ip_inventory_cidr_utilization_summary: list[oci.core.models.IpInventoryCidrUtilizationSummary]

        :param message:
            The value to assign to the message property of this IpInventoryCidrUtilizationCollection.
        :type message: str

        :param compartment_id:
            The value to assign to the compartment_id property of this IpInventoryCidrUtilizationCollection.
        :type compartment_id: str

        """
        self.swagger_types = {
            'count': 'int',
            'last_updated_timestamp': 'datetime',
            'ip_inventory_cidr_utilization_summary': 'list[IpInventoryCidrUtilizationSummary]',
            'message': 'str',
            'compartment_id': 'str'
        }

        self.attribute_map = {
            'count': 'count',
            'last_updated_timestamp': 'lastUpdatedTimestamp',
            'ip_inventory_cidr_utilization_summary': 'ipInventoryCidrUtilizationSummary',
            'message': 'message',
            'compartment_id': 'compartmentId'
        }

        self._count = None
        self._last_updated_timestamp = None
        self._ip_inventory_cidr_utilization_summary = None
        self._message = None
        self._compartment_id = None

    @property
    def count(self):
        """
        Gets the count of this IpInventoryCidrUtilizationCollection.
        Specifies the count for the number of results for the response.


        :return: The count of this IpInventoryCidrUtilizationCollection.
        :rtype: int
        """
        return self._count

    @count.setter
    def count(self, count):
        """
        Sets the count of this IpInventoryCidrUtilizationCollection.
        Specifies the count for the number of results for the response.


        :param count: The count of this IpInventoryCidrUtilizationCollection.
        :type: int
        """
        self._count = count

    @property
    def last_updated_timestamp(self):
        """
        Gets the last_updated_timestamp of this IpInventoryCidrUtilizationCollection.
        The Timestamp of the latest update from the database in the format defined by `RFC3339`__.
        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The last_updated_timestamp of this IpInventoryCidrUtilizationCollection.
        :rtype: datetime
        """
        return self._last_updated_timestamp

    @last_updated_timestamp.setter
    def last_updated_timestamp(self, last_updated_timestamp):
        """
        Sets the last_updated_timestamp of this IpInventoryCidrUtilizationCollection.
        The Timestamp of the latest update from the database in the format defined by `RFC3339`__.
        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param last_updated_timestamp: The last_updated_timestamp of this IpInventoryCidrUtilizationCollection.
        :type: datetime
        """
        self._last_updated_timestamp = last_updated_timestamp

    @property
    def ip_inventory_cidr_utilization_summary(self):
        """
        Gets the ip_inventory_cidr_utilization_summary of this IpInventoryCidrUtilizationCollection.
        Lists 'IpInventoryCidrUtilizationSummary` object.


        :return: The ip_inventory_cidr_utilization_summary of this IpInventoryCidrUtilizationCollection.
        :rtype: list[oci.core.models.IpInventoryCidrUtilizationSummary]
        """
        return self._ip_inventory_cidr_utilization_summary

    @ip_inventory_cidr_utilization_summary.setter
    def ip_inventory_cidr_utilization_summary(self, ip_inventory_cidr_utilization_summary):
        """
        Sets the ip_inventory_cidr_utilization_summary of this IpInventoryCidrUtilizationCollection.
        Lists 'IpInventoryCidrUtilizationSummary` object.


        :param ip_inventory_cidr_utilization_summary: The ip_inventory_cidr_utilization_summary of this IpInventoryCidrUtilizationCollection.
        :type: list[oci.core.models.IpInventoryCidrUtilizationSummary]
        """
        self._ip_inventory_cidr_utilization_summary = ip_inventory_cidr_utilization_summary

    @property
    def message(self):
        """
        Gets the message of this IpInventoryCidrUtilizationCollection.
        Indicates the status of the data.


        :return: The message of this IpInventoryCidrUtilizationCollection.
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """
        Sets the message of this IpInventoryCidrUtilizationCollection.
        Indicates the status of the data.


        :param message: The message of this IpInventoryCidrUtilizationCollection.
        :type: str
        """
        self._message = message

    @property
    def compartment_id(self):
        """
        Gets the compartment_id of this IpInventoryCidrUtilizationCollection.
        Compartment of the subnet.


        :return: The compartment_id of this IpInventoryCidrUtilizationCollection.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this IpInventoryCidrUtilizationCollection.
        Compartment of the subnet.


        :param compartment_id: The compartment_id of this IpInventoryCidrUtilizationCollection.
        :type: str
        """
        self._compartment_id = compartment_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other