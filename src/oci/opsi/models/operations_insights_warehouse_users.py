# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200630


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class OperationsInsightsWarehouseUsers(object):
    """
    Logical grouping used for Operations Insights Warehouse User operations.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new OperationsInsightsWarehouseUsers object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param operations_insights_warehouse_users:
            The value to assign to the operations_insights_warehouse_users property of this OperationsInsightsWarehouseUsers.
        :type operations_insights_warehouse_users: object

        """
        self.swagger_types = {
            'operations_insights_warehouse_users': 'object'
        }

        self.attribute_map = {
            'operations_insights_warehouse_users': 'operationsInsightsWarehouseUsers'
        }

        self._operations_insights_warehouse_users = None

    @property
    def operations_insights_warehouse_users(self):
        """
        Gets the operations_insights_warehouse_users of this OperationsInsightsWarehouseUsers.
        Operations Insights Warehouse User Object.


        :return: The operations_insights_warehouse_users of this OperationsInsightsWarehouseUsers.
        :rtype: object
        """
        return self._operations_insights_warehouse_users

    @operations_insights_warehouse_users.setter
    def operations_insights_warehouse_users(self, operations_insights_warehouse_users):
        """
        Sets the operations_insights_warehouse_users of this OperationsInsightsWarehouseUsers.
        Operations Insights Warehouse User Object.


        :param operations_insights_warehouse_users: The operations_insights_warehouse_users of this OperationsInsightsWarehouseUsers.
        :type: object
        """
        self._operations_insights_warehouse_users = operations_insights_warehouse_users

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
