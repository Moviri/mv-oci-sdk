# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200107


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UsageCarbonEmissionAggregation(object):
    """
    The account (tenant) usage carbon emissions.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new UsageCarbonEmissionAggregation object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param group_by:
            The value to assign to the group_by property of this UsageCarbonEmissionAggregation.
        :type group_by: list[str]

        :param items:
            The value to assign to the items property of this UsageCarbonEmissionAggregation.
        :type items: list[oci.usage_api.models.UsageCarbonEmissionSummary]

        """
        self.swagger_types = {
            'group_by': 'list[str]',
            'items': 'list[UsageCarbonEmissionSummary]'
        }

        self.attribute_map = {
            'group_by': 'groupBy',
            'items': 'items'
        }

        self._group_by = None
        self._items = None

    @property
    def group_by(self):
        """
        Gets the group_by of this UsageCarbonEmissionAggregation.
        Aggregate the result by.


        :return: The group_by of this UsageCarbonEmissionAggregation.
        :rtype: list[str]
        """
        return self._group_by

    @group_by.setter
    def group_by(self, group_by):
        """
        Sets the group_by of this UsageCarbonEmissionAggregation.
        Aggregate the result by.


        :param group_by: The group_by of this UsageCarbonEmissionAggregation.
        :type: list[str]
        """
        self._group_by = group_by

    @property
    def items(self):
        """
        **[Required]** Gets the items of this UsageCarbonEmissionAggregation.
        A list of usage carbon emission items.


        :return: The items of this UsageCarbonEmissionAggregation.
        :rtype: list[oci.usage_api.models.UsageCarbonEmissionSummary]
        """
        return self._items

    @items.setter
    def items(self, items):
        """
        Sets the items of this UsageCarbonEmissionAggregation.
        A list of usage carbon emission items.


        :param items: The items of this UsageCarbonEmissionAggregation.
        :type: list[oci.usage_api.models.UsageCarbonEmissionSummary]
        """
        self._items = items

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
