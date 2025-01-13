# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20191001


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ContactTypeRule(object):
    """
    Contact type rule information
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ContactTypeRule object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param fields:
            The value to assign to the fields property of this ContactTypeRule.
        :type fields: list[oci.osp_gateway.models.Field]

        """
        self.swagger_types = {
            'fields': 'list[Field]'
        }

        self.attribute_map = {
            'fields': 'fields'
        }

        self._fields = None

    @property
    def fields(self):
        """
        **[Required]** Gets the fields of this ContactTypeRule.
        Contact type rule fields


        :return: The fields of this ContactTypeRule.
        :rtype: list[oci.osp_gateway.models.Field]
        """
        return self._fields

    @fields.setter
    def fields(self, fields):
        """
        Sets the fields of this ContactTypeRule.
        Contact type rule fields


        :param fields: The fields of this ContactTypeRule.
        :type: list[oci.osp_gateway.models.Field]
        """
        self._fields = fields

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
