# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181231


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateSubCategoryDetails(object):
    """
    Details for creating the service subcategory of the support ticket.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateSubCategoryDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param sub_category_key:
            The value to assign to the sub_category_key property of this CreateSubCategoryDetails.
        :type sub_category_key: str

        """
        self.swagger_types = {
            'sub_category_key': 'str'
        }

        self.attribute_map = {
            'sub_category_key': 'subCategoryKey'
        }

        self._sub_category_key = None

    @property
    def sub_category_key(self):
        """
        Gets the sub_category_key of this CreateSubCategoryDetails.
        Unique identifier for the service subcategory.


        :return: The sub_category_key of this CreateSubCategoryDetails.
        :rtype: str
        """
        return self._sub_category_key

    @sub_category_key.setter
    def sub_category_key(self, sub_category_key):
        """
        Sets the sub_category_key of this CreateSubCategoryDetails.
        Unique identifier for the service subcategory.


        :param sub_category_key: The sub_category_key of this CreateSubCategoryDetails.
        :type: str
        """
        self._sub_category_key = sub_category_key

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
