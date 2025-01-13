# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200630


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AddmDbParameterCategorySummary(object):
    """
    Database parameter category summary
    """

    def __init__(self, **kwargs):
        """
        Initializes a new AddmDbParameterCategorySummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this AddmDbParameterCategorySummary.
        :type id: str

        :param name:
            The value to assign to the name property of this AddmDbParameterCategorySummary.
        :type name: str

        :param display_name:
            The value to assign to the display_name property of this AddmDbParameterCategorySummary.
        :type display_name: str

        """
        self.swagger_types = {
            'id': 'str',
            'name': 'str',
            'display_name': 'str'
        }

        self.attribute_map = {
            'id': 'id',
            'name': 'name',
            'display_name': 'displayName'
        }

        self._id = None
        self._name = None
        self._display_name = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this AddmDbParameterCategorySummary.
        The `OCID`__ of the Database insight.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The id of this AddmDbParameterCategorySummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this AddmDbParameterCategorySummary.
        The `OCID`__ of the Database insight.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param id: The id of this AddmDbParameterCategorySummary.
        :type: str
        """
        self._id = id

    @property
    def name(self):
        """
        **[Required]** Gets the name of this AddmDbParameterCategorySummary.
        Name of database parameter category


        :return: The name of this AddmDbParameterCategorySummary.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this AddmDbParameterCategorySummary.
        Name of database parameter category


        :param name: The name of this AddmDbParameterCategorySummary.
        :type: str
        """
        self._name = name

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this AddmDbParameterCategorySummary.
        Display name of database parameter  category


        :return: The display_name of this AddmDbParameterCategorySummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this AddmDbParameterCategorySummary.
        Display name of database parameter  category


        :param display_name: The display_name of this AddmDbParameterCategorySummary.
        :type: str
        """
        self._display_name = display_name

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
