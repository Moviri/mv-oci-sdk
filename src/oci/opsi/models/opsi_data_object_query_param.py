# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200630


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class OpsiDataObjectQueryParam(object):
    """
    Details for a query parameter to be applied on an OPSI data object, when a data object query is executed.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new OpsiDataObjectQueryParam object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param name:
            The value to assign to the name property of this OpsiDataObjectQueryParam.
        :type name: str

        :param value:
            The value to assign to the value property of this OpsiDataObjectQueryParam.
        :type value: object

        """
        self.swagger_types = {
            'name': 'str',
            'value': 'object'
        }

        self.attribute_map = {
            'name': 'name',
            'value': 'value'
        }

        self._name = None
        self._value = None

    @property
    def name(self):
        """
        **[Required]** Gets the name of this OpsiDataObjectQueryParam.
        Name of the query parameter.


        :return: The name of this OpsiDataObjectQueryParam.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this OpsiDataObjectQueryParam.
        Name of the query parameter.


        :param name: The name of this OpsiDataObjectQueryParam.
        :type: str
        """
        self._name = name

    @property
    def value(self):
        """
        **[Required]** Gets the value of this OpsiDataObjectQueryParam.
        Value for the query parameter.


        :return: The value of this OpsiDataObjectQueryParam.
        :rtype: object
        """
        return self._value

    @value.setter
    def value(self, value):
        """
        Sets the value of this OpsiDataObjectQueryParam.
        Value for the query parameter.


        :param value: The value of this OpsiDataObjectQueryParam.
        :type: object
        """
        self._value = value

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
