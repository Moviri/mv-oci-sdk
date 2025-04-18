# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20201101


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class JobInBind(object):
    """
    The details of the job in-bind variable.
    """

    #: A constant which can be used with the data_type property of a JobInBind.
    #: This constant has a value of "NUMBER"
    DATA_TYPE_NUMBER = "NUMBER"

    #: A constant which can be used with the data_type property of a JobInBind.
    #: This constant has a value of "STRING"
    DATA_TYPE_STRING = "STRING"

    #: A constant which can be used with the data_type property of a JobInBind.
    #: This constant has a value of "CLOB"
    DATA_TYPE_CLOB = "CLOB"

    def __init__(self, **kwargs):
        """
        Initializes a new JobInBind object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param position:
            The value to assign to the position property of this JobInBind.
        :type position: int

        :param data_type:
            The value to assign to the data_type property of this JobInBind.
            Allowed values for this property are: "NUMBER", "STRING", "CLOB", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type data_type: str

        :param values:
            The value to assign to the values property of this JobInBind.
        :type values: list[str]

        :param array_type_name:
            The value to assign to the array_type_name property of this JobInBind.
        :type array_type_name: str

        """
        self.swagger_types = {
            'position': 'int',
            'data_type': 'str',
            'values': 'list[str]',
            'array_type_name': 'str'
        }

        self.attribute_map = {
            'position': 'position',
            'data_type': 'dataType',
            'values': 'values',
            'array_type_name': 'arrayTypeName'
        }

        self._position = None
        self._data_type = None
        self._values = None
        self._array_type_name = None

    @property
    def position(self):
        """
        **[Required]** Gets the position of this JobInBind.
        The position of the in-bind variable.


        :return: The position of this JobInBind.
        :rtype: int
        """
        return self._position

    @position.setter
    def position(self, position):
        """
        Sets the position of this JobInBind.
        The position of the in-bind variable.


        :param position: The position of this JobInBind.
        :type: int
        """
        self._position = position

    @property
    def data_type(self):
        """
        **[Required]** Gets the data_type of this JobInBind.
        The datatype of the in-bind variable.

        Allowed values for this property are: "NUMBER", "STRING", "CLOB", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The data_type of this JobInBind.
        :rtype: str
        """
        return self._data_type

    @data_type.setter
    def data_type(self, data_type):
        """
        Sets the data_type of this JobInBind.
        The datatype of the in-bind variable.


        :param data_type: The data_type of this JobInBind.
        :type: str
        """
        allowed_values = ["NUMBER", "STRING", "CLOB"]
        if not value_allowed_none_or_none_sentinel(data_type, allowed_values):
            data_type = 'UNKNOWN_ENUM_VALUE'
        self._data_type = data_type

    @property
    def values(self):
        """
        **[Required]** Gets the values of this JobInBind.
        The values for the in-bind variable.


        :return: The values of this JobInBind.
        :rtype: list[str]
        """
        return self._values

    @values.setter
    def values(self, values):
        """
        Sets the values of this JobInBind.
        The values for the in-bind variable.


        :param values: The values of this JobInBind.
        :type: list[str]
        """
        self._values = values

    @property
    def array_type_name(self):
        """
        Gets the array_type_name of this JobInBind.
        The Oracle schema object name for the predefined type of array.


        :return: The array_type_name of this JobInBind.
        :rtype: str
        """
        return self._array_type_name

    @array_type_name.setter
    def array_type_name(self, array_type_name):
        """
        Sets the array_type_name of this JobInBind.
        The Oracle schema object name for the predefined type of array.


        :param array_type_name: The array_type_name of this JobInBind.
        :type: str
        """
        self._array_type_name = array_type_name

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
