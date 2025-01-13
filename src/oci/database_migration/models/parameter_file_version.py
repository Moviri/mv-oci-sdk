# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230518


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ParameterFileVersion(object):
    """
    A parameter file detatails
    """

    #: A constant which can be used with the kind property of a ParameterFileVersion.
    #: This constant has a value of "EXTRACT"
    KIND_EXTRACT = "EXTRACT"

    #: A constant which can be used with the kind property of a ParameterFileVersion.
    #: This constant has a value of "REPLICAT"
    KIND_REPLICAT = "REPLICAT"

    def __init__(self, **kwargs):
        """
        Initializes a new ParameterFileVersion object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param name:
            The value to assign to the name property of this ParameterFileVersion.
        :type name: str

        :param description:
            The value to assign to the description property of this ParameterFileVersion.
        :type description: str

        :param is_current:
            The value to assign to the is_current property of this ParameterFileVersion.
        :type is_current: bool

        :param is_factory:
            The value to assign to the is_factory property of this ParameterFileVersion.
        :type is_factory: bool

        :param kind:
            The value to assign to the kind property of this ParameterFileVersion.
            Allowed values for this property are: "EXTRACT", "REPLICAT", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type kind: str

        :param time_created:
            The value to assign to the time_created property of this ParameterFileVersion.
        :type time_created: datetime

        :param content:
            The value to assign to the content property of this ParameterFileVersion.
        :type content: str

        """
        self.swagger_types = {
            'name': 'str',
            'description': 'str',
            'is_current': 'bool',
            'is_factory': 'bool',
            'kind': 'str',
            'time_created': 'datetime',
            'content': 'str'
        }

        self.attribute_map = {
            'name': 'name',
            'description': 'description',
            'is_current': 'isCurrent',
            'is_factory': 'isFactory',
            'kind': 'kind',
            'time_created': 'timeCreated',
            'content': 'content'
        }

        self._name = None
        self._description = None
        self._is_current = None
        self._is_factory = None
        self._kind = None
        self._time_created = None
        self._content = None

    @property
    def name(self):
        """
        **[Required]** Gets the name of this ParameterFileVersion.
        A unique name associated with the current migration/job and extract/replicat name


        :return: The name of this ParameterFileVersion.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this ParameterFileVersion.
        A unique name associated with the current migration/job and extract/replicat name


        :param name: The name of this ParameterFileVersion.
        :type: str
        """
        self._name = name

    @property
    def description(self):
        """
        Gets the description of this ParameterFileVersion.
        Describes the current parameter file version


        :return: The description of this ParameterFileVersion.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this ParameterFileVersion.
        Describes the current parameter file version


        :param description: The description of this ParameterFileVersion.
        :type: str
        """
        self._description = description

    @property
    def is_current(self):
        """
        **[Required]** Gets the is_current of this ParameterFileVersion.
        Return boolean true/false for the currently in-use parameter file (factory or a versioned file)


        :return: The is_current of this ParameterFileVersion.
        :rtype: bool
        """
        return self._is_current

    @is_current.setter
    def is_current(self, is_current):
        """
        Sets the is_current of this ParameterFileVersion.
        Return boolean true/false for the currently in-use parameter file (factory or a versioned file)


        :param is_current: The is_current of this ParameterFileVersion.
        :type: bool
        """
        self._is_current = is_current

    @property
    def is_factory(self):
        """
        **[Required]** Gets the is_factory of this ParameterFileVersion.
        Return true/false for whether the parameter file is oracle provided (Factory)


        :return: The is_factory of this ParameterFileVersion.
        :rtype: bool
        """
        return self._is_factory

    @is_factory.setter
    def is_factory(self, is_factory):
        """
        Sets the is_factory of this ParameterFileVersion.
        Return true/false for whether the parameter file is oracle provided (Factory)


        :param is_factory: The is_factory of this ParameterFileVersion.
        :type: bool
        """
        self._is_factory = is_factory

    @property
    def kind(self):
        """
        **[Required]** Gets the kind of this ParameterFileVersion.
        Indicator of Parameter File 'kind' (for an EXTRACT or a REPLICAT)

        Allowed values for this property are: "EXTRACT", "REPLICAT", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The kind of this ParameterFileVersion.
        :rtype: str
        """
        return self._kind

    @kind.setter
    def kind(self, kind):
        """
        Sets the kind of this ParameterFileVersion.
        Indicator of Parameter File 'kind' (for an EXTRACT or a REPLICAT)


        :param kind: The kind of this ParameterFileVersion.
        :type: str
        """
        allowed_values = ["EXTRACT", "REPLICAT"]
        if not value_allowed_none_or_none_sentinel(kind, allowed_values):
            kind = 'UNKNOWN_ENUM_VALUE'
        self._kind = kind

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this ParameterFileVersion.
        The time when this parameter file was applied on the process


        :return: The time_created of this ParameterFileVersion.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ParameterFileVersion.
        The time when this parameter file was applied on the process


        :param time_created: The time_created of this ParameterFileVersion.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def content(self):
        """
        **[Required]** Gets the content of this ParameterFileVersion.
        The content in base64 encoded character string containing the value of the parameter file


        :return: The content of this ParameterFileVersion.
        :rtype: str
        """
        return self._content

    @content.setter
    def content(self, content):
        """
        Sets the content of this ParameterFileVersion.
        The content in base64 encoded character string containing the value of the parameter file


        :param content: The content of this ParameterFileVersion.
        :type: str
        """
        self._content = content

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
