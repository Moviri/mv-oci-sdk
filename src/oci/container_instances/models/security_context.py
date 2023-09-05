# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210415


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class SecurityContext(object):
    """
    Security context for container.
    """

    #: A constant which can be used with the security_context_type property of a SecurityContext.
    #: This constant has a value of "LINUX"
    SECURITY_CONTEXT_TYPE_LINUX = "LINUX"

    def __init__(self, **kwargs):
        """
        Initializes a new SecurityContext object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.container_instances.models.LinuxSecurityContext`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param security_context_type:
            The value to assign to the security_context_type property of this SecurityContext.
            Allowed values for this property are: "LINUX", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type security_context_type: str

        """
        self.swagger_types = {
            'security_context_type': 'str'
        }

        self.attribute_map = {
            'security_context_type': 'securityContextType'
        }

        self._security_context_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['securityContextType']

        if type == 'LINUX':
            return 'LinuxSecurityContext'
        else:
            return 'SecurityContext'

    @property
    def security_context_type(self):
        """
        Gets the security_context_type of this SecurityContext.
        The type of security context

        Allowed values for this property are: "LINUX", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The security_context_type of this SecurityContext.
        :rtype: str
        """
        return self._security_context_type

    @security_context_type.setter
    def security_context_type(self, security_context_type):
        """
        Sets the security_context_type of this SecurityContext.
        The type of security context


        :param security_context_type: The security_context_type of this SecurityContext.
        :type: str
        """
        allowed_values = ["LINUX"]
        if not value_allowed_none_or_none_sentinel(security_context_type, allowed_values):
            security_context_type = 'UNKNOWN_ENUM_VALUE'
        self._security_context_type = security_context_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other