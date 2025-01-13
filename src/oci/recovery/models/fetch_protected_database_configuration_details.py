# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210216


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class FetchProtectedDatabaseConfigurationDetails(object):
    """
    Provides which configuration details to get.
    """

    #: A constant which can be used with the configuration_type property of a FetchProtectedDatabaseConfigurationDetails.
    #: This constant has a value of "CABUNDLE"
    CONFIGURATION_TYPE_CABUNDLE = "CABUNDLE"

    #: A constant which can be used with the configuration_type property of a FetchProtectedDatabaseConfigurationDetails.
    #: This constant has a value of "TNSNAMES"
    CONFIGURATION_TYPE_TNSNAMES = "TNSNAMES"

    #: A constant which can be used with the configuration_type property of a FetchProtectedDatabaseConfigurationDetails.
    #: This constant has a value of "HOSTS"
    CONFIGURATION_TYPE_HOSTS = "HOSTS"

    #: A constant which can be used with the configuration_type property of a FetchProtectedDatabaseConfigurationDetails.
    #: This constant has a value of "RCVCONF"
    CONFIGURATION_TYPE_RCVCONF = "RCVCONF"

    #: A constant which can be used with the configuration_type property of a FetchProtectedDatabaseConfigurationDetails.
    #: This constant has a value of "ALL"
    CONFIGURATION_TYPE_ALL = "ALL"

    def __init__(self, **kwargs):
        """
        Initializes a new FetchProtectedDatabaseConfigurationDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param configuration_type:
            The value to assign to the configuration_type property of this FetchProtectedDatabaseConfigurationDetails.
            Allowed values for this property are: "CABUNDLE", "TNSNAMES", "HOSTS", "RCVCONF", "ALL"
        :type configuration_type: str

        """
        self.swagger_types = {
            'configuration_type': 'str'
        }

        self.attribute_map = {
            'configuration_type': 'configurationType'
        }

        self._configuration_type = None

    @property
    def configuration_type(self):
        """
        Gets the configuration_type of this FetchProtectedDatabaseConfigurationDetails.
        Currently has four config options ALL, TNSNAMES, HOSTS and CABUNDLE. All will return a zipped folder containing the contents of both tnsnames and the certificateChainPem.

        Allowed values for this property are: "CABUNDLE", "TNSNAMES", "HOSTS", "RCVCONF", "ALL"


        :return: The configuration_type of this FetchProtectedDatabaseConfigurationDetails.
        :rtype: str
        """
        return self._configuration_type

    @configuration_type.setter
    def configuration_type(self, configuration_type):
        """
        Sets the configuration_type of this FetchProtectedDatabaseConfigurationDetails.
        Currently has four config options ALL, TNSNAMES, HOSTS and CABUNDLE. All will return a zipped folder containing the contents of both tnsnames and the certificateChainPem.


        :param configuration_type: The configuration_type of this FetchProtectedDatabaseConfigurationDetails.
        :type: str
        """
        allowed_values = ["CABUNDLE", "TNSNAMES", "HOSTS", "RCVCONF", "ALL"]
        if not value_allowed_none_or_none_sentinel(configuration_type, allowed_values):
            raise ValueError(
                f"Invalid value for `configuration_type`, must be None or one of {allowed_values}"
            )
        self._configuration_type = configuration_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
