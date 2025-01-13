# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918

from .instance_configuration_instance_details import InstanceConfigurationInstanceDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ComputeInstanceOptions(InstanceConfigurationInstanceDetails):
    """
    Multiple Compute Instance Configuration instance details.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ComputeInstanceOptions object with values from keyword arguments. The default value of the :py:attr:`~oci.core.models.ComputeInstanceOptions.instance_type` attribute
        of this class is ``instance_options`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param instance_type:
            The value to assign to the instance_type property of this ComputeInstanceOptions.
        :type instance_type: str

        :param options:
            The value to assign to the options property of this ComputeInstanceOptions.
        :type options: list[oci.core.models.ComputeInstanceDetails]

        """
        self.swagger_types = {
            'instance_type': 'str',
            'options': 'list[ComputeInstanceDetails]'
        }

        self.attribute_map = {
            'instance_type': 'instanceType',
            'options': 'options'
        }

        self._instance_type = None
        self._options = None
        self._instance_type = 'instance_options'

    @property
    def options(self):
        """
        Gets the options of this ComputeInstanceOptions.
        The Compute Instance Configuration parameters.


        :return: The options of this ComputeInstanceOptions.
        :rtype: list[oci.core.models.ComputeInstanceDetails]
        """
        return self._options

    @options.setter
    def options(self, options):
        """
        Sets the options of this ComputeInstanceOptions.
        The Compute Instance Configuration parameters.


        :param options: The options of this ComputeInstanceOptions.
        :type: list[oci.core.models.ComputeInstanceDetails]
        """
        self._options = options

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
