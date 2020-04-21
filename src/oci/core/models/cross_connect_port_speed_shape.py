# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CrossConnectPortSpeedShape(object):
    """
    An individual port speed level for cross-connects.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CrossConnectPortSpeedShape object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param name:
            The value to assign to the name property of this CrossConnectPortSpeedShape.
        :type name: str

        :param port_speed_in_gbps:
            The value to assign to the port_speed_in_gbps property of this CrossConnectPortSpeedShape.
        :type port_speed_in_gbps: int

        """
        self.swagger_types = {
            'name': 'str',
            'port_speed_in_gbps': 'int'
        }

        self.attribute_map = {
            'name': 'name',
            'port_speed_in_gbps': 'portSpeedInGbps'
        }

        self._name = None
        self._port_speed_in_gbps = None

    @property
    def name(self):
        """
        **[Required]** Gets the name of this CrossConnectPortSpeedShape.
        The name of the port speed shape.

        Example: `10 Gbps`


        :return: The name of this CrossConnectPortSpeedShape.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this CrossConnectPortSpeedShape.
        The name of the port speed shape.

        Example: `10 Gbps`


        :param name: The name of this CrossConnectPortSpeedShape.
        :type: str
        """
        self._name = name

    @property
    def port_speed_in_gbps(self):
        """
        **[Required]** Gets the port_speed_in_gbps of this CrossConnectPortSpeedShape.
        The port speed in Gbps.

        Example: `10`


        :return: The port_speed_in_gbps of this CrossConnectPortSpeedShape.
        :rtype: int
        """
        return self._port_speed_in_gbps

    @port_speed_in_gbps.setter
    def port_speed_in_gbps(self, port_speed_in_gbps):
        """
        Sets the port_speed_in_gbps of this CrossConnectPortSpeedShape.
        The port speed in Gbps.

        Example: `10`


        :param port_speed_in_gbps: The port_speed_in_gbps of this CrossConnectPortSpeedShape.
        :type: int
        """
        self._port_speed_in_gbps = port_speed_in_gbps

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
