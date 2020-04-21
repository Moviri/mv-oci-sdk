# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class LetterOfAuthority(object):
    """
    The Letter of Authority for the cross-connect. You must submit this letter when
    requesting cabling for the cross-connect at the FastConnect location.
    """

    #: A constant which can be used with the circuit_type property of a LetterOfAuthority.
    #: This constant has a value of "Single_mode_LC"
    CIRCUIT_TYPE_SINGLE_MODE_LC = "Single_mode_LC"

    #: A constant which can be used with the circuit_type property of a LetterOfAuthority.
    #: This constant has a value of "Single_mode_SC"
    CIRCUIT_TYPE_SINGLE_MODE_SC = "Single_mode_SC"

    def __init__(self, **kwargs):
        """
        Initializes a new LetterOfAuthority object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param authorized_entity_name:
            The value to assign to the authorized_entity_name property of this LetterOfAuthority.
        :type authorized_entity_name: str

        :param circuit_type:
            The value to assign to the circuit_type property of this LetterOfAuthority.
            Allowed values for this property are: "Single_mode_LC", "Single_mode_SC", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type circuit_type: str

        :param cross_connect_id:
            The value to assign to the cross_connect_id property of this LetterOfAuthority.
        :type cross_connect_id: str

        :param facility_location:
            The value to assign to the facility_location property of this LetterOfAuthority.
        :type facility_location: str

        :param port_name:
            The value to assign to the port_name property of this LetterOfAuthority.
        :type port_name: str

        :param time_expires:
            The value to assign to the time_expires property of this LetterOfAuthority.
        :type time_expires: datetime

        :param time_issued:
            The value to assign to the time_issued property of this LetterOfAuthority.
        :type time_issued: datetime

        """
        self.swagger_types = {
            'authorized_entity_name': 'str',
            'circuit_type': 'str',
            'cross_connect_id': 'str',
            'facility_location': 'str',
            'port_name': 'str',
            'time_expires': 'datetime',
            'time_issued': 'datetime'
        }

        self.attribute_map = {
            'authorized_entity_name': 'authorizedEntityName',
            'circuit_type': 'circuitType',
            'cross_connect_id': 'crossConnectId',
            'facility_location': 'facilityLocation',
            'port_name': 'portName',
            'time_expires': 'timeExpires',
            'time_issued': 'timeIssued'
        }

        self._authorized_entity_name = None
        self._circuit_type = None
        self._cross_connect_id = None
        self._facility_location = None
        self._port_name = None
        self._time_expires = None
        self._time_issued = None

    @property
    def authorized_entity_name(self):
        """
        Gets the authorized_entity_name of this LetterOfAuthority.
        The name of the entity authorized by this Letter of Authority.


        :return: The authorized_entity_name of this LetterOfAuthority.
        :rtype: str
        """
        return self._authorized_entity_name

    @authorized_entity_name.setter
    def authorized_entity_name(self, authorized_entity_name):
        """
        Sets the authorized_entity_name of this LetterOfAuthority.
        The name of the entity authorized by this Letter of Authority.


        :param authorized_entity_name: The authorized_entity_name of this LetterOfAuthority.
        :type: str
        """
        self._authorized_entity_name = authorized_entity_name

    @property
    def circuit_type(self):
        """
        Gets the circuit_type of this LetterOfAuthority.
        The type of cross-connect fiber, termination, and optical specification.

        Allowed values for this property are: "Single_mode_LC", "Single_mode_SC", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The circuit_type of this LetterOfAuthority.
        :rtype: str
        """
        return self._circuit_type

    @circuit_type.setter
    def circuit_type(self, circuit_type):
        """
        Sets the circuit_type of this LetterOfAuthority.
        The type of cross-connect fiber, termination, and optical specification.


        :param circuit_type: The circuit_type of this LetterOfAuthority.
        :type: str
        """
        allowed_values = ["Single_mode_LC", "Single_mode_SC"]
        if not value_allowed_none_or_none_sentinel(circuit_type, allowed_values):
            circuit_type = 'UNKNOWN_ENUM_VALUE'
        self._circuit_type = circuit_type

    @property
    def cross_connect_id(self):
        """
        Gets the cross_connect_id of this LetterOfAuthority.
        The OCID of the cross-connect.


        :return: The cross_connect_id of this LetterOfAuthority.
        :rtype: str
        """
        return self._cross_connect_id

    @cross_connect_id.setter
    def cross_connect_id(self, cross_connect_id):
        """
        Sets the cross_connect_id of this LetterOfAuthority.
        The OCID of the cross-connect.


        :param cross_connect_id: The cross_connect_id of this LetterOfAuthority.
        :type: str
        """
        self._cross_connect_id = cross_connect_id

    @property
    def facility_location(self):
        """
        Gets the facility_location of this LetterOfAuthority.
        The address of the FastConnect location.


        :return: The facility_location of this LetterOfAuthority.
        :rtype: str
        """
        return self._facility_location

    @facility_location.setter
    def facility_location(self, facility_location):
        """
        Sets the facility_location of this LetterOfAuthority.
        The address of the FastConnect location.


        :param facility_location: The facility_location of this LetterOfAuthority.
        :type: str
        """
        self._facility_location = facility_location

    @property
    def port_name(self):
        """
        Gets the port_name of this LetterOfAuthority.
        The meet-me room port for this cross-connect.


        :return: The port_name of this LetterOfAuthority.
        :rtype: str
        """
        return self._port_name

    @port_name.setter
    def port_name(self, port_name):
        """
        Sets the port_name of this LetterOfAuthority.
        The meet-me room port for this cross-connect.


        :param port_name: The port_name of this LetterOfAuthority.
        :type: str
        """
        self._port_name = port_name

    @property
    def time_expires(self):
        """
        Gets the time_expires of this LetterOfAuthority.
        The date and time when the Letter of Authority expires, in the format defined by RFC3339.


        :return: The time_expires of this LetterOfAuthority.
        :rtype: datetime
        """
        return self._time_expires

    @time_expires.setter
    def time_expires(self, time_expires):
        """
        Sets the time_expires of this LetterOfAuthority.
        The date and time when the Letter of Authority expires, in the format defined by RFC3339.


        :param time_expires: The time_expires of this LetterOfAuthority.
        :type: datetime
        """
        self._time_expires = time_expires

    @property
    def time_issued(self):
        """
        Gets the time_issued of this LetterOfAuthority.
        The date and time the Letter of Authority was created, in the format defined by RFC3339.

        Example: `2016-08-25T21:10:29.600Z`


        :return: The time_issued of this LetterOfAuthority.
        :rtype: datetime
        """
        return self._time_issued

    @time_issued.setter
    def time_issued(self, time_issued):
        """
        Sets the time_issued of this LetterOfAuthority.
        The date and time the Letter of Authority was created, in the format defined by RFC3339.

        Example: `2016-08-25T21:10:29.600Z`


        :param time_issued: The time_issued of this LetterOfAuthority.
        :type: datetime
        """
        self._time_issued = time_issued

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
