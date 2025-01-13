# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220125

from .dr_protection_group_member import DrProtectionGroupMember
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DrProtectionGroupMemberNetworkLoadBalancer(DrProtectionGroupMember):
    """
    The properties for a network load balancer member of a DR protection group.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DrProtectionGroupMemberNetworkLoadBalancer object with values from keyword arguments. The default value of the :py:attr:`~oci.disaster_recovery.models.DrProtectionGroupMemberNetworkLoadBalancer.member_type` attribute
        of this class is ``NETWORK_LOAD_BALANCER`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param member_id:
            The value to assign to the member_id property of this DrProtectionGroupMemberNetworkLoadBalancer.
        :type member_id: str

        :param member_type:
            The value to assign to the member_type property of this DrProtectionGroupMemberNetworkLoadBalancer.
            Allowed values for this property are: "COMPUTE_INSTANCE", "COMPUTE_INSTANCE_MOVABLE", "COMPUTE_INSTANCE_NON_MOVABLE", "VOLUME_GROUP", "DATABASE", "AUTONOMOUS_DATABASE", "AUTONOMOUS_CONTAINER_DATABASE", "LOAD_BALANCER", "NETWORK_LOAD_BALANCER", "FILE_SYSTEM", "OBJECT_STORAGE_BUCKET"
        :type member_type: str

        :param destination_network_load_balancer_id:
            The value to assign to the destination_network_load_balancer_id property of this DrProtectionGroupMemberNetworkLoadBalancer.
        :type destination_network_load_balancer_id: str

        :param backend_set_mappings:
            The value to assign to the backend_set_mappings property of this DrProtectionGroupMemberNetworkLoadBalancer.
        :type backend_set_mappings: list[oci.disaster_recovery.models.NetworkLoadBalancerBackendSetMapping]

        """
        self.swagger_types = {
            'member_id': 'str',
            'member_type': 'str',
            'destination_network_load_balancer_id': 'str',
            'backend_set_mappings': 'list[NetworkLoadBalancerBackendSetMapping]'
        }

        self.attribute_map = {
            'member_id': 'memberId',
            'member_type': 'memberType',
            'destination_network_load_balancer_id': 'destinationNetworkLoadBalancerId',
            'backend_set_mappings': 'backendSetMappings'
        }

        self._member_id = None
        self._member_type = None
        self._destination_network_load_balancer_id = None
        self._backend_set_mappings = None
        self._member_type = 'NETWORK_LOAD_BALANCER'

    @property
    def destination_network_load_balancer_id(self):
        """
        Gets the destination_network_load_balancer_id of this DrProtectionGroupMemberNetworkLoadBalancer.
        The OCID of the destination network load balancer.
        The backend sets in this destination network load balancer are updated during DR.

        Example: `ocid1.networkloadbalancer.oc1..uniqueID`


        :return: The destination_network_load_balancer_id of this DrProtectionGroupMemberNetworkLoadBalancer.
        :rtype: str
        """
        return self._destination_network_load_balancer_id

    @destination_network_load_balancer_id.setter
    def destination_network_load_balancer_id(self, destination_network_load_balancer_id):
        """
        Sets the destination_network_load_balancer_id of this DrProtectionGroupMemberNetworkLoadBalancer.
        The OCID of the destination network load balancer.
        The backend sets in this destination network load balancer are updated during DR.

        Example: `ocid1.networkloadbalancer.oc1..uniqueID`


        :param destination_network_load_balancer_id: The destination_network_load_balancer_id of this DrProtectionGroupMemberNetworkLoadBalancer.
        :type: str
        """
        self._destination_network_load_balancer_id = destination_network_load_balancer_id

    @property
    def backend_set_mappings(self):
        """
        Gets the backend_set_mappings of this DrProtectionGroupMemberNetworkLoadBalancer.
        A list of backend set mappings that are used to transfer or update backends during DR.


        :return: The backend_set_mappings of this DrProtectionGroupMemberNetworkLoadBalancer.
        :rtype: list[oci.disaster_recovery.models.NetworkLoadBalancerBackendSetMapping]
        """
        return self._backend_set_mappings

    @backend_set_mappings.setter
    def backend_set_mappings(self, backend_set_mappings):
        """
        Sets the backend_set_mappings of this DrProtectionGroupMemberNetworkLoadBalancer.
        A list of backend set mappings that are used to transfer or update backends during DR.


        :param backend_set_mappings: The backend_set_mappings of this DrProtectionGroupMemberNetworkLoadBalancer.
        :type: list[oci.disaster_recovery.models.NetworkLoadBalancerBackendSetMapping]
        """
        self._backend_set_mappings = backend_set_mappings

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
