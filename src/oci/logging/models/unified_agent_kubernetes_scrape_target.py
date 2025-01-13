# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200531


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class UnifiedAgentKubernetesScrapeTarget(object):
    """
    Monitoring scrape object.
    """

    #: A constant which can be used with the resource_type property of a UnifiedAgentKubernetesScrapeTarget.
    #: This constant has a value of "PODS"
    RESOURCE_TYPE_PODS = "PODS"

    #: A constant which can be used with the resource_type property of a UnifiedAgentKubernetesScrapeTarget.
    #: This constant has a value of "ENDPOINTS"
    RESOURCE_TYPE_ENDPOINTS = "ENDPOINTS"

    #: A constant which can be used with the resource_type property of a UnifiedAgentKubernetesScrapeTarget.
    #: This constant has a value of "NODES"
    RESOURCE_TYPE_NODES = "NODES"

    #: A constant which can be used with the resource_type property of a UnifiedAgentKubernetesScrapeTarget.
    #: This constant has a value of "SERVICES"
    RESOURCE_TYPE_SERVICES = "SERVICES"

    def __init__(self, **kwargs):
        """
        Initializes a new UnifiedAgentKubernetesScrapeTarget object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param resource_type:
            The value to assign to the resource_type property of this UnifiedAgentKubernetesScrapeTarget.
            Allowed values for this property are: "PODS", "ENDPOINTS", "NODES", "SERVICES", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type resource_type: str

        :param k8s_namespace:
            The value to assign to the k8s_namespace property of this UnifiedAgentKubernetesScrapeTarget.
        :type k8s_namespace: str

        :param service_name:
            The value to assign to the service_name property of this UnifiedAgentKubernetesScrapeTarget.
        :type service_name: str

        :param resource_group:
            The value to assign to the resource_group property of this UnifiedAgentKubernetesScrapeTarget.
        :type resource_group: str

        """
        self.swagger_types = {
            'resource_type': 'str',
            'k8s_namespace': 'str',
            'service_name': 'str',
            'resource_group': 'str'
        }

        self.attribute_map = {
            'resource_type': 'resourceType',
            'k8s_namespace': 'k8sNamespace',
            'service_name': 'serviceName',
            'resource_group': 'resourceGroup'
        }

        self._resource_type = None
        self._k8s_namespace = None
        self._service_name = None
        self._resource_group = None

    @property
    def resource_type(self):
        """
        **[Required]** Gets the resource_type of this UnifiedAgentKubernetesScrapeTarget.
        Type of resource to scrape metrics.

        Allowed values for this property are: "PODS", "ENDPOINTS", "NODES", "SERVICES", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The resource_type of this UnifiedAgentKubernetesScrapeTarget.
        :rtype: str
        """
        return self._resource_type

    @resource_type.setter
    def resource_type(self, resource_type):
        """
        Sets the resource_type of this UnifiedAgentKubernetesScrapeTarget.
        Type of resource to scrape metrics.


        :param resource_type: The resource_type of this UnifiedAgentKubernetesScrapeTarget.
        :type: str
        """
        allowed_values = ["PODS", "ENDPOINTS", "NODES", "SERVICES"]
        if not value_allowed_none_or_none_sentinel(resource_type, allowed_values):
            resource_type = 'UNKNOWN_ENUM_VALUE'
        self._resource_type = resource_type

    @property
    def k8s_namespace(self):
        """
        **[Required]** Gets the k8s_namespace of this UnifiedAgentKubernetesScrapeTarget.
        K8s namespace of the resource.


        :return: The k8s_namespace of this UnifiedAgentKubernetesScrapeTarget.
        :rtype: str
        """
        return self._k8s_namespace

    @k8s_namespace.setter
    def k8s_namespace(self, k8s_namespace):
        """
        Sets the k8s_namespace of this UnifiedAgentKubernetesScrapeTarget.
        K8s namespace of the resource.


        :param k8s_namespace: The k8s_namespace of this UnifiedAgentKubernetesScrapeTarget.
        :type: str
        """
        self._k8s_namespace = k8s_namespace

    @property
    def service_name(self):
        """
        Gets the service_name of this UnifiedAgentKubernetesScrapeTarget.
        Name of the service prepended to the endpoints.


        :return: The service_name of this UnifiedAgentKubernetesScrapeTarget.
        :rtype: str
        """
        return self._service_name

    @service_name.setter
    def service_name(self, service_name):
        """
        Sets the service_name of this UnifiedAgentKubernetesScrapeTarget.
        Name of the service prepended to the endpoints.


        :param service_name: The service_name of this UnifiedAgentKubernetesScrapeTarget.
        :type: str
        """
        self._service_name = service_name

    @property
    def resource_group(self):
        """
        Gets the resource_group of this UnifiedAgentKubernetesScrapeTarget.
        Resource group in OCI monitoring.


        :return: The resource_group of this UnifiedAgentKubernetesScrapeTarget.
        :rtype: str
        """
        return self._resource_group

    @resource_group.setter
    def resource_group(self, resource_group):
        """
        Sets the resource_group of this UnifiedAgentKubernetesScrapeTarget.
        Resource group in OCI monitoring.


        :param resource_group: The resource_group of this UnifiedAgentKubernetesScrapeTarget.
        :type: str
        """
        self._resource_group = resource_group

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
