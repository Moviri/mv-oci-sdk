# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20180828


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DeleteBlockVolumesForNamespaceDetails(object):
    """
    delete block volumes for namespace
    """

    def __init__(self, **kwargs):
        """
        Initializes a new DeleteBlockVolumesForNamespaceDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param cluster_id:
            The value to assign to the cluster_id property of this DeleteBlockVolumesForNamespaceDetails.
        :type cluster_id: str

        :param namespace:
            The value to assign to the namespace property of this DeleteBlockVolumesForNamespaceDetails.
        :type namespace: str

        """
        self.swagger_types = {
            'cluster_id': 'str',
            'namespace': 'str'
        }

        self.attribute_map = {
            'cluster_id': 'clusterId',
            'namespace': 'namespace'
        }

        self._cluster_id = None
        self._namespace = None

    @property
    def cluster_id(self):
        """
        **[Required]** Gets the cluster_id of this DeleteBlockVolumesForNamespaceDetails.
        OCID of the Opensearch Cluster.


        :return: The cluster_id of this DeleteBlockVolumesForNamespaceDetails.
        :rtype: str
        """
        return self._cluster_id

    @cluster_id.setter
    def cluster_id(self, cluster_id):
        """
        Sets the cluster_id of this DeleteBlockVolumesForNamespaceDetails.
        OCID of the Opensearch Cluster.


        :param cluster_id: The cluster_id of this DeleteBlockVolumesForNamespaceDetails.
        :type: str
        """
        self._cluster_id = cluster_id

    @property
    def namespace(self):
        """
        **[Required]** Gets the namespace of this DeleteBlockVolumesForNamespaceDetails.
        Namespace of the Opensearch Cluster.


        :return: The namespace of this DeleteBlockVolumesForNamespaceDetails.
        :rtype: str
        """
        return self._namespace

    @namespace.setter
    def namespace(self, namespace):
        """
        Sets the namespace of this DeleteBlockVolumesForNamespaceDetails.
        Namespace of the Opensearch Cluster.


        :param namespace: The namespace of this DeleteBlockVolumesForNamespaceDetails.
        :type: str
        """
        self._namespace = namespace

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
