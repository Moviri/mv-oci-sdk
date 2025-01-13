# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200630


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class QueryOpsiDataObjectDataDetails(object):
    """
    Information required to form and execute query on an OPSI data object.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new QueryOpsiDataObjectDataDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param data_object_identifier:
            The value to assign to the data_object_identifier property of this QueryOpsiDataObjectDataDetails.
        :type data_object_identifier: str

        :param data_objects:
            The value to assign to the data_objects property of this QueryOpsiDataObjectDataDetails.
        :type data_objects: list[oci.opsi.models.OpsiDataObjectDetailsInQuery]

        :param query:
            The value to assign to the query property of this QueryOpsiDataObjectDataDetails.
        :type query: oci.opsi.models.DataObjectQuery

        :param resource_filters:
            The value to assign to the resource_filters property of this QueryOpsiDataObjectDataDetails.
        :type resource_filters: oci.opsi.models.ResourceFilters

        """
        self.swagger_types = {
            'data_object_identifier': 'str',
            'data_objects': 'list[OpsiDataObjectDetailsInQuery]',
            'query': 'DataObjectQuery',
            'resource_filters': 'ResourceFilters'
        }

        self.attribute_map = {
            'data_object_identifier': 'dataObjectIdentifier',
            'data_objects': 'dataObjects',
            'query': 'query',
            'resource_filters': 'resourceFilters'
        }

        self._data_object_identifier = None
        self._data_objects = None
        self._query = None
        self._resource_filters = None

    @property
    def data_object_identifier(self):
        """
        Gets the data_object_identifier of this QueryOpsiDataObjectDataDetails.
        Unique OPSI data object identifier.


        :return: The data_object_identifier of this QueryOpsiDataObjectDataDetails.
        :rtype: str
        """
        return self._data_object_identifier

    @data_object_identifier.setter
    def data_object_identifier(self, data_object_identifier):
        """
        Sets the data_object_identifier of this QueryOpsiDataObjectDataDetails.
        Unique OPSI data object identifier.


        :param data_object_identifier: The data_object_identifier of this QueryOpsiDataObjectDataDetails.
        :type: str
        """
        self._data_object_identifier = data_object_identifier

    @property
    def data_objects(self):
        """
        Gets the data_objects of this QueryOpsiDataObjectDataDetails.
        Details of OPSI data objects used in the query.


        :return: The data_objects of this QueryOpsiDataObjectDataDetails.
        :rtype: list[oci.opsi.models.OpsiDataObjectDetailsInQuery]
        """
        return self._data_objects

    @data_objects.setter
    def data_objects(self, data_objects):
        """
        Sets the data_objects of this QueryOpsiDataObjectDataDetails.
        Details of OPSI data objects used in the query.


        :param data_objects: The data_objects of this QueryOpsiDataObjectDataDetails.
        :type: list[oci.opsi.models.OpsiDataObjectDetailsInQuery]
        """
        self._data_objects = data_objects

    @property
    def query(self):
        """
        **[Required]** Gets the query of this QueryOpsiDataObjectDataDetails.

        :return: The query of this QueryOpsiDataObjectDataDetails.
        :rtype: oci.opsi.models.DataObjectQuery
        """
        return self._query

    @query.setter
    def query(self, query):
        """
        Sets the query of this QueryOpsiDataObjectDataDetails.

        :param query: The query of this QueryOpsiDataObjectDataDetails.
        :type: oci.opsi.models.DataObjectQuery
        """
        self._query = query

    @property
    def resource_filters(self):
        """
        Gets the resource_filters of this QueryOpsiDataObjectDataDetails.

        :return: The resource_filters of this QueryOpsiDataObjectDataDetails.
        :rtype: oci.opsi.models.ResourceFilters
        """
        return self._resource_filters

    @resource_filters.setter
    def resource_filters(self, resource_filters):
        """
        Sets the resource_filters of this QueryOpsiDataObjectDataDetails.

        :param resource_filters: The resource_filters of this QueryOpsiDataObjectDataDetails.
        :type: oci.opsi.models.ResourceFilters
        """
        self._resource_filters = resource_filters

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
