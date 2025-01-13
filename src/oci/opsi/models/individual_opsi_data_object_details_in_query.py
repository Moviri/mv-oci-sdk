# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200630

from .opsi_data_object_details_in_query import OpsiDataObjectDetailsInQuery
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class IndividualOpsiDataObjectDetailsInQuery(OpsiDataObjectDetailsInQuery):
    """
    Details applicable for an individual OPSI data object used in a data object query.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new IndividualOpsiDataObjectDetailsInQuery object with values from keyword arguments. The default value of the :py:attr:`~oci.opsi.models.IndividualOpsiDataObjectDetailsInQuery.data_object_details_target` attribute
        of this class is ``INDIVIDUAL_OPSIDATAOBJECT`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param data_object_details_target:
            The value to assign to the data_object_details_target property of this IndividualOpsiDataObjectDetailsInQuery.
            Allowed values for this property are: "INDIVIDUAL_OPSIDATAOBJECT", "OPSIDATAOBJECTTYPE_OPSIDATAOBJECTS"
        :type data_object_details_target: str

        :param _query_params:
            The value to assign to the _query_params property of this IndividualOpsiDataObjectDetailsInQuery.
        :type _query_params: list[oci.opsi.models.OpsiDataObjectQueryParam]

        :param data_object_identifier:
            The value to assign to the data_object_identifier property of this IndividualOpsiDataObjectDetailsInQuery.
        :type data_object_identifier: str

        """
        self.swagger_types = {
            'data_object_details_target': 'str',
            '_query_params': 'list[OpsiDataObjectQueryParam]',
            'data_object_identifier': 'str'
        }

        self.attribute_map = {
            'data_object_details_target': 'dataObjectDetailsTarget',
            '_query_params': 'queryParams',
            'data_object_identifier': 'dataObjectIdentifier'
        }

        self._data_object_details_target = None
        self.__query_params = None
        self._data_object_identifier = None
        self._data_object_details_target = 'INDIVIDUAL_OPSIDATAOBJECT'

    @property
    def data_object_identifier(self):
        """
        **[Required]** Gets the data_object_identifier of this IndividualOpsiDataObjectDetailsInQuery.
        Unique OPSI data object identifier.


        :return: The data_object_identifier of this IndividualOpsiDataObjectDetailsInQuery.
        :rtype: str
        """
        return self._data_object_identifier

    @data_object_identifier.setter
    def data_object_identifier(self, data_object_identifier):
        """
        Sets the data_object_identifier of this IndividualOpsiDataObjectDetailsInQuery.
        Unique OPSI data object identifier.


        :param data_object_identifier: The data_object_identifier of this IndividualOpsiDataObjectDetailsInQuery.
        :type: str
        """
        self._data_object_identifier = data_object_identifier

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
