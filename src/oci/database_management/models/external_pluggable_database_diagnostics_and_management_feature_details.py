# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20201101

from .external_pluggable_database_feature_details import ExternalPluggableDatabaseFeatureDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExternalPluggableDatabaseDiagnosticsAndManagementFeatureDetails(ExternalPluggableDatabaseFeatureDetails):
    """
    The details required to enable the Diagnostics and Management feature.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ExternalPluggableDatabaseDiagnosticsAndManagementFeatureDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.database_management.models.ExternalPluggableDatabaseDiagnosticsAndManagementFeatureDetails.feature` attribute
        of this class is ``DIAGNOSTICS_AND_MANAGEMENT`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param feature:
            The value to assign to the feature property of this ExternalPluggableDatabaseDiagnosticsAndManagementFeatureDetails.
            Allowed values for this property are: "DIAGNOSTICS_AND_MANAGEMENT", "DB_LIFECYCLE_MANAGEMENT", "SQLWATCH"
        :type feature: str

        :param connector_details:
            The value to assign to the connector_details property of this ExternalPluggableDatabaseDiagnosticsAndManagementFeatureDetails.
        :type connector_details: oci.database_management.models.ConnectorDetails

        """
        self.swagger_types = {
            'feature': 'str',
            'connector_details': 'ConnectorDetails'
        }

        self.attribute_map = {
            'feature': 'feature',
            'connector_details': 'connectorDetails'
        }

        self._feature = None
        self._connector_details = None
        self._feature = 'DIAGNOSTICS_AND_MANAGEMENT'

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
