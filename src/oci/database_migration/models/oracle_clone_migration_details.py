# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230518

from .clone_migration_details import CloneMigrationDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class OracleCloneMigrationDetails(CloneMigrationDetails):
    """
    Oracle Clone Migration Summary
    """

    def __init__(self, **kwargs):
        """
        Initializes a new OracleCloneMigrationDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.database_migration.models.OracleCloneMigrationDetails.database_combination` attribute
        of this class is ``ORACLE`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param database_combination:
            The value to assign to the database_combination property of this OracleCloneMigrationDetails.
            Allowed values for this property are: "MYSQL", "ORACLE"
        :type database_combination: str

        :param display_name:
            The value to assign to the display_name property of this OracleCloneMigrationDetails.
        :type display_name: str

        :param compartment_id:
            The value to assign to the compartment_id property of this OracleCloneMigrationDetails.
        :type compartment_id: str

        :param source_database_connection_id:
            The value to assign to the source_database_connection_id property of this OracleCloneMigrationDetails.
        :type source_database_connection_id: str

        :param target_database_connection_id:
            The value to assign to the target_database_connection_id property of this OracleCloneMigrationDetails.
        :type target_database_connection_id: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this OracleCloneMigrationDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this OracleCloneMigrationDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param source_container_database_connection_id:
            The value to assign to the source_container_database_connection_id property of this OracleCloneMigrationDetails.
        :type source_container_database_connection_id: str

        """
        self.swagger_types = {
            'database_combination': 'str',
            'display_name': 'str',
            'compartment_id': 'str',
            'source_database_connection_id': 'str',
            'target_database_connection_id': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'source_container_database_connection_id': 'str'
        }

        self.attribute_map = {
            'database_combination': 'databaseCombination',
            'display_name': 'displayName',
            'compartment_id': 'compartmentId',
            'source_database_connection_id': 'sourceDatabaseConnectionId',
            'target_database_connection_id': 'targetDatabaseConnectionId',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'source_container_database_connection_id': 'sourceContainerDatabaseConnectionId'
        }

        self._database_combination = None
        self._display_name = None
        self._compartment_id = None
        self._source_database_connection_id = None
        self._target_database_connection_id = None
        self._freeform_tags = None
        self._defined_tags = None
        self._source_container_database_connection_id = None
        self._database_combination = 'ORACLE'

    @property
    def source_container_database_connection_id(self):
        """
        Gets the source_container_database_connection_id of this OracleCloneMigrationDetails.
        The OCID of the resource being referenced.


        :return: The source_container_database_connection_id of this OracleCloneMigrationDetails.
        :rtype: str
        """
        return self._source_container_database_connection_id

    @source_container_database_connection_id.setter
    def source_container_database_connection_id(self, source_container_database_connection_id):
        """
        Sets the source_container_database_connection_id of this OracleCloneMigrationDetails.
        The OCID of the resource being referenced.


        :param source_container_database_connection_id: The source_container_database_connection_id of this OracleCloneMigrationDetails.
        :type: str
        """
        self._source_container_database_connection_id = source_container_database_connection_id

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
