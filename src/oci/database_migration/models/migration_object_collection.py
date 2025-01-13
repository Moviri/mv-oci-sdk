# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230518


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class MigrationObjectCollection(object):
    """
    Common Migration Objects collection.
    """

    #: A constant which can be used with the database_combination property of a MigrationObjectCollection.
    #: This constant has a value of "MYSQL"
    DATABASE_COMBINATION_MYSQL = "MYSQL"

    #: A constant which can be used with the database_combination property of a MigrationObjectCollection.
    #: This constant has a value of "ORACLE"
    DATABASE_COMBINATION_ORACLE = "ORACLE"

    def __init__(self, **kwargs):
        """
        Initializes a new MigrationObjectCollection object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.database_migration.models.MySqlMigrationObjectCollection`
        * :class:`~oci.database_migration.models.OracleMigrationObjectCollection`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param database_combination:
            The value to assign to the database_combination property of this MigrationObjectCollection.
            Allowed values for this property are: "MYSQL", "ORACLE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type database_combination: str

        """
        self.swagger_types = {
            'database_combination': 'str'
        }

        self.attribute_map = {
            'database_combination': 'databaseCombination'
        }

        self._database_combination = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['databaseCombination']

        if type == 'MYSQL':
            return 'MySqlMigrationObjectCollection'

        if type == 'ORACLE':
            return 'OracleMigrationObjectCollection'
        else:
            return 'MigrationObjectCollection'

    @property
    def database_combination(self):
        """
        **[Required]** Gets the database_combination of this MigrationObjectCollection.
        The combination of source and target databases participating in a migration.
        Example: ORACLE means the migration is meant for migrating Oracle source and target databases.

        Allowed values for this property are: "MYSQL", "ORACLE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The database_combination of this MigrationObjectCollection.
        :rtype: str
        """
        return self._database_combination

    @database_combination.setter
    def database_combination(self, database_combination):
        """
        Sets the database_combination of this MigrationObjectCollection.
        The combination of source and target databases participating in a migration.
        Example: ORACLE means the migration is meant for migrating Oracle source and target databases.


        :param database_combination: The database_combination of this MigrationObjectCollection.
        :type: str
        """
        allowed_values = ["MYSQL", "ORACLE"]
        if not value_allowed_none_or_none_sentinel(database_combination, allowed_values):
            database_combination = 'UNKNOWN_ENUM_VALUE'
        self._database_combination = database_combination

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
