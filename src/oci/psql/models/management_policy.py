# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220915


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ManagementPolicy(object):
    """
    PostgreSQL DB system management policy
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ManagementPolicy object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param maintenance_window_start:
            The value to assign to the maintenance_window_start property of this ManagementPolicy.
        :type maintenance_window_start: str

        :param backup_policy:
            The value to assign to the backup_policy property of this ManagementPolicy.
        :type backup_policy: oci.psql.models.BackupPolicy

        """
        self.swagger_types = {
            'maintenance_window_start': 'str',
            'backup_policy': 'BackupPolicy'
        }

        self.attribute_map = {
            'maintenance_window_start': 'maintenanceWindowStart',
            'backup_policy': 'backupPolicy'
        }

        self._maintenance_window_start = None
        self._backup_policy = None

    @property
    def maintenance_window_start(self):
        """
        **[Required]** Gets the maintenance_window_start of this ManagementPolicy.
        The start of the maintenance window.


        :return: The maintenance_window_start of this ManagementPolicy.
        :rtype: str
        """
        return self._maintenance_window_start

    @maintenance_window_start.setter
    def maintenance_window_start(self, maintenance_window_start):
        """
        Sets the maintenance_window_start of this ManagementPolicy.
        The start of the maintenance window.


        :param maintenance_window_start: The maintenance_window_start of this ManagementPolicy.
        :type: str
        """
        self._maintenance_window_start = maintenance_window_start

    @property
    def backup_policy(self):
        """
        **[Required]** Gets the backup_policy of this ManagementPolicy.

        :return: The backup_policy of this ManagementPolicy.
        :rtype: oci.psql.models.BackupPolicy
        """
        return self._backup_policy

    @backup_policy.setter
    def backup_policy(self, backup_policy):
        """
        Sets the backup_policy of this ManagementPolicy.

        :param backup_policy: The backup_policy of this ManagementPolicy.
        :type: oci.psql.models.BackupPolicy
        """
        self._backup_policy = backup_policy

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
