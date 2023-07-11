# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20201101


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ChangePlanRetentionDetails(object):
    """
    The details required to change the plan retention period.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ChangePlanRetentionDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param retention_weeks:
            The value to assign to the retention_weeks property of this ChangePlanRetentionDetails.
        :type retention_weeks: int

        :param credentials:
            The value to assign to the credentials property of this ChangePlanRetentionDetails.
        :type credentials: oci.database_management.models.ManagedDatabaseCredential

        """
        self.swagger_types = {
            'retention_weeks': 'int',
            'credentials': 'ManagedDatabaseCredential'
        }

        self.attribute_map = {
            'retention_weeks': 'retentionWeeks',
            'credentials': 'credentials'
        }

        self._retention_weeks = None
        self._credentials = None

    @property
    def retention_weeks(self):
        """
        **[Required]** Gets the retention_weeks of this ChangePlanRetentionDetails.
        The retention period in weeks. It can range between 5 and 523 weeks.


        :return: The retention_weeks of this ChangePlanRetentionDetails.
        :rtype: int
        """
        return self._retention_weeks

    @retention_weeks.setter
    def retention_weeks(self, retention_weeks):
        """
        Sets the retention_weeks of this ChangePlanRetentionDetails.
        The retention period in weeks. It can range between 5 and 523 weeks.


        :param retention_weeks: The retention_weeks of this ChangePlanRetentionDetails.
        :type: int
        """
        self._retention_weeks = retention_weeks

    @property
    def credentials(self):
        """
        **[Required]** Gets the credentials of this ChangePlanRetentionDetails.

        :return: The credentials of this ChangePlanRetentionDetails.
        :rtype: oci.database_management.models.ManagedDatabaseCredential
        """
        return self._credentials

    @credentials.setter
    def credentials(self, credentials):
        """
        Sets the credentials of this ChangePlanRetentionDetails.

        :param credentials: The credentials of this ChangePlanRetentionDetails.
        :type: oci.database_management.models.ManagedDatabaseCredential
        """
        self._credentials = credentials

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other