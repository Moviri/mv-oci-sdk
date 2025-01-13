# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200131


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AdhocQueryRegionalDetails(object):
    """
    Instance level status for each region.
    """

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "CREATING"
    REGIONAL_STATUS_CREATING = "CREATING"

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "CREATED"
    REGIONAL_STATUS_CREATED = "CREATED"

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "IN_PROGRESS"
    REGIONAL_STATUS_IN_PROGRESS = "IN_PROGRESS"

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "PARTIALLY_COMPLETED"
    REGIONAL_STATUS_PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "EXPIRED"
    REGIONAL_STATUS_EXPIRED = "EXPIRED"

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "COMPLETED"
    REGIONAL_STATUS_COMPLETED = "COMPLETED"

    #: A constant which can be used with the regional_status property of a AdhocQueryRegionalDetails.
    #: This constant has a value of "FAILED"
    REGIONAL_STATUS_FAILED = "FAILED"

    def __init__(self, **kwargs):
        """
        Initializes a new AdhocQueryRegionalDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param region:
            The value to assign to the region property of this AdhocQueryRegionalDetails.
        :type region: str

        :param regional_status:
            The value to assign to the regional_status property of this AdhocQueryRegionalDetails.
            Allowed values for this property are: "CREATING", "CREATED", "IN_PROGRESS", "PARTIALLY_COMPLETED", "EXPIRED", "COMPLETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type regional_status: str

        :param regional_error:
            The value to assign to the regional_error property of this AdhocQueryRegionalDetails.
        :type regional_error: str

        :param expected_count:
            The value to assign to the expected_count property of this AdhocQueryRegionalDetails.
        :type expected_count: str

        :param failed_count:
            The value to assign to the failed_count property of this AdhocQueryRegionalDetails.
        :type failed_count: str

        :param succeeded_count:
            The value to assign to the succeeded_count property of this AdhocQueryRegionalDetails.
        :type succeeded_count: str

        :param expired_count:
            The value to assign to the expired_count property of this AdhocQueryRegionalDetails.
        :type expired_count: str

        """
        self.swagger_types = {
            'region': 'str',
            'regional_status': 'str',
            'regional_error': 'str',
            'expected_count': 'str',
            'failed_count': 'str',
            'succeeded_count': 'str',
            'expired_count': 'str'
        }

        self.attribute_map = {
            'region': 'region',
            'regional_status': 'regionalStatus',
            'regional_error': 'regionalError',
            'expected_count': 'expectedCount',
            'failed_count': 'failedCount',
            'succeeded_count': 'succeededCount',
            'expired_count': 'expiredCount'
        }

        self._region = None
        self._regional_status = None
        self._regional_error = None
        self._expected_count = None
        self._failed_count = None
        self._succeeded_count = None
        self._expired_count = None

    @property
    def region(self):
        """
        **[Required]** Gets the region of this AdhocQueryRegionalDetails.
        Region name


        :return: The region of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._region

    @region.setter
    def region(self, region):
        """
        Sets the region of this AdhocQueryRegionalDetails.
        Region name


        :param region: The region of this AdhocQueryRegionalDetails.
        :type: str
        """
        self._region = region

    @property
    def regional_status(self):
        """
        Gets the regional_status of this AdhocQueryRegionalDetails.
        adhoc query status of the region

        Allowed values for this property are: "CREATING", "CREATED", "IN_PROGRESS", "PARTIALLY_COMPLETED", "EXPIRED", "COMPLETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The regional_status of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._regional_status

    @regional_status.setter
    def regional_status(self, regional_status):
        """
        Sets the regional_status of this AdhocQueryRegionalDetails.
        adhoc query status of the region


        :param regional_status: The regional_status of this AdhocQueryRegionalDetails.
        :type: str
        """
        allowed_values = ["CREATING", "CREATED", "IN_PROGRESS", "PARTIALLY_COMPLETED", "EXPIRED", "COMPLETED", "FAILED"]
        if not value_allowed_none_or_none_sentinel(regional_status, allowed_values):
            regional_status = 'UNKNOWN_ENUM_VALUE'
        self._regional_status = regional_status

    @property
    def regional_error(self):
        """
        Gets the regional_error of this AdhocQueryRegionalDetails.
        error message to show if adhoc query fails in a region


        :return: The regional_error of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._regional_error

    @regional_error.setter
    def regional_error(self, regional_error):
        """
        Sets the regional_error of this AdhocQueryRegionalDetails.
        error message to show if adhoc query fails in a region


        :param regional_error: The regional_error of this AdhocQueryRegionalDetails.
        :type: str
        """
        self._regional_error = regional_error

    @property
    def expected_count(self):
        """
        Gets the expected_count of this AdhocQueryRegionalDetails.
        Expected number of instances on which query should run


        :return: The expected_count of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._expected_count

    @expected_count.setter
    def expected_count(self, expected_count):
        """
        Sets the expected_count of this AdhocQueryRegionalDetails.
        Expected number of instances on which query should run


        :param expected_count: The expected_count of this AdhocQueryRegionalDetails.
        :type: str
        """
        self._expected_count = expected_count

    @property
    def failed_count(self):
        """
        Gets the failed_count of this AdhocQueryRegionalDetails.
        Number of instances on which query failed


        :return: The failed_count of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._failed_count

    @failed_count.setter
    def failed_count(self, failed_count):
        """
        Sets the failed_count of this AdhocQueryRegionalDetails.
        Number of instances on which query failed


        :param failed_count: The failed_count of this AdhocQueryRegionalDetails.
        :type: str
        """
        self._failed_count = failed_count

    @property
    def succeeded_count(self):
        """
        Gets the succeeded_count of this AdhocQueryRegionalDetails.
        Number of instances on which query succeeded


        :return: The succeeded_count of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._succeeded_count

    @succeeded_count.setter
    def succeeded_count(self, succeeded_count):
        """
        Sets the succeeded_count of this AdhocQueryRegionalDetails.
        Number of instances on which query succeeded


        :param succeeded_count: The succeeded_count of this AdhocQueryRegionalDetails.
        :type: str
        """
        self._succeeded_count = succeeded_count

    @property
    def expired_count(self):
        """
        Gets the expired_count of this AdhocQueryRegionalDetails.
        Number of instances on which query expired


        :return: The expired_count of this AdhocQueryRegionalDetails.
        :rtype: str
        """
        return self._expired_count

    @expired_count.setter
    def expired_count(self, expired_count):
        """
        Sets the expired_count of this AdhocQueryRegionalDetails.
        Number of instances on which query expired


        :param expired_count: The expired_count of this AdhocQueryRegionalDetails.
        :type: str
        """
        self._expired_count = expired_count

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
