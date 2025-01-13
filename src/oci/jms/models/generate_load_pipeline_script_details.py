# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210610


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class GenerateLoadPipelineScriptDetails(object):
    """
    Attributes to generate load pipeline script.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new GenerateLoadPipelineScriptDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param target_bucket_name:
            The value to assign to the target_bucket_name property of this GenerateLoadPipelineScriptDetails.
        :type target_bucket_name: str

        :param target_bucket_namespace:
            The value to assign to the target_bucket_namespace property of this GenerateLoadPipelineScriptDetails.
        :type target_bucket_namespace: str

        :param target_bucket_region:
            The value to assign to the target_bucket_region property of this GenerateLoadPipelineScriptDetails.
        :type target_bucket_region: str

        :param interval_minutes:
            The value to assign to the interval_minutes property of this GenerateLoadPipelineScriptDetails.
        :type interval_minutes: int

        """
        self.swagger_types = {
            'target_bucket_name': 'str',
            'target_bucket_namespace': 'str',
            'target_bucket_region': 'str',
            'interval_minutes': 'int'
        }

        self.attribute_map = {
            'target_bucket_name': 'targetBucketName',
            'target_bucket_namespace': 'targetBucketNamespace',
            'target_bucket_region': 'targetBucketRegion',
            'interval_minutes': 'intervalMinutes'
        }

        self._target_bucket_name = None
        self._target_bucket_namespace = None
        self._target_bucket_region = None
        self._interval_minutes = None

    @property
    def target_bucket_name(self):
        """
        **[Required]** Gets the target_bucket_name of this GenerateLoadPipelineScriptDetails.
        The name of the bucket where data will be exported.


        :return: The target_bucket_name of this GenerateLoadPipelineScriptDetails.
        :rtype: str
        """
        return self._target_bucket_name

    @target_bucket_name.setter
    def target_bucket_name(self, target_bucket_name):
        """
        Sets the target_bucket_name of this GenerateLoadPipelineScriptDetails.
        The name of the bucket where data will be exported.


        :param target_bucket_name: The target_bucket_name of this GenerateLoadPipelineScriptDetails.
        :type: str
        """
        self._target_bucket_name = target_bucket_name

    @property
    def target_bucket_namespace(self):
        """
        **[Required]** Gets the target_bucket_namespace of this GenerateLoadPipelineScriptDetails.
        The namespace of the bucket where data will be exported.


        :return: The target_bucket_namespace of this GenerateLoadPipelineScriptDetails.
        :rtype: str
        """
        return self._target_bucket_namespace

    @target_bucket_namespace.setter
    def target_bucket_namespace(self, target_bucket_namespace):
        """
        Sets the target_bucket_namespace of this GenerateLoadPipelineScriptDetails.
        The namespace of the bucket where data will be exported.


        :param target_bucket_namespace: The target_bucket_namespace of this GenerateLoadPipelineScriptDetails.
        :type: str
        """
        self._target_bucket_namespace = target_bucket_namespace

    @property
    def target_bucket_region(self):
        """
        **[Required]** Gets the target_bucket_region of this GenerateLoadPipelineScriptDetails.
        The id of the region of the target bucket.


        :return: The target_bucket_region of this GenerateLoadPipelineScriptDetails.
        :rtype: str
        """
        return self._target_bucket_region

    @target_bucket_region.setter
    def target_bucket_region(self, target_bucket_region):
        """
        Sets the target_bucket_region of this GenerateLoadPipelineScriptDetails.
        The id of the region of the target bucket.


        :param target_bucket_region: The target_bucket_region of this GenerateLoadPipelineScriptDetails.
        :type: str
        """
        self._target_bucket_region = target_bucket_region

    @property
    def interval_minutes(self):
        """
        Gets the interval_minutes of this GenerateLoadPipelineScriptDetails.
        The time internal in minutes between consecutive executions of scheduled pipeline job.


        :return: The interval_minutes of this GenerateLoadPipelineScriptDetails.
        :rtype: int
        """
        return self._interval_minutes

    @interval_minutes.setter
    def interval_minutes(self, interval_minutes):
        """
        Sets the interval_minutes of this GenerateLoadPipelineScriptDetails.
        The time internal in minutes between consecutive executions of scheduled pipeline job.


        :param interval_minutes: The interval_minutes of this GenerateLoadPipelineScriptDetails.
        :type: int
        """
        self._interval_minutes = interval_minutes

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
