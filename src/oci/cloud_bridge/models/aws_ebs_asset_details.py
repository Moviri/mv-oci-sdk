# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220509


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AwsEbsAssetDetails(object):
    """
    AWS EBS type of asset.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new AwsEbsAssetDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param aws_ebs:
            The value to assign to the aws_ebs property of this AwsEbsAssetDetails.
        :type aws_ebs: oci.cloud_bridge.models.AwsEbsProperties

        """
        self.swagger_types = {
            'aws_ebs': 'AwsEbsProperties'
        }

        self.attribute_map = {
            'aws_ebs': 'awsEbs'
        }

        self._aws_ebs = None

    @property
    def aws_ebs(self):
        """
        **[Required]** Gets the aws_ebs of this AwsEbsAssetDetails.

        :return: The aws_ebs of this AwsEbsAssetDetails.
        :rtype: oci.cloud_bridge.models.AwsEbsProperties
        """
        return self._aws_ebs

    @aws_ebs.setter
    def aws_ebs(self, aws_ebs):
        """
        Sets the aws_ebs of this AwsEbsAssetDetails.

        :param aws_ebs: The aws_ebs of this AwsEbsAssetDetails.
        :type: oci.cloud_bridge.models.AwsEbsProperties
        """
        self._aws_ebs = aws_ebs

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
