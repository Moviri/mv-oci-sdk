# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DrgRouteDistributionMatchCriteria(object):
    """
    The match criteria in a route distribution statement. The match criteria outlines which routes
    should be imported or exported.
    """

    #: A constant which can be used with the match_type property of a DrgRouteDistributionMatchCriteria.
    #: This constant has a value of "DRG_ATTACHMENT_TYPE"
    MATCH_TYPE_DRG_ATTACHMENT_TYPE = "DRG_ATTACHMENT_TYPE"

    #: A constant which can be used with the match_type property of a DrgRouteDistributionMatchCriteria.
    #: This constant has a value of "DRG_ATTACHMENT_ID"
    MATCH_TYPE_DRG_ATTACHMENT_ID = "DRG_ATTACHMENT_ID"

    #: A constant which can be used with the match_type property of a DrgRouteDistributionMatchCriteria.
    #: This constant has a value of "MATCH_ALL"
    MATCH_TYPE_MATCH_ALL = "MATCH_ALL"

    def __init__(self, **kwargs):
        """
        Initializes a new DrgRouteDistributionMatchCriteria object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.vn_monitoring.models.DrgAttachmentIdDrgRouteDistributionMatchCriteria`
        * :class:`~oci.vn_monitoring.models.DrgAttachmentTypeDrgRouteDistributionMatchCriteria`
        * :class:`~oci.vn_monitoring.models.DrgAttachmentMatchAllDrgRouteDistributionMatchCriteria`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param match_type:
            The value to assign to the match_type property of this DrgRouteDistributionMatchCriteria.
            Allowed values for this property are: "DRG_ATTACHMENT_TYPE", "DRG_ATTACHMENT_ID", "MATCH_ALL"
        :type match_type: str

        """
        self.swagger_types = {
            'match_type': 'str'
        }

        self.attribute_map = {
            'match_type': 'matchType'
        }

        self._match_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['matchType']

        if type == 'DRG_ATTACHMENT_ID':
            return 'DrgAttachmentIdDrgRouteDistributionMatchCriteria'

        if type == 'DRG_ATTACHMENT_TYPE':
            return 'DrgAttachmentTypeDrgRouteDistributionMatchCriteria'

        if type == 'MATCH_ALL':
            return 'DrgAttachmentMatchAllDrgRouteDistributionMatchCriteria'
        else:
            return 'DrgRouteDistributionMatchCriteria'

    @property
    def match_type(self):
        """
        **[Required]** Gets the match_type of this DrgRouteDistributionMatchCriteria.
        The type of the match criteria for a route distribution statement.

        Allowed values for this property are: "DRG_ATTACHMENT_TYPE", "DRG_ATTACHMENT_ID", "MATCH_ALL"


        :return: The match_type of this DrgRouteDistributionMatchCriteria.
        :rtype: str
        """
        return self._match_type

    @match_type.setter
    def match_type(self, match_type):
        """
        Sets the match_type of this DrgRouteDistributionMatchCriteria.
        The type of the match criteria for a route distribution statement.


        :param match_type: The match_type of this DrgRouteDistributionMatchCriteria.
        :type: str
        """
        allowed_values = ["DRG_ATTACHMENT_TYPE", "DRG_ATTACHMENT_ID", "MATCH_ALL"]
        if not value_allowed_none_or_none_sentinel(match_type, allowed_values):
            raise ValueError(
                f"Invalid value for `match_type`, must be None or one of {allowed_values}"
            )
        self._match_type = match_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
