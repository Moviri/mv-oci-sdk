# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210201


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class TestDetails(object):
    """
    The request body used to execute a test.
    """

    #: A constant which can be used with the test_type property of a TestDetails.
    #: This constant has a value of "SPAN_ENRICHMENT"
    TEST_TYPE_SPAN_ENRICHMENT = "SPAN_ENRICHMENT"

    def __init__(self, **kwargs):
        """
        Initializes a new TestDetails object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.apm_config.models.TestSpanEnrichmentDetails`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param test_type:
            The value to assign to the test_type property of this TestDetails.
            Allowed values for this property are: "SPAN_ENRICHMENT"
        :type test_type: str

        """
        self.swagger_types = {
            'test_type': 'str'
        }

        self.attribute_map = {
            'test_type': 'testType'
        }

        self._test_type = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['testType']

        if type == 'SPAN_ENRICHMENT':
            return 'TestSpanEnrichmentDetails'
        else:
            return 'TestDetails'

    @property
    def test_type(self):
        """
        **[Required]** Gets the test_type of this TestDetails.
        The kind of test to run.

        Allowed values for this property are: "SPAN_ENRICHMENT"


        :return: The test_type of this TestDetails.
        :rtype: str
        """
        return self._test_type

    @test_type.setter
    def test_type(self, test_type):
        """
        Sets the test_type of this TestDetails.
        The kind of test to run.


        :param test_type: The test_type of this TestDetails.
        :type: str
        """
        allowed_values = ["SPAN_ENRICHMENT"]
        if not value_allowed_none_or_none_sentinel(test_type, allowed_values):
            raise ValueError(
                f"Invalid value for `test_type`, must be None or one of {allowed_values}"
            )
        self._test_type = test_type

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
