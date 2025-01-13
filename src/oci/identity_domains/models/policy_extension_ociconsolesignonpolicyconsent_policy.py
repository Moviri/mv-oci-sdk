# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: v1


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class PolicyExtensionOciconsolesignonpolicyconsentPolicy(object):
    """
    This extension defines attributes used to record consent for modification of the \"Security Policy for OCI Console\" sign-on policy, Rule, Condition or ConditionGroup.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new PolicyExtensionOciconsolesignonpolicyconsentPolicy object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param consent:
            The value to assign to the consent property of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :type consent: bool

        :param justification:
            The value to assign to the justification property of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :type justification: str

        :param reason:
            The value to assign to the reason property of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :type reason: str

        """
        self.swagger_types = {
            'consent': 'bool',
            'justification': 'str',
            'reason': 'str'
        }

        self.attribute_map = {
            'consent': 'consent',
            'justification': 'justification',
            'reason': 'reason'
        }

        self._consent = None
        self._justification = None
        self._reason = None

    @property
    def consent(self):
        """
        Gets the consent of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        Set to true when an identity domain administrator opts to change the Oracle security defaults for the \"Security Policy for OCI Console\" shipped by Oracle. Defaults to false.

        **Added In:** 2405220110

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: boolean


        :return: The consent of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :rtype: bool
        """
        return self._consent

    @consent.setter
    def consent(self, consent):
        """
        Sets the consent of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        Set to true when an identity domain administrator opts to change the Oracle security defaults for the \"Security Policy for OCI Console\" shipped by Oracle. Defaults to false.

        **Added In:** 2405220110

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: boolean


        :param consent: The consent of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :type: bool
        """
        self._consent = consent

    @property
    def justification(self):
        """
        Gets the justification of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        The justification for the change when an identity domain administrator opts to modify the Oracle security defaults for the \"Security Policy for OCI Console\" sign-on policy shipped by Oracle.

        **Added In:** 2405220110

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: string


        :return: The justification of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :rtype: str
        """
        return self._justification

    @justification.setter
    def justification(self, justification):
        """
        Sets the justification of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        The justification for the change when an identity domain administrator opts to modify the Oracle security defaults for the \"Security Policy for OCI Console\" sign-on policy shipped by Oracle.

        **Added In:** 2405220110

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: string


        :param justification: The justification of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :type: str
        """
        self._justification = justification

    @property
    def reason(self):
        """
        Gets the reason of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        The detailed reason for the change when an identity domain administrator opts to modify the Oracle security defaults for the \"Security Policy for OCI Console\" sign-on policy shipped by Oracle.

        **Added In:** 2405220110

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: string


        :return: The reason of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :rtype: str
        """
        return self._reason

    @reason.setter
    def reason(self, reason):
        """
        Sets the reason of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        The detailed reason for the change when an identity domain administrator opts to modify the Oracle security defaults for the \"Security Policy for OCI Console\" sign-on policy shipped by Oracle.

        **Added In:** 2405220110

        **SCIM++ Properties:**
         - idcsSearchable: false
         - multiValued: false
         - mutability: writeOnly
         - required: false
         - returned: never
         - type: string


        :param reason: The reason of this PolicyExtensionOciconsolesignonpolicyconsentPolicy.
        :type: str
        """
        self._reason = reason

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
