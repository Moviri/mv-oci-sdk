# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: v1


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ExtensionTermsOfUseUser(object):
    """
    Terms Of Use extension
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ExtensionTermsOfUseUser object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param terms_of_use_consents:
            The value to assign to the terms_of_use_consents property of this ExtensionTermsOfUseUser.
        :type terms_of_use_consents: list[oci.identity_domains.models.UserExtTermsOfUseConsents]

        """
        self.swagger_types = {
            'terms_of_use_consents': 'list[UserExtTermsOfUseConsents]'
        }

        self.attribute_map = {
            'terms_of_use_consents': 'termsOfUseConsents'
        }

        self._terms_of_use_consents = None

    @property
    def terms_of_use_consents(self):
        """
        Gets the terms_of_use_consents of this ExtensionTermsOfUseUser.
        Description:

        **Added In:** 18.2.6

        **SCIM++ Properties:**
         - idcsCompositeKey: [value]
         - idcsSearchable: true
         - multiValued: true
         - mutability: readWrite
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :return: The terms_of_use_consents of this ExtensionTermsOfUseUser.
        :rtype: list[oci.identity_domains.models.UserExtTermsOfUseConsents]
        """
        return self._terms_of_use_consents

    @terms_of_use_consents.setter
    def terms_of_use_consents(self, terms_of_use_consents):
        """
        Sets the terms_of_use_consents of this ExtensionTermsOfUseUser.
        Description:

        **Added In:** 18.2.6

        **SCIM++ Properties:**
         - idcsCompositeKey: [value]
         - idcsSearchable: true
         - multiValued: true
         - mutability: readWrite
         - required: false
         - returned: request
         - type: complex
         - uniqueness: none


        :param terms_of_use_consents: The terms_of_use_consents of this ExtensionTermsOfUseUser.
        :type: list[oci.identity_domains.models.UserExtTermsOfUseConsents]
        """
        self._terms_of_use_consents = terms_of_use_consents

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
