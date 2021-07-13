# coding: utf-8
# Copyright (c) 2016, 2021, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreatePublicationDetails(object):
    """
    The model for the parameters needed to create a publication.
    """

    #: A constant which can be used with the listing_type property of a CreatePublicationDetails.
    #: This constant has a value of "COMMUNITY"
    LISTING_TYPE_COMMUNITY = "COMMUNITY"

    #: A constant which can be used with the listing_type property of a CreatePublicationDetails.
    #: This constant has a value of "PARTNER"
    LISTING_TYPE_PARTNER = "PARTNER"

    #: A constant which can be used with the listing_type property of a CreatePublicationDetails.
    #: This constant has a value of "PRIVATE"
    LISTING_TYPE_PRIVATE = "PRIVATE"

    def __init__(self, **kwargs):
        """
        Initializes a new CreatePublicationDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param listing_type:
            The value to assign to the listing_type property of this CreatePublicationDetails.
            Allowed values for this property are: "COMMUNITY", "PARTNER", "PRIVATE"
        :type listing_type: str

        :param name:
            The value to assign to the name property of this CreatePublicationDetails.
        :type name: str

        :param short_description:
            The value to assign to the short_description property of this CreatePublicationDetails.
        :type short_description: str

        :param long_description:
            The value to assign to the long_description property of this CreatePublicationDetails.
        :type long_description: str

        :param support_contacts:
            The value to assign to the support_contacts property of this CreatePublicationDetails.
        :type support_contacts: list[oci.marketplace.models.SupportContact]

        :param compartment_id:
            The value to assign to the compartment_id property of this CreatePublicationDetails.
        :type compartment_id: str

        :param package_details:
            The value to assign to the package_details property of this CreatePublicationDetails.
        :type package_details: oci.marketplace.models.CreatePublicationPackage

        :param is_agreement_acknowledged:
            The value to assign to the is_agreement_acknowledged property of this CreatePublicationDetails.
        :type is_agreement_acknowledged: bool

        :param defined_tags:
            The value to assign to the defined_tags property of this CreatePublicationDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreatePublicationDetails.
        :type freeform_tags: dict(str, str)

        """
        self.swagger_types = {
            'listing_type': 'str',
            'name': 'str',
            'short_description': 'str',
            'long_description': 'str',
            'support_contacts': 'list[SupportContact]',
            'compartment_id': 'str',
            'package_details': 'CreatePublicationPackage',
            'is_agreement_acknowledged': 'bool',
            'defined_tags': 'dict(str, dict(str, object))',
            'freeform_tags': 'dict(str, str)'
        }

        self.attribute_map = {
            'listing_type': 'listingType',
            'name': 'name',
            'short_description': 'shortDescription',
            'long_description': 'longDescription',
            'support_contacts': 'supportContacts',
            'compartment_id': 'compartmentId',
            'package_details': 'packageDetails',
            'is_agreement_acknowledged': 'isAgreementAcknowledged',
            'defined_tags': 'definedTags',
            'freeform_tags': 'freeformTags'
        }

        self._listing_type = None
        self._name = None
        self._short_description = None
        self._long_description = None
        self._support_contacts = None
        self._compartment_id = None
        self._package_details = None
        self._is_agreement_acknowledged = None
        self._defined_tags = None
        self._freeform_tags = None

    @property
    def listing_type(self):
        """
        **[Required]** Gets the listing_type of this CreatePublicationDetails.
        The publisher category to which the publication belongs. The publisher category informs where the listing appears for use.

        Allowed values for this property are: "COMMUNITY", "PARTNER", "PRIVATE"


        :return: The listing_type of this CreatePublicationDetails.
        :rtype: str
        """
        return self._listing_type

    @listing_type.setter
    def listing_type(self, listing_type):
        """
        Sets the listing_type of this CreatePublicationDetails.
        The publisher category to which the publication belongs. The publisher category informs where the listing appears for use.


        :param listing_type: The listing_type of this CreatePublicationDetails.
        :type: str
        """
        allowed_values = ["COMMUNITY", "PARTNER", "PRIVATE"]
        if not value_allowed_none_or_none_sentinel(listing_type, allowed_values):
            raise ValueError(
                "Invalid value for `listing_type`, must be None or one of {0}"
                .format(allowed_values)
            )
        self._listing_type = listing_type

    @property
    def name(self):
        """
        **[Required]** Gets the name of this CreatePublicationDetails.
        The name of the publication, which is also used in the listing.


        :return: The name of this CreatePublicationDetails.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this CreatePublicationDetails.
        The name of the publication, which is also used in the listing.


        :param name: The name of this CreatePublicationDetails.
        :type: str
        """
        self._name = name

    @property
    def short_description(self):
        """
        **[Required]** Gets the short_description of this CreatePublicationDetails.
        A short description of the publication to use in the listing.


        :return: The short_description of this CreatePublicationDetails.
        :rtype: str
        """
        return self._short_description

    @short_description.setter
    def short_description(self, short_description):
        """
        Sets the short_description of this CreatePublicationDetails.
        A short description of the publication to use in the listing.


        :param short_description: The short_description of this CreatePublicationDetails.
        :type: str
        """
        self._short_description = short_description

    @property
    def long_description(self):
        """
        Gets the long_description of this CreatePublicationDetails.
        A long description of the publication to use in the listing.


        :return: The long_description of this CreatePublicationDetails.
        :rtype: str
        """
        return self._long_description

    @long_description.setter
    def long_description(self, long_description):
        """
        Sets the long_description of this CreatePublicationDetails.
        A long description of the publication to use in the listing.


        :param long_description: The long_description of this CreatePublicationDetails.
        :type: str
        """
        self._long_description = long_description

    @property
    def support_contacts(self):
        """
        **[Required]** Gets the support_contacts of this CreatePublicationDetails.
        Contact information for getting support from the publisher for the listing.


        :return: The support_contacts of this CreatePublicationDetails.
        :rtype: list[oci.marketplace.models.SupportContact]
        """
        return self._support_contacts

    @support_contacts.setter
    def support_contacts(self, support_contacts):
        """
        Sets the support_contacts of this CreatePublicationDetails.
        Contact information for getting support from the publisher for the listing.


        :param support_contacts: The support_contacts of this CreatePublicationDetails.
        :type: list[oci.marketplace.models.SupportContact]
        """
        self._support_contacts = support_contacts

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreatePublicationDetails.
        The `OCID`__ of the compartment where you want to create the publication.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this CreatePublicationDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreatePublicationDetails.
        The `OCID`__ of the compartment where you want to create the publication.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this CreatePublicationDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def package_details(self):
        """
        **[Required]** Gets the package_details of this CreatePublicationDetails.

        :return: The package_details of this CreatePublicationDetails.
        :rtype: oci.marketplace.models.CreatePublicationPackage
        """
        return self._package_details

    @package_details.setter
    def package_details(self, package_details):
        """
        Sets the package_details of this CreatePublicationDetails.

        :param package_details: The package_details of this CreatePublicationDetails.
        :type: oci.marketplace.models.CreatePublicationPackage
        """
        self._package_details = package_details

    @property
    def is_agreement_acknowledged(self):
        """
        **[Required]** Gets the is_agreement_acknowledged of this CreatePublicationDetails.
        Whether the publisher acknowledged that they have the right and authority to share the contents of the publication and that they accepted the Oracle terms of use agreements required to create a publication.


        :return: The is_agreement_acknowledged of this CreatePublicationDetails.
        :rtype: bool
        """
        return self._is_agreement_acknowledged

    @is_agreement_acknowledged.setter
    def is_agreement_acknowledged(self, is_agreement_acknowledged):
        """
        Sets the is_agreement_acknowledged of this CreatePublicationDetails.
        Whether the publisher acknowledged that they have the right and authority to share the contents of the publication and that they accepted the Oracle terms of use agreements required to create a publication.


        :param is_agreement_acknowledged: The is_agreement_acknowledged of this CreatePublicationDetails.
        :type: bool
        """
        self._is_agreement_acknowledged = is_agreement_acknowledged

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreatePublicationDetails.
        The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this CreatePublicationDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreatePublicationDetails.
        The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this CreatePublicationDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreatePublicationDetails.
        The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no
        predefined name, type, or namespace. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this CreatePublicationDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreatePublicationDetails.
        The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no
        predefined name, type, or namespace. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this CreatePublicationDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
