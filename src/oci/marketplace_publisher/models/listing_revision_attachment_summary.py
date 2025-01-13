# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220901


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ListingRevisionAttachmentSummary(object):
    """
    The model for a summary of a listing revision related attachments.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ListingRevisionAttachmentSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ListingRevisionAttachmentSummary.
        :type id: str

        :param listing_revision_id:
            The value to assign to the listing_revision_id property of this ListingRevisionAttachmentSummary.
        :type listing_revision_id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ListingRevisionAttachmentSummary.
        :type compartment_id: str

        :param display_name:
            The value to assign to the display_name property of this ListingRevisionAttachmentSummary.
        :type display_name: str

        :param attachment_type:
            The value to assign to the attachment_type property of this ListingRevisionAttachmentSummary.
        :type attachment_type: str

        :param content_url:
            The value to assign to the content_url property of this ListingRevisionAttachmentSummary.
        :type content_url: str

        :param mime_type:
            The value to assign to the mime_type property of this ListingRevisionAttachmentSummary.
        :type mime_type: str

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ListingRevisionAttachmentSummary.
        :type lifecycle_state: str

        :param time_created:
            The value to assign to the time_created property of this ListingRevisionAttachmentSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this ListingRevisionAttachmentSummary.
        :type time_updated: datetime

        :param freeform_tags:
            The value to assign to the freeform_tags property of this ListingRevisionAttachmentSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this ListingRevisionAttachmentSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this ListingRevisionAttachmentSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'listing_revision_id': 'str',
            'compartment_id': 'str',
            'display_name': 'str',
            'attachment_type': 'str',
            'content_url': 'str',
            'mime_type': 'str',
            'lifecycle_state': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'listing_revision_id': 'listingRevisionId',
            'compartment_id': 'compartmentId',
            'display_name': 'displayName',
            'attachment_type': 'attachmentType',
            'content_url': 'contentUrl',
            'mime_type': 'mimeType',
            'lifecycle_state': 'lifecycleState',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._listing_revision_id = None
        self._compartment_id = None
        self._display_name = None
        self._attachment_type = None
        self._content_url = None
        self._mime_type = None
        self._lifecycle_state = None
        self._time_created = None
        self._time_updated = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ListingRevisionAttachmentSummary.
        The OCID of the listing revision attachment.


        :return: The id of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ListingRevisionAttachmentSummary.
        The OCID of the listing revision attachment.


        :param id: The id of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._id = id

    @property
    def listing_revision_id(self):
        """
        **[Required]** Gets the listing_revision_id of this ListingRevisionAttachmentSummary.
        The ID of the listing revision.


        :return: The listing_revision_id of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._listing_revision_id

    @listing_revision_id.setter
    def listing_revision_id(self, listing_revision_id):
        """
        Sets the listing_revision_id of this ListingRevisionAttachmentSummary.
        The ID of the listing revision.


        :param listing_revision_id: The listing_revision_id of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._listing_revision_id = listing_revision_id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ListingRevisionAttachmentSummary.
        The unique identifier for the compartment.


        :return: The compartment_id of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ListingRevisionAttachmentSummary.
        The unique identifier for the compartment.


        :param compartment_id: The compartment_id of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this ListingRevisionAttachmentSummary.
        The name of the specified document.


        :return: The display_name of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ListingRevisionAttachmentSummary.
        The name of the specified document.


        :param display_name: The display_name of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def attachment_type(self):
        """
        **[Required]** Gets the attachment_type of this ListingRevisionAttachmentSummary.
        The specified attachment type.


        :return: The attachment_type of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._attachment_type

    @attachment_type.setter
    def attachment_type(self, attachment_type):
        """
        Sets the attachment_type of this ListingRevisionAttachmentSummary.
        The specified attachment type.


        :param attachment_type: The attachment_type of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._attachment_type = attachment_type

    @property
    def content_url(self):
        """
        **[Required]** Gets the content_url of this ListingRevisionAttachmentSummary.
        The URL of the specified attachment.


        :return: The content_url of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._content_url

    @content_url.setter
    def content_url(self, content_url):
        """
        Sets the content_url of this ListingRevisionAttachmentSummary.
        The URL of the specified attachment.


        :param content_url: The content_url of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._content_url = content_url

    @property
    def mime_type(self):
        """
        Gets the mime_type of this ListingRevisionAttachmentSummary.
        The MIME type of the screenshot.


        :return: The mime_type of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._mime_type

    @mime_type.setter
    def mime_type(self, mime_type):
        """
        Sets the mime_type of this ListingRevisionAttachmentSummary.
        The MIME type of the screenshot.


        :param mime_type: The mime_type of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._mime_type = mime_type

    @property
    def lifecycle_state(self):
        """
        Gets the lifecycle_state of this ListingRevisionAttachmentSummary.
        The current state of the document.


        :return: The lifecycle_state of this ListingRevisionAttachmentSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ListingRevisionAttachmentSummary.
        The current state of the document.


        :param lifecycle_state: The lifecycle_state of this ListingRevisionAttachmentSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this ListingRevisionAttachmentSummary.
        The date and time the related document was created, expressed in `RFC 3339`__
        timestamp format.

        Example: `2022-09-24T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_created of this ListingRevisionAttachmentSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ListingRevisionAttachmentSummary.
        The date and time the related document was created, expressed in `RFC 3339`__
        timestamp format.

        Example: `2022-09-24T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_created: The time_created of this ListingRevisionAttachmentSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        **[Required]** Gets the time_updated of this ListingRevisionAttachmentSummary.
        The date and time the related document was updated, expressed in `RFC 3339`__
        timestamp format.

        Example: `2022-09-24T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_updated of this ListingRevisionAttachmentSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this ListingRevisionAttachmentSummary.
        The date and time the related document was updated, expressed in `RFC 3339`__
        timestamp format.

        Example: `2022-09-24T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_updated: The time_updated of this ListingRevisionAttachmentSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this ListingRevisionAttachmentSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :return: The freeform_tags of this ListingRevisionAttachmentSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this ListingRevisionAttachmentSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :param freeform_tags: The freeform_tags of this ListingRevisionAttachmentSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this ListingRevisionAttachmentSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this ListingRevisionAttachmentSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this ListingRevisionAttachmentSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this ListingRevisionAttachmentSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this ListingRevisionAttachmentSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this ListingRevisionAttachmentSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this ListingRevisionAttachmentSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this ListingRevisionAttachmentSummary.
        :type: dict(str, dict(str, object))
        """
        self._system_tags = system_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
