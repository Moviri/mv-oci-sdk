# coding: utf-8
# Copyright (c) 2016, 2021, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class DatabaseSoftwareImageSummary(object):
    """
    The Database service supports the creation of database software images for use in creating and patching DB systems and databases.

    To use any of the API operations, you must be authorized in an IAM policy. If you are not authorized, talk to an administrator. If you are an administrator who needs to write policies to give users access, see `Getting Started with Policies`__.

    For information about access control and compartments, see `Overview of the Identity Service`__.

    **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.

    __ https://docs.cloud.oracle.com/Content/Identity/Concepts/policygetstarted.htm
    __ https://docs.cloud.oracle.com/Content/Identity/Concepts/overview.htm
    """

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "PROVISIONING"
    LIFECYCLE_STATE_PROVISIONING = "PROVISIONING"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "AVAILABLE"
    LIFECYCLE_STATE_AVAILABLE = "AVAILABLE"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "DELETING"
    LIFECYCLE_STATE_DELETING = "DELETING"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "FAILED"
    LIFECYCLE_STATE_FAILED = "FAILED"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "TERMINATING"
    LIFECYCLE_STATE_TERMINATING = "TERMINATING"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "TERMINATED"
    LIFECYCLE_STATE_TERMINATED = "TERMINATED"

    #: A constant which can be used with the lifecycle_state property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "UPDATING"
    LIFECYCLE_STATE_UPDATING = "UPDATING"

    #: A constant which can be used with the image_type property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "GRID_IMAGE"
    IMAGE_TYPE_GRID_IMAGE = "GRID_IMAGE"

    #: A constant which can be used with the image_type property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "DATABASE_IMAGE"
    IMAGE_TYPE_DATABASE_IMAGE = "DATABASE_IMAGE"

    #: A constant which can be used with the image_shape_family property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "VM_BM_SHAPE"
    IMAGE_SHAPE_FAMILY_VM_BM_SHAPE = "VM_BM_SHAPE"

    #: A constant which can be used with the image_shape_family property of a DatabaseSoftwareImageSummary.
    #: This constant has a value of "EXADATA_SHAPE"
    IMAGE_SHAPE_FAMILY_EXADATA_SHAPE = "EXADATA_SHAPE"

    def __init__(self, **kwargs):
        """
        Initializes a new DatabaseSoftwareImageSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this DatabaseSoftwareImageSummary.
        :type id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this DatabaseSoftwareImageSummary.
        :type compartment_id: str

        :param database_version:
            The value to assign to the database_version property of this DatabaseSoftwareImageSummary.
        :type database_version: str

        :param display_name:
            The value to assign to the display_name property of this DatabaseSoftwareImageSummary.
        :type display_name: str

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this DatabaseSoftwareImageSummary.
            Allowed values for this property are: "PROVISIONING", "AVAILABLE", "DELETING", "DELETED", "FAILED", "TERMINATING", "TERMINATED", "UPDATING", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this DatabaseSoftwareImageSummary.
        :type lifecycle_details: str

        :param time_created:
            The value to assign to the time_created property of this DatabaseSoftwareImageSummary.
        :type time_created: datetime

        :param image_type:
            The value to assign to the image_type property of this DatabaseSoftwareImageSummary.
            Allowed values for this property are: "GRID_IMAGE", "DATABASE_IMAGE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type image_type: str

        :param image_shape_family:
            The value to assign to the image_shape_family property of this DatabaseSoftwareImageSummary.
            Allowed values for this property are: "VM_BM_SHAPE", "EXADATA_SHAPE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type image_shape_family: str

        :param patch_set:
            The value to assign to the patch_set property of this DatabaseSoftwareImageSummary.
        :type patch_set: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this DatabaseSoftwareImageSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this DatabaseSoftwareImageSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param database_software_image_included_patches:
            The value to assign to the database_software_image_included_patches property of this DatabaseSoftwareImageSummary.
        :type database_software_image_included_patches: list[str]

        :param included_patches_summary:
            The value to assign to the included_patches_summary property of this DatabaseSoftwareImageSummary.
        :type included_patches_summary: str

        :param database_software_image_one_off_patches:
            The value to assign to the database_software_image_one_off_patches property of this DatabaseSoftwareImageSummary.
        :type database_software_image_one_off_patches: list[str]

        :param ls_inventory:
            The value to assign to the ls_inventory property of this DatabaseSoftwareImageSummary.
        :type ls_inventory: str

        :param is_upgrade_supported:
            The value to assign to the is_upgrade_supported property of this DatabaseSoftwareImageSummary.
        :type is_upgrade_supported: bool

        """
        self.swagger_types = {
            'id': 'str',
            'compartment_id': 'str',
            'database_version': 'str',
            'display_name': 'str',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'time_created': 'datetime',
            'image_type': 'str',
            'image_shape_family': 'str',
            'patch_set': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'database_software_image_included_patches': 'list[str]',
            'included_patches_summary': 'str',
            'database_software_image_one_off_patches': 'list[str]',
            'ls_inventory': 'str',
            'is_upgrade_supported': 'bool'
        }

        self.attribute_map = {
            'id': 'id',
            'compartment_id': 'compartmentId',
            'database_version': 'databaseVersion',
            'display_name': 'displayName',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'time_created': 'timeCreated',
            'image_type': 'imageType',
            'image_shape_family': 'imageShapeFamily',
            'patch_set': 'patchSet',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'database_software_image_included_patches': 'databaseSoftwareImageIncludedPatches',
            'included_patches_summary': 'includedPatchesSummary',
            'database_software_image_one_off_patches': 'databaseSoftwareImageOneOffPatches',
            'ls_inventory': 'lsInventory',
            'is_upgrade_supported': 'isUpgradeSupported'
        }

        self._id = None
        self._compartment_id = None
        self._database_version = None
        self._display_name = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._time_created = None
        self._image_type = None
        self._image_shape_family = None
        self._patch_set = None
        self._freeform_tags = None
        self._defined_tags = None
        self._database_software_image_included_patches = None
        self._included_patches_summary = None
        self._database_software_image_one_off_patches = None
        self._ls_inventory = None
        self._is_upgrade_supported = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this DatabaseSoftwareImageSummary.
        The `OCID`__ of the database software image.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The id of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this DatabaseSoftwareImageSummary.
        The `OCID`__ of the database software image.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param id: The id of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._id = id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this DatabaseSoftwareImageSummary.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this DatabaseSoftwareImageSummary.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def database_version(self):
        """
        **[Required]** Gets the database_version of this DatabaseSoftwareImageSummary.
        The database version with which the database software image is to be built.


        :return: The database_version of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._database_version

    @database_version.setter
    def database_version(self, database_version):
        """
        Sets the database_version of this DatabaseSoftwareImageSummary.
        The database version with which the database software image is to be built.


        :param database_version: The database_version of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._database_version = database_version

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this DatabaseSoftwareImageSummary.
        The user-friendly name for the database software image. The name does not have to be unique.


        :return: The display_name of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this DatabaseSoftwareImageSummary.
        The user-friendly name for the database software image. The name does not have to be unique.


        :param display_name: The display_name of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this DatabaseSoftwareImageSummary.
        The current state of the database software image.

        Allowed values for this property are: "PROVISIONING", "AVAILABLE", "DELETING", "DELETED", "FAILED", "TERMINATING", "TERMINATED", "UPDATING", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this DatabaseSoftwareImageSummary.
        The current state of the database software image.


        :param lifecycle_state: The lifecycle_state of this DatabaseSoftwareImageSummary.
        :type: str
        """
        allowed_values = ["PROVISIONING", "AVAILABLE", "DELETING", "DELETED", "FAILED", "TERMINATING", "TERMINATED", "UPDATING"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this DatabaseSoftwareImageSummary.
        Detailed message for the lifecycle state.


        :return: The lifecycle_details of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this DatabaseSoftwareImageSummary.
        Detailed message for the lifecycle state.


        :param lifecycle_details: The lifecycle_details of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this DatabaseSoftwareImageSummary.
        The date and time the database software image was created.


        :return: The time_created of this DatabaseSoftwareImageSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this DatabaseSoftwareImageSummary.
        The date and time the database software image was created.


        :param time_created: The time_created of this DatabaseSoftwareImageSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def image_type(self):
        """
        **[Required]** Gets the image_type of this DatabaseSoftwareImageSummary.
        The type of software image. Can be grid or database.

        Allowed values for this property are: "GRID_IMAGE", "DATABASE_IMAGE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The image_type of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._image_type

    @image_type.setter
    def image_type(self, image_type):
        """
        Sets the image_type of this DatabaseSoftwareImageSummary.
        The type of software image. Can be grid or database.


        :param image_type: The image_type of this DatabaseSoftwareImageSummary.
        :type: str
        """
        allowed_values = ["GRID_IMAGE", "DATABASE_IMAGE"]
        if not value_allowed_none_or_none_sentinel(image_type, allowed_values):
            image_type = 'UNKNOWN_ENUM_VALUE'
        self._image_type = image_type

    @property
    def image_shape_family(self):
        """
        **[Required]** Gets the image_shape_family of this DatabaseSoftwareImageSummary.
        To what shape the image is meant for.

        Allowed values for this property are: "VM_BM_SHAPE", "EXADATA_SHAPE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The image_shape_family of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._image_shape_family

    @image_shape_family.setter
    def image_shape_family(self, image_shape_family):
        """
        Sets the image_shape_family of this DatabaseSoftwareImageSummary.
        To what shape the image is meant for.


        :param image_shape_family: The image_shape_family of this DatabaseSoftwareImageSummary.
        :type: str
        """
        allowed_values = ["VM_BM_SHAPE", "EXADATA_SHAPE"]
        if not value_allowed_none_or_none_sentinel(image_shape_family, allowed_values):
            image_shape_family = 'UNKNOWN_ENUM_VALUE'
        self._image_shape_family = image_shape_family

    @property
    def patch_set(self):
        """
        **[Required]** Gets the patch_set of this DatabaseSoftwareImageSummary.
        The PSU or PBP or Release Updates. To get a list of supported versions, use the :func:`list_db_versions` operation.


        :return: The patch_set of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._patch_set

    @patch_set.setter
    def patch_set(self, patch_set):
        """
        Sets the patch_set of this DatabaseSoftwareImageSummary.
        The PSU or PBP or Release Updates. To get a list of supported versions, use the :func:`list_db_versions` operation.


        :param patch_set: The patch_set of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._patch_set = patch_set

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this DatabaseSoftwareImageSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this DatabaseSoftwareImageSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this DatabaseSoftwareImageSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this DatabaseSoftwareImageSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this DatabaseSoftwareImageSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this DatabaseSoftwareImageSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this DatabaseSoftwareImageSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this DatabaseSoftwareImageSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def database_software_image_included_patches(self):
        """
        Gets the database_software_image_included_patches of this DatabaseSoftwareImageSummary.
        List of one-off patches for Database Homes.


        :return: The database_software_image_included_patches of this DatabaseSoftwareImageSummary.
        :rtype: list[str]
        """
        return self._database_software_image_included_patches

    @database_software_image_included_patches.setter
    def database_software_image_included_patches(self, database_software_image_included_patches):
        """
        Sets the database_software_image_included_patches of this DatabaseSoftwareImageSummary.
        List of one-off patches for Database Homes.


        :param database_software_image_included_patches: The database_software_image_included_patches of this DatabaseSoftwareImageSummary.
        :type: list[str]
        """
        self._database_software_image_included_patches = database_software_image_included_patches

    @property
    def included_patches_summary(self):
        """
        Gets the included_patches_summary of this DatabaseSoftwareImageSummary.
        The patches included in the image and the version of the image


        :return: The included_patches_summary of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._included_patches_summary

    @included_patches_summary.setter
    def included_patches_summary(self, included_patches_summary):
        """
        Sets the included_patches_summary of this DatabaseSoftwareImageSummary.
        The patches included in the image and the version of the image


        :param included_patches_summary: The included_patches_summary of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._included_patches_summary = included_patches_summary

    @property
    def database_software_image_one_off_patches(self):
        """
        Gets the database_software_image_one_off_patches of this DatabaseSoftwareImageSummary.
        List of one-off patches for Database Homes.


        :return: The database_software_image_one_off_patches of this DatabaseSoftwareImageSummary.
        :rtype: list[str]
        """
        return self._database_software_image_one_off_patches

    @database_software_image_one_off_patches.setter
    def database_software_image_one_off_patches(self, database_software_image_one_off_patches):
        """
        Sets the database_software_image_one_off_patches of this DatabaseSoftwareImageSummary.
        List of one-off patches for Database Homes.


        :param database_software_image_one_off_patches: The database_software_image_one_off_patches of this DatabaseSoftwareImageSummary.
        :type: list[str]
        """
        self._database_software_image_one_off_patches = database_software_image_one_off_patches

    @property
    def ls_inventory(self):
        """
        Gets the ls_inventory of this DatabaseSoftwareImageSummary.
        output from lsinventory which will get passed as a string


        :return: The ls_inventory of this DatabaseSoftwareImageSummary.
        :rtype: str
        """
        return self._ls_inventory

    @ls_inventory.setter
    def ls_inventory(self, ls_inventory):
        """
        Sets the ls_inventory of this DatabaseSoftwareImageSummary.
        output from lsinventory which will get passed as a string


        :param ls_inventory: The ls_inventory of this DatabaseSoftwareImageSummary.
        :type: str
        """
        self._ls_inventory = ls_inventory

    @property
    def is_upgrade_supported(self):
        """
        Gets the is_upgrade_supported of this DatabaseSoftwareImageSummary.
        True if this Database software image is supported for Upgrade.


        :return: The is_upgrade_supported of this DatabaseSoftwareImageSummary.
        :rtype: bool
        """
        return self._is_upgrade_supported

    @is_upgrade_supported.setter
    def is_upgrade_supported(self, is_upgrade_supported):
        """
        Sets the is_upgrade_supported of this DatabaseSoftwareImageSummary.
        True if this Database software image is supported for Upgrade.


        :param is_upgrade_supported: The is_upgrade_supported of this DatabaseSoftwareImageSummary.
        :type: bool
        """
        self._is_upgrade_supported = is_upgrade_supported

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other