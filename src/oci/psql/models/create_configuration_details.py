# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220915


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateConfigurationDetails(object):
    """
    The information to create a new configuration.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateConfigurationDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this CreateConfigurationDetails.
        :type display_name: str

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateConfigurationDetails.
        :type compartment_id: str

        :param description:
            The value to assign to the description property of this CreateConfigurationDetails.
        :type description: str

        :param db_version:
            The value to assign to the db_version property of this CreateConfigurationDetails.
        :type db_version: str

        :param shape:
            The value to assign to the shape property of this CreateConfigurationDetails.
        :type shape: str

        :param is_flexible:
            The value to assign to the is_flexible property of this CreateConfigurationDetails.
        :type is_flexible: bool

        :param instance_ocpu_count:
            The value to assign to the instance_ocpu_count property of this CreateConfigurationDetails.
        :type instance_ocpu_count: int

        :param instance_memory_size_in_gbs:
            The value to assign to the instance_memory_size_in_gbs property of this CreateConfigurationDetails.
        :type instance_memory_size_in_gbs: int

        :param db_configuration_overrides:
            The value to assign to the db_configuration_overrides property of this CreateConfigurationDetails.
        :type db_configuration_overrides: oci.psql.models.DbConfigurationOverrideCollection

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateConfigurationDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateConfigurationDetails.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this CreateConfigurationDetails.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'display_name': 'str',
            'compartment_id': 'str',
            'description': 'str',
            'db_version': 'str',
            'shape': 'str',
            'is_flexible': 'bool',
            'instance_ocpu_count': 'int',
            'instance_memory_size_in_gbs': 'int',
            'db_configuration_overrides': 'DbConfigurationOverrideCollection',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'compartment_id': 'compartmentId',
            'description': 'description',
            'db_version': 'dbVersion',
            'shape': 'shape',
            'is_flexible': 'isFlexible',
            'instance_ocpu_count': 'instanceOcpuCount',
            'instance_memory_size_in_gbs': 'instanceMemorySizeInGBs',
            'db_configuration_overrides': 'dbConfigurationOverrides',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._display_name = None
        self._compartment_id = None
        self._description = None
        self._db_version = None
        self._shape = None
        self._is_flexible = None
        self._instance_ocpu_count = None
        self._instance_memory_size_in_gbs = None
        self._db_configuration_overrides = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this CreateConfigurationDetails.
        A user-friendly display name for the configuration. Avoid entering confidential information.


        :return: The display_name of this CreateConfigurationDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this CreateConfigurationDetails.
        A user-friendly display name for the configuration. Avoid entering confidential information.


        :param display_name: The display_name of this CreateConfigurationDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateConfigurationDetails.
        The `OCID`__ of the compartment that contains the configuration.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this CreateConfigurationDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateConfigurationDetails.
        The `OCID`__ of the compartment that contains the configuration.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this CreateConfigurationDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def description(self):
        """
        Gets the description of this CreateConfigurationDetails.
        Details about the configuration set.


        :return: The description of this CreateConfigurationDetails.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this CreateConfigurationDetails.
        Details about the configuration set.


        :param description: The description of this CreateConfigurationDetails.
        :type: str
        """
        self._description = description

    @property
    def db_version(self):
        """
        **[Required]** Gets the db_version of this CreateConfigurationDetails.
        Version of the PostgreSQL database.


        :return: The db_version of this CreateConfigurationDetails.
        :rtype: str
        """
        return self._db_version

    @db_version.setter
    def db_version(self, db_version):
        """
        Sets the db_version of this CreateConfigurationDetails.
        Version of the PostgreSQL database.


        :param db_version: The db_version of this CreateConfigurationDetails.
        :type: str
        """
        self._db_version = db_version

    @property
    def shape(self):
        """
        **[Required]** Gets the shape of this CreateConfigurationDetails.
        The name of the shape for the configuration.
        Example: `VM.Standard.E4.Flex`


        :return: The shape of this CreateConfigurationDetails.
        :rtype: str
        """
        return self._shape

    @shape.setter
    def shape(self, shape):
        """
        Sets the shape of this CreateConfigurationDetails.
        The name of the shape for the configuration.
        Example: `VM.Standard.E4.Flex`


        :param shape: The shape of this CreateConfigurationDetails.
        :type: str
        """
        self._shape = shape

    @property
    def is_flexible(self):
        """
        Gets the is_flexible of this CreateConfigurationDetails.
        Whether the configuration supports flexible shapes.


        :return: The is_flexible of this CreateConfigurationDetails.
        :rtype: bool
        """
        return self._is_flexible

    @is_flexible.setter
    def is_flexible(self, is_flexible):
        """
        Sets the is_flexible of this CreateConfigurationDetails.
        Whether the configuration supports flexible shapes.


        :param is_flexible: The is_flexible of this CreateConfigurationDetails.
        :type: bool
        """
        self._is_flexible = is_flexible

    @property
    def instance_ocpu_count(self):
        """
        Gets the instance_ocpu_count of this CreateConfigurationDetails.
        CPU core count.

        Skip or set it's value to 0 if configuration is for a flexible shape.


        :return: The instance_ocpu_count of this CreateConfigurationDetails.
        :rtype: int
        """
        return self._instance_ocpu_count

    @instance_ocpu_count.setter
    def instance_ocpu_count(self, instance_ocpu_count):
        """
        Sets the instance_ocpu_count of this CreateConfigurationDetails.
        CPU core count.

        Skip or set it's value to 0 if configuration is for a flexible shape.


        :param instance_ocpu_count: The instance_ocpu_count of this CreateConfigurationDetails.
        :type: int
        """
        self._instance_ocpu_count = instance_ocpu_count

    @property
    def instance_memory_size_in_gbs(self):
        """
        Gets the instance_memory_size_in_gbs of this CreateConfigurationDetails.
        Memory size in gigabytes with 1GB increment.

        Skip or set it's value to 0 if configuration is for a flexible shape.


        :return: The instance_memory_size_in_gbs of this CreateConfigurationDetails.
        :rtype: int
        """
        return self._instance_memory_size_in_gbs

    @instance_memory_size_in_gbs.setter
    def instance_memory_size_in_gbs(self, instance_memory_size_in_gbs):
        """
        Sets the instance_memory_size_in_gbs of this CreateConfigurationDetails.
        Memory size in gigabytes with 1GB increment.

        Skip or set it's value to 0 if configuration is for a flexible shape.


        :param instance_memory_size_in_gbs: The instance_memory_size_in_gbs of this CreateConfigurationDetails.
        :type: int
        """
        self._instance_memory_size_in_gbs = instance_memory_size_in_gbs

    @property
    def db_configuration_overrides(self):
        """
        **[Required]** Gets the db_configuration_overrides of this CreateConfigurationDetails.

        :return: The db_configuration_overrides of this CreateConfigurationDetails.
        :rtype: oci.psql.models.DbConfigurationOverrideCollection
        """
        return self._db_configuration_overrides

    @db_configuration_overrides.setter
    def db_configuration_overrides(self, db_configuration_overrides):
        """
        Sets the db_configuration_overrides of this CreateConfigurationDetails.

        :param db_configuration_overrides: The db_configuration_overrides of this CreateConfigurationDetails.
        :type: oci.psql.models.DbConfigurationOverrideCollection
        """
        self._db_configuration_overrides = db_configuration_overrides

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateConfigurationDetails.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :return: The freeform_tags of this CreateConfigurationDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateConfigurationDetails.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :param freeform_tags: The freeform_tags of this CreateConfigurationDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateConfigurationDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this CreateConfigurationDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateConfigurationDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this CreateConfigurationDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this CreateConfigurationDetails.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this CreateConfigurationDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this CreateConfigurationDetails.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this CreateConfigurationDetails.
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
