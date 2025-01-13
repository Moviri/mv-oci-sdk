# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210330


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ConfigSummary(object):
    """
    Summary of the configuration.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new ConfigSummary object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.stack_monitoring.models.AutoPromoteConfigSummary`
        * :class:`~oci.stack_monitoring.models.LicenseAutoAssignConfigSummary`
        * :class:`~oci.stack_monitoring.models.LicenseEnterpriseExtensibilityConfigSummary`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ConfigSummary.
        :type id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ConfigSummary.
        :type compartment_id: str

        :param display_name:
            The value to assign to the display_name property of this ConfigSummary.
        :type display_name: str

        :param time_created:
            The value to assign to the time_created property of this ConfigSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this ConfigSummary.
        :type time_updated: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ConfigSummary.
        :type lifecycle_state: str

        :param config_type:
            The value to assign to the config_type property of this ConfigSummary.
        :type config_type: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this ConfigSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this ConfigSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this ConfigSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'compartment_id': 'str',
            'display_name': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'lifecycle_state': 'str',
            'config_type': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'compartment_id': 'compartmentId',
            'display_name': 'displayName',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'lifecycle_state': 'lifecycleState',
            'config_type': 'configType',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._compartment_id = None
        self._display_name = None
        self._time_created = None
        self._time_updated = None
        self._lifecycle_state = None
        self._config_type = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['configType']

        if type == 'AUTO_PROMOTE':
            return 'AutoPromoteConfigSummary'

        if type == 'LICENSE_AUTO_ASSIGN':
            return 'LicenseAutoAssignConfigSummary'

        if type == 'LICENSE_ENTERPRISE_EXTENSIBILITY':
            return 'LicenseEnterpriseExtensibilityConfigSummary'
        else:
            return 'ConfigSummary'

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ConfigSummary.
        Unique identifier that is immutable on creation.


        :return: The id of this ConfigSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ConfigSummary.
        Unique identifier that is immutable on creation.


        :param id: The id of this ConfigSummary.
        :type: str
        """
        self._id = id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ConfigSummary.
        Compartment Identifier.


        :return: The compartment_id of this ConfigSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ConfigSummary.
        Compartment Identifier.


        :param compartment_id: The compartment_id of this ConfigSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def display_name(self):
        """
        Gets the display_name of this ConfigSummary.
        Config Identifier, can be renamed.


        :return: The display_name of this ConfigSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ConfigSummary.
        Config Identifier, can be renamed.


        :param display_name: The display_name of this ConfigSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def time_created(self):
        """
        Gets the time_created of this ConfigSummary.
        The time the the configuration was created. An RFC3339 formatted datetime string.


        :return: The time_created of this ConfigSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ConfigSummary.
        The time the the configuration was created. An RFC3339 formatted datetime string.


        :param time_created: The time_created of this ConfigSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        Gets the time_updated of this ConfigSummary.
        The time the configuration was updated.


        :return: The time_updated of this ConfigSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this ConfigSummary.
        The time the configuration was updated.


        :param time_updated: The time_updated of this ConfigSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this ConfigSummary.
        The current state of the configuration.


        :return: The lifecycle_state of this ConfigSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ConfigSummary.
        The current state of the configuration.


        :param lifecycle_state: The lifecycle_state of this ConfigSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def config_type(self):
        """
        **[Required]** Gets the config_type of this ConfigSummary.
        The type of configuration.


        :return: The config_type of this ConfigSummary.
        :rtype: str
        """
        return self._config_type

    @config_type.setter
    def config_type(self, config_type):
        """
        Sets the config_type of this ConfigSummary.
        The type of configuration.


        :param config_type: The config_type of this ConfigSummary.
        :type: str
        """
        self._config_type = config_type

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this ConfigSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :return: The freeform_tags of this ConfigSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this ConfigSummary.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :param freeform_tags: The freeform_tags of this ConfigSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this ConfigSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this ConfigSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this ConfigSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this ConfigSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this ConfigSummary.
        Usage of system tag keys. These predefined keys are scoped to namespaces.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this ConfigSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this ConfigSummary.
        Usage of system tag keys. These predefined keys are scoped to namespaces.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this ConfigSummary.
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
