# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210610


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class JmsPluginSummary(object):
    """
    Summary of the JmsPlugin.
    """

    #: A constant which can be used with the agent_type property of a JmsPluginSummary.
    #: This constant has a value of "OMA"
    AGENT_TYPE_OMA = "OMA"

    #: A constant which can be used with the agent_type property of a JmsPluginSummary.
    #: This constant has a value of "OCA"
    AGENT_TYPE_OCA = "OCA"

    #: A constant which can be used with the lifecycle_state property of a JmsPluginSummary.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a JmsPluginSummary.
    #: This constant has a value of "INACTIVE"
    LIFECYCLE_STATE_INACTIVE = "INACTIVE"

    #: A constant which can be used with the lifecycle_state property of a JmsPluginSummary.
    #: This constant has a value of "NEEDS_ATTENTION"
    LIFECYCLE_STATE_NEEDS_ATTENTION = "NEEDS_ATTENTION"

    #: A constant which can be used with the lifecycle_state property of a JmsPluginSummary.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the availability_status property of a JmsPluginSummary.
    #: This constant has a value of "ACTIVE"
    AVAILABILITY_STATUS_ACTIVE = "ACTIVE"

    #: A constant which can be used with the availability_status property of a JmsPluginSummary.
    #: This constant has a value of "SILENT"
    AVAILABILITY_STATUS_SILENT = "SILENT"

    #: A constant which can be used with the availability_status property of a JmsPluginSummary.
    #: This constant has a value of "NOT_AVAILABLE"
    AVAILABILITY_STATUS_NOT_AVAILABLE = "NOT_AVAILABLE"

    #: A constant which can be used with the os_family property of a JmsPluginSummary.
    #: This constant has a value of "LINUX"
    OS_FAMILY_LINUX = "LINUX"

    #: A constant which can be used with the os_family property of a JmsPluginSummary.
    #: This constant has a value of "WINDOWS"
    OS_FAMILY_WINDOWS = "WINDOWS"

    #: A constant which can be used with the os_family property of a JmsPluginSummary.
    #: This constant has a value of "MACOS"
    OS_FAMILY_MACOS = "MACOS"

    #: A constant which can be used with the os_family property of a JmsPluginSummary.
    #: This constant has a value of "UNKNOWN"
    OS_FAMILY_UNKNOWN = "UNKNOWN"

    def __init__(self, **kwargs):
        """
        Initializes a new JmsPluginSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this JmsPluginSummary.
        :type id: str

        :param agent_id:
            The value to assign to the agent_id property of this JmsPluginSummary.
        :type agent_id: str

        :param agent_type:
            The value to assign to the agent_type property of this JmsPluginSummary.
            Allowed values for this property are: "OMA", "OCA", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type agent_type: str

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this JmsPluginSummary.
            Allowed values for this property are: "ACTIVE", "INACTIVE", "NEEDS_ATTENTION", "DELETED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param availability_status:
            The value to assign to the availability_status property of this JmsPluginSummary.
            Allowed values for this property are: "ACTIVE", "SILENT", "NOT_AVAILABLE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type availability_status: str

        :param fleet_id:
            The value to assign to the fleet_id property of this JmsPluginSummary.
        :type fleet_id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this JmsPluginSummary.
        :type compartment_id: str

        :param hostname:
            The value to assign to the hostname property of this JmsPluginSummary.
        :type hostname: str

        :param os_family:
            The value to assign to the os_family property of this JmsPluginSummary.
            Allowed values for this property are: "LINUX", "WINDOWS", "MACOS", "UNKNOWN", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type os_family: str

        :param os_architecture:
            The value to assign to the os_architecture property of this JmsPluginSummary.
        :type os_architecture: str

        :param os_distribution:
            The value to assign to the os_distribution property of this JmsPluginSummary.
        :type os_distribution: str

        :param plugin_version:
            The value to assign to the plugin_version property of this JmsPluginSummary.
        :type plugin_version: str

        :param time_registered:
            The value to assign to the time_registered property of this JmsPluginSummary.
        :type time_registered: datetime

        :param time_last_seen:
            The value to assign to the time_last_seen property of this JmsPluginSummary.
        :type time_last_seen: datetime

        :param defined_tags:
            The value to assign to the defined_tags property of this JmsPluginSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param freeform_tags:
            The value to assign to the freeform_tags property of this JmsPluginSummary.
        :type freeform_tags: dict(str, str)

        :param system_tags:
            The value to assign to the system_tags property of this JmsPluginSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'agent_id': 'str',
            'agent_type': 'str',
            'lifecycle_state': 'str',
            'availability_status': 'str',
            'fleet_id': 'str',
            'compartment_id': 'str',
            'hostname': 'str',
            'os_family': 'str',
            'os_architecture': 'str',
            'os_distribution': 'str',
            'plugin_version': 'str',
            'time_registered': 'datetime',
            'time_last_seen': 'datetime',
            'defined_tags': 'dict(str, dict(str, object))',
            'freeform_tags': 'dict(str, str)',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'agent_id': 'agentId',
            'agent_type': 'agentType',
            'lifecycle_state': 'lifecycleState',
            'availability_status': 'availabilityStatus',
            'fleet_id': 'fleetId',
            'compartment_id': 'compartmentId',
            'hostname': 'hostname',
            'os_family': 'osFamily',
            'os_architecture': 'osArchitecture',
            'os_distribution': 'osDistribution',
            'plugin_version': 'pluginVersion',
            'time_registered': 'timeRegistered',
            'time_last_seen': 'timeLastSeen',
            'defined_tags': 'definedTags',
            'freeform_tags': 'freeformTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._agent_id = None
        self._agent_type = None
        self._lifecycle_state = None
        self._availability_status = None
        self._fleet_id = None
        self._compartment_id = None
        self._hostname = None
        self._os_family = None
        self._os_architecture = None
        self._os_distribution = None
        self._plugin_version = None
        self._time_registered = None
        self._time_last_seen = None
        self._defined_tags = None
        self._freeform_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this JmsPluginSummary.
        The `OCID`__ to identify this JmsPlugin.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The id of this JmsPluginSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this JmsPluginSummary.
        The `OCID`__ to identify this JmsPlugin.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param id: The id of this JmsPluginSummary.
        :type: str
        """
        self._id = id

    @property
    def agent_id(self):
        """
        **[Required]** Gets the agent_id of this JmsPluginSummary.
        The `OCID`__ of the Management Agent (OMA) or the Oracle Cloud Agent (OCA) instance where the JMS plugin is deployed.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The agent_id of this JmsPluginSummary.
        :rtype: str
        """
        return self._agent_id

    @agent_id.setter
    def agent_id(self, agent_id):
        """
        Sets the agent_id of this JmsPluginSummary.
        The `OCID`__ of the Management Agent (OMA) or the Oracle Cloud Agent (OCA) instance where the JMS plugin is deployed.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param agent_id: The agent_id of this JmsPluginSummary.
        :type: str
        """
        self._agent_id = agent_id

    @property
    def agent_type(self):
        """
        **[Required]** Gets the agent_type of this JmsPluginSummary.
        The agent type.

        Allowed values for this property are: "OMA", "OCA", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The agent_type of this JmsPluginSummary.
        :rtype: str
        """
        return self._agent_type

    @agent_type.setter
    def agent_type(self, agent_type):
        """
        Sets the agent_type of this JmsPluginSummary.
        The agent type.


        :param agent_type: The agent_type of this JmsPluginSummary.
        :type: str
        """
        allowed_values = ["OMA", "OCA"]
        if not value_allowed_none_or_none_sentinel(agent_type, allowed_values):
            agent_type = 'UNKNOWN_ENUM_VALUE'
        self._agent_type = agent_type

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this JmsPluginSummary.
        The lifecycle state.

        Allowed values for this property are: "ACTIVE", "INACTIVE", "NEEDS_ATTENTION", "DELETED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this JmsPluginSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this JmsPluginSummary.
        The lifecycle state.


        :param lifecycle_state: The lifecycle_state of this JmsPluginSummary.
        :type: str
        """
        allowed_values = ["ACTIVE", "INACTIVE", "NEEDS_ATTENTION", "DELETED"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def availability_status(self):
        """
        **[Required]** Gets the availability_status of this JmsPluginSummary.
        The availability status.

        Allowed values for this property are: "ACTIVE", "SILENT", "NOT_AVAILABLE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The availability_status of this JmsPluginSummary.
        :rtype: str
        """
        return self._availability_status

    @availability_status.setter
    def availability_status(self, availability_status):
        """
        Sets the availability_status of this JmsPluginSummary.
        The availability status.


        :param availability_status: The availability_status of this JmsPluginSummary.
        :type: str
        """
        allowed_values = ["ACTIVE", "SILENT", "NOT_AVAILABLE"]
        if not value_allowed_none_or_none_sentinel(availability_status, allowed_values):
            availability_status = 'UNKNOWN_ENUM_VALUE'
        self._availability_status = availability_status

    @property
    def fleet_id(self):
        """
        Gets the fleet_id of this JmsPluginSummary.
        The `OCID`__ of the fleet.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The fleet_id of this JmsPluginSummary.
        :rtype: str
        """
        return self._fleet_id

    @fleet_id.setter
    def fleet_id(self, fleet_id):
        """
        Sets the fleet_id of this JmsPluginSummary.
        The `OCID`__ of the fleet.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param fleet_id: The fleet_id of this JmsPluginSummary.
        :type: str
        """
        self._fleet_id = fleet_id

    @property
    def compartment_id(self):
        """
        Gets the compartment_id of this JmsPluginSummary.
        The OMA/OCA agent's compartment `OCID`__.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this JmsPluginSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this JmsPluginSummary.
        The OMA/OCA agent's compartment `OCID`__.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this JmsPluginSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def hostname(self):
        """
        Gets the hostname of this JmsPluginSummary.
        The hostname of the agent.


        :return: The hostname of this JmsPluginSummary.
        :rtype: str
        """
        return self._hostname

    @hostname.setter
    def hostname(self, hostname):
        """
        Sets the hostname of this JmsPluginSummary.
        The hostname of the agent.


        :param hostname: The hostname of this JmsPluginSummary.
        :type: str
        """
        self._hostname = hostname

    @property
    def os_family(self):
        """
        Gets the os_family of this JmsPluginSummary.
        The operating system family for the plugin.

        Allowed values for this property are: "LINUX", "WINDOWS", "MACOS", "UNKNOWN", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The os_family of this JmsPluginSummary.
        :rtype: str
        """
        return self._os_family

    @os_family.setter
    def os_family(self, os_family):
        """
        Sets the os_family of this JmsPluginSummary.
        The operating system family for the plugin.


        :param os_family: The os_family of this JmsPluginSummary.
        :type: str
        """
        allowed_values = ["LINUX", "WINDOWS", "MACOS", "UNKNOWN"]
        if not value_allowed_none_or_none_sentinel(os_family, allowed_values):
            os_family = 'UNKNOWN_ENUM_VALUE'
        self._os_family = os_family

    @property
    def os_architecture(self):
        """
        Gets the os_architecture of this JmsPluginSummary.
        The architecture of the operating system of the plugin.


        :return: The os_architecture of this JmsPluginSummary.
        :rtype: str
        """
        return self._os_architecture

    @os_architecture.setter
    def os_architecture(self, os_architecture):
        """
        Sets the os_architecture of this JmsPluginSummary.
        The architecture of the operating system of the plugin.


        :param os_architecture: The os_architecture of this JmsPluginSummary.
        :type: str
        """
        self._os_architecture = os_architecture

    @property
    def os_distribution(self):
        """
        Gets the os_distribution of this JmsPluginSummary.
        The distribution of the operating system of the plugin.


        :return: The os_distribution of this JmsPluginSummary.
        :rtype: str
        """
        return self._os_distribution

    @os_distribution.setter
    def os_distribution(self, os_distribution):
        """
        Sets the os_distribution of this JmsPluginSummary.
        The distribution of the operating system of the plugin.


        :param os_distribution: The os_distribution of this JmsPluginSummary.
        :type: str
        """
        self._os_distribution = os_distribution

    @property
    def plugin_version(self):
        """
        Gets the plugin_version of this JmsPluginSummary.
        The version of the plugin.


        :return: The plugin_version of this JmsPluginSummary.
        :rtype: str
        """
        return self._plugin_version

    @plugin_version.setter
    def plugin_version(self, plugin_version):
        """
        Sets the plugin_version of this JmsPluginSummary.
        The version of the plugin.


        :param plugin_version: The plugin_version of this JmsPluginSummary.
        :type: str
        """
        self._plugin_version = plugin_version

    @property
    def time_registered(self):
        """
        **[Required]** Gets the time_registered of this JmsPluginSummary.
        The date and time the plugin was registered.


        :return: The time_registered of this JmsPluginSummary.
        :rtype: datetime
        """
        return self._time_registered

    @time_registered.setter
    def time_registered(self, time_registered):
        """
        Sets the time_registered of this JmsPluginSummary.
        The date and time the plugin was registered.


        :param time_registered: The time_registered of this JmsPluginSummary.
        :type: datetime
        """
        self._time_registered = time_registered

    @property
    def time_last_seen(self):
        """
        Gets the time_last_seen of this JmsPluginSummary.
        The date and time the resource was _last_ reported to JMS.
        This is potentially _after_ the specified time period provided by the filters.
        For example, a resource can be last reported to JMS before the start of a specified time period,
        if it is also reported during the time period.


        :return: The time_last_seen of this JmsPluginSummary.
        :rtype: datetime
        """
        return self._time_last_seen

    @time_last_seen.setter
    def time_last_seen(self, time_last_seen):
        """
        Sets the time_last_seen of this JmsPluginSummary.
        The date and time the resource was _last_ reported to JMS.
        This is potentially _after_ the specified time period provided by the filters.
        For example, a resource can be last reported to JMS before the start of a specified time period,
        if it is also reported during the time period.


        :param time_last_seen: The time_last_seen of this JmsPluginSummary.
        :type: datetime
        """
        self._time_last_seen = time_last_seen

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this JmsPluginSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`. (See `Understanding Free-form Tags`__).

        __ https://docs.cloud.oracle.com/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm


        :return: The defined_tags of this JmsPluginSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this JmsPluginSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`. (See `Understanding Free-form Tags`__).

        __ https://docs.cloud.oracle.com/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm


        :param defined_tags: The defined_tags of this JmsPluginSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this JmsPluginSummary.
        Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`. (See `Managing Tags and Tag Namespaces`__.)

        __ https://docs.cloud.oracle.com/Content/Tagging/Concepts/understandingfreeformtags.htm


        :return: The freeform_tags of this JmsPluginSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this JmsPluginSummary.
        Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`. (See `Managing Tags and Tag Namespaces`__.)

        __ https://docs.cloud.oracle.com/Content/Tagging/Concepts/understandingfreeformtags.htm


        :param freeform_tags: The freeform_tags of this JmsPluginSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this JmsPluginSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        System tags can be viewed by users, but can only be created by the system.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The system_tags of this JmsPluginSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this JmsPluginSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        System tags can be viewed by users, but can only be created by the system.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param system_tags: The system_tags of this JmsPluginSummary.
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
