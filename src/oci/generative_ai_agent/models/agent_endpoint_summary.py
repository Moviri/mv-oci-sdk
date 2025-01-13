# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20240531


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AgentEndpointSummary(object):
    """
    Summary information about an endpoint.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new AgentEndpointSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this AgentEndpointSummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this AgentEndpointSummary.
        :type display_name: str

        :param description:
            The value to assign to the description property of this AgentEndpointSummary.
        :type description: str

        :param compartment_id:
            The value to assign to the compartment_id property of this AgentEndpointSummary.
        :type compartment_id: str

        :param agent_id:
            The value to assign to the agent_id property of this AgentEndpointSummary.
        :type agent_id: str

        :param content_moderation_config:
            The value to assign to the content_moderation_config property of this AgentEndpointSummary.
        :type content_moderation_config: oci.generative_ai_agent.models.ContentModerationConfig

        :param should_enable_trace:
            The value to assign to the should_enable_trace property of this AgentEndpointSummary.
        :type should_enable_trace: bool

        :param should_enable_citation:
            The value to assign to the should_enable_citation property of this AgentEndpointSummary.
        :type should_enable_citation: bool

        :param should_enable_session:
            The value to assign to the should_enable_session property of this AgentEndpointSummary.
        :type should_enable_session: bool

        :param session_config:
            The value to assign to the session_config property of this AgentEndpointSummary.
        :type session_config: oci.generative_ai_agent.models.SessionConfig

        :param time_created:
            The value to assign to the time_created property of this AgentEndpointSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this AgentEndpointSummary.
        :type time_updated: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this AgentEndpointSummary.
        :type lifecycle_state: str

        :param lifecycle_details:
            The value to assign to the lifecycle_details property of this AgentEndpointSummary.
        :type lifecycle_details: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this AgentEndpointSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this AgentEndpointSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this AgentEndpointSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'description': 'str',
            'compartment_id': 'str',
            'agent_id': 'str',
            'content_moderation_config': 'ContentModerationConfig',
            'should_enable_trace': 'bool',
            'should_enable_citation': 'bool',
            'should_enable_session': 'bool',
            'session_config': 'SessionConfig',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'lifecycle_state': 'str',
            'lifecycle_details': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName',
            'description': 'description',
            'compartment_id': 'compartmentId',
            'agent_id': 'agentId',
            'content_moderation_config': 'contentModerationConfig',
            'should_enable_trace': 'shouldEnableTrace',
            'should_enable_citation': 'shouldEnableCitation',
            'should_enable_session': 'shouldEnableSession',
            'session_config': 'sessionConfig',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'lifecycle_state': 'lifecycleState',
            'lifecycle_details': 'lifecycleDetails',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._display_name = None
        self._description = None
        self._compartment_id = None
        self._agent_id = None
        self._content_moderation_config = None
        self._should_enable_trace = None
        self._should_enable_citation = None
        self._should_enable_session = None
        self._session_config = None
        self._time_created = None
        self._time_updated = None
        self._lifecycle_state = None
        self._lifecycle_details = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this AgentEndpointSummary.
        The `OCID`__ of the AgentEndpoint.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The id of this AgentEndpointSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this AgentEndpointSummary.
        The `OCID`__ of the AgentEndpoint.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param id: The id of this AgentEndpointSummary.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        Gets the display_name of this AgentEndpointSummary.
        A user-friendly name. Does not have to be unique, and it's changeable.


        :return: The display_name of this AgentEndpointSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this AgentEndpointSummary.
        A user-friendly name. Does not have to be unique, and it's changeable.


        :param display_name: The display_name of this AgentEndpointSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this AgentEndpointSummary.
        An optional description of the endpoint.


        :return: The description of this AgentEndpointSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this AgentEndpointSummary.
        An optional description of the endpoint.


        :param description: The description of this AgentEndpointSummary.
        :type: str
        """
        self._description = description

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this AgentEndpointSummary.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this AgentEndpointSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this AgentEndpointSummary.
        The `OCID`__ of the compartment.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this AgentEndpointSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def agent_id(self):
        """
        **[Required]** Gets the agent_id of this AgentEndpointSummary.
        The OCID of the agent that this AgentEndpoint is associated with.


        :return: The agent_id of this AgentEndpointSummary.
        :rtype: str
        """
        return self._agent_id

    @agent_id.setter
    def agent_id(self, agent_id):
        """
        Sets the agent_id of this AgentEndpointSummary.
        The OCID of the agent that this AgentEndpoint is associated with.


        :param agent_id: The agent_id of this AgentEndpointSummary.
        :type: str
        """
        self._agent_id = agent_id

    @property
    def content_moderation_config(self):
        """
        Gets the content_moderation_config of this AgentEndpointSummary.

        :return: The content_moderation_config of this AgentEndpointSummary.
        :rtype: oci.generative_ai_agent.models.ContentModerationConfig
        """
        return self._content_moderation_config

    @content_moderation_config.setter
    def content_moderation_config(self, content_moderation_config):
        """
        Sets the content_moderation_config of this AgentEndpointSummary.

        :param content_moderation_config: The content_moderation_config of this AgentEndpointSummary.
        :type: oci.generative_ai_agent.models.ContentModerationConfig
        """
        self._content_moderation_config = content_moderation_config

    @property
    def should_enable_trace(self):
        """
        Gets the should_enable_trace of this AgentEndpointSummary.
        Whether to show traces in the chat result.


        :return: The should_enable_trace of this AgentEndpointSummary.
        :rtype: bool
        """
        return self._should_enable_trace

    @should_enable_trace.setter
    def should_enable_trace(self, should_enable_trace):
        """
        Sets the should_enable_trace of this AgentEndpointSummary.
        Whether to show traces in the chat result.


        :param should_enable_trace: The should_enable_trace of this AgentEndpointSummary.
        :type: bool
        """
        self._should_enable_trace = should_enable_trace

    @property
    def should_enable_citation(self):
        """
        Gets the should_enable_citation of this AgentEndpointSummary.
        Whether to show citations in the chat result.


        :return: The should_enable_citation of this AgentEndpointSummary.
        :rtype: bool
        """
        return self._should_enable_citation

    @should_enable_citation.setter
    def should_enable_citation(self, should_enable_citation):
        """
        Sets the should_enable_citation of this AgentEndpointSummary.
        Whether to show citations in the chat result.


        :param should_enable_citation: The should_enable_citation of this AgentEndpointSummary.
        :type: bool
        """
        self._should_enable_citation = should_enable_citation

    @property
    def should_enable_session(self):
        """
        Gets the should_enable_session of this AgentEndpointSummary.
        Whether or not to enable Session-based chat.


        :return: The should_enable_session of this AgentEndpointSummary.
        :rtype: bool
        """
        return self._should_enable_session

    @should_enable_session.setter
    def should_enable_session(self, should_enable_session):
        """
        Sets the should_enable_session of this AgentEndpointSummary.
        Whether or not to enable Session-based chat.


        :param should_enable_session: The should_enable_session of this AgentEndpointSummary.
        :type: bool
        """
        self._should_enable_session = should_enable_session

    @property
    def session_config(self):
        """
        Gets the session_config of this AgentEndpointSummary.

        :return: The session_config of this AgentEndpointSummary.
        :rtype: oci.generative_ai_agent.models.SessionConfig
        """
        return self._session_config

    @session_config.setter
    def session_config(self, session_config):
        """
        Sets the session_config of this AgentEndpointSummary.

        :param session_config: The session_config of this AgentEndpointSummary.
        :type: oci.generative_ai_agent.models.SessionConfig
        """
        self._session_config = session_config

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this AgentEndpointSummary.
        The date and time the endpoint was created, in the format defined by `RFC 3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_created of this AgentEndpointSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this AgentEndpointSummary.
        The date and time the endpoint was created, in the format defined by `RFC 3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_created: The time_created of this AgentEndpointSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        Gets the time_updated of this AgentEndpointSummary.
        The date and time the AgentEndpoint was updated, in the format defined by `RFC 3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :return: The time_updated of this AgentEndpointSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this AgentEndpointSummary.
        The date and time the AgentEndpoint was updated, in the format defined by `RFC 3339`__.

        Example: `2016-08-25T21:10:29.600Z`

        __ https://tools.ietf.org/html/rfc3339


        :param time_updated: The time_updated of this AgentEndpointSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this AgentEndpointSummary.
        The current state of the endpoint.


        :return: The lifecycle_state of this AgentEndpointSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this AgentEndpointSummary.
        The current state of the endpoint.


        :param lifecycle_state: The lifecycle_state of this AgentEndpointSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def lifecycle_details(self):
        """
        Gets the lifecycle_details of this AgentEndpointSummary.
        A message that describes the current state of the endpoint in more detail. For example,
        can be used to provide actionable information for a resource in the Failed state.


        :return: The lifecycle_details of this AgentEndpointSummary.
        :rtype: str
        """
        return self._lifecycle_details

    @lifecycle_details.setter
    def lifecycle_details(self, lifecycle_details):
        """
        Sets the lifecycle_details of this AgentEndpointSummary.
        A message that describes the current state of the endpoint in more detail. For example,
        can be used to provide actionable information for a resource in the Failed state.


        :param lifecycle_details: The lifecycle_details of this AgentEndpointSummary.
        :type: str
        """
        self._lifecycle_details = lifecycle_details

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this AgentEndpointSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this AgentEndpointSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this AgentEndpointSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this AgentEndpointSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this AgentEndpointSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this AgentEndpointSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this AgentEndpointSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this AgentEndpointSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this AgentEndpointSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this AgentEndpointSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this AgentEndpointSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.

        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this AgentEndpointSummary.
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
