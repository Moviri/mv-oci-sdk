# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20201101

from .create_external_db_system_connector_details import CreateExternalDbSystemConnectorDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateExternalDbSystemMacsConnectorDetails(CreateExternalDbSystemConnectorDetails):
    """
    The details for creating an external connector that is used to connect to an external DB system component
    using the `Management Agent Cloud Service (MACS)`__.

    __ https://docs.cloud.oracle.com/iaas/management-agents/index.html
    """

    def __init__(self, **kwargs):
        """
        Initializes a new CreateExternalDbSystemMacsConnectorDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.database_management.models.CreateExternalDbSystemMacsConnectorDetails.connector_type` attribute
        of this class is ``MACS`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param connector_type:
            The value to assign to the connector_type property of this CreateExternalDbSystemMacsConnectorDetails.
            Allowed values for this property are: "MACS"
        :type connector_type: str

        :param display_name:
            The value to assign to the display_name property of this CreateExternalDbSystemMacsConnectorDetails.
        :type display_name: str

        :param external_db_system_id:
            The value to assign to the external_db_system_id property of this CreateExternalDbSystemMacsConnectorDetails.
        :type external_db_system_id: str

        :param agent_id:
            The value to assign to the agent_id property of this CreateExternalDbSystemMacsConnectorDetails.
        :type agent_id: str

        :param connection_info:
            The value to assign to the connection_info property of this CreateExternalDbSystemMacsConnectorDetails.
        :type connection_info: oci.database_management.models.ExternalDbSystemConnectionInfo

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateExternalDbSystemMacsConnectorDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateExternalDbSystemMacsConnectorDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'connector_type': 'str',
            'display_name': 'str',
            'external_db_system_id': 'str',
            'agent_id': 'str',
            'connection_info': 'ExternalDbSystemConnectionInfo',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'connector_type': 'connectorType',
            'display_name': 'displayName',
            'external_db_system_id': 'externalDbSystemId',
            'agent_id': 'agentId',
            'connection_info': 'connectionInfo',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._connector_type = None
        self._display_name = None
        self._external_db_system_id = None
        self._agent_id = None
        self._connection_info = None
        self._freeform_tags = None
        self._defined_tags = None
        self._connector_type = 'MACS'

    @property
    def agent_id(self):
        """
        **[Required]** Gets the agent_id of this CreateExternalDbSystemMacsConnectorDetails.
        The `OCID`__ of the management agent
        used for the external DB system connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The agent_id of this CreateExternalDbSystemMacsConnectorDetails.
        :rtype: str
        """
        return self._agent_id

    @agent_id.setter
    def agent_id(self, agent_id):
        """
        Sets the agent_id of this CreateExternalDbSystemMacsConnectorDetails.
        The `OCID`__ of the management agent
        used for the external DB system connector.

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param agent_id: The agent_id of this CreateExternalDbSystemMacsConnectorDetails.
        :type: str
        """
        self._agent_id = agent_id

    @property
    def connection_info(self):
        """
        Gets the connection_info of this CreateExternalDbSystemMacsConnectorDetails.

        :return: The connection_info of this CreateExternalDbSystemMacsConnectorDetails.
        :rtype: oci.database_management.models.ExternalDbSystemConnectionInfo
        """
        return self._connection_info

    @connection_info.setter
    def connection_info(self, connection_info):
        """
        Sets the connection_info of this CreateExternalDbSystemMacsConnectorDetails.

        :param connection_info: The connection_info of this CreateExternalDbSystemMacsConnectorDetails.
        :type: oci.database_management.models.ExternalDbSystemConnectionInfo
        """
        self._connection_info = connection_info

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateExternalDbSystemMacsConnectorDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this CreateExternalDbSystemMacsConnectorDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateExternalDbSystemMacsConnectorDetails.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this CreateExternalDbSystemMacsConnectorDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateExternalDbSystemMacsConnectorDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this CreateExternalDbSystemMacsConnectorDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateExternalDbSystemMacsConnectorDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this CreateExternalDbSystemMacsConnectorDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
