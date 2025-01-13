# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181201


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class SqlFirewallAllowedSqlSummary(object):
    """
    The resource represents a SQL Firewall allowed SQL in Data Safe.
    """

    #: A constant which can be used with the sql_level property of a SqlFirewallAllowedSqlSummary.
    #: This constant has a value of "USER_ISSUED_SQL"
    SQL_LEVEL_USER_ISSUED_SQL = "USER_ISSUED_SQL"

    #: A constant which can be used with the sql_level property of a SqlFirewallAllowedSqlSummary.
    #: This constant has a value of "ALL_SQL"
    SQL_LEVEL_ALL_SQL = "ALL_SQL"

    #: A constant which can be used with the lifecycle_state property of a SqlFirewallAllowedSqlSummary.
    #: This constant has a value of "ACTIVE"
    LIFECYCLE_STATE_ACTIVE = "ACTIVE"

    #: A constant which can be used with the lifecycle_state property of a SqlFirewallAllowedSqlSummary.
    #: This constant has a value of "DELETED"
    LIFECYCLE_STATE_DELETED = "DELETED"

    #: A constant which can be used with the lifecycle_state property of a SqlFirewallAllowedSqlSummary.
    #: This constant has a value of "FAILED"
    LIFECYCLE_STATE_FAILED = "FAILED"

    def __init__(self, **kwargs):
        """
        Initializes a new SqlFirewallAllowedSqlSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this SqlFirewallAllowedSqlSummary.
        :type id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this SqlFirewallAllowedSqlSummary.
        :type compartment_id: str

        :param display_name:
            The value to assign to the display_name property of this SqlFirewallAllowedSqlSummary.
        :type display_name: str

        :param description:
            The value to assign to the description property of this SqlFirewallAllowedSqlSummary.
        :type description: str

        :param sql_firewall_policy_id:
            The value to assign to the sql_firewall_policy_id property of this SqlFirewallAllowedSqlSummary.
        :type sql_firewall_policy_id: str

        :param current_user:
            The value to assign to the current_user property of this SqlFirewallAllowedSqlSummary.
        :type current_user: str

        :param db_user_name:
            The value to assign to the db_user_name property of this SqlFirewallAllowedSqlSummary.
        :type db_user_name: str

        :param sql_text:
            The value to assign to the sql_text property of this SqlFirewallAllowedSqlSummary.
        :type sql_text: str

        :param sql_level:
            The value to assign to the sql_level property of this SqlFirewallAllowedSqlSummary.
            Allowed values for this property are: "USER_ISSUED_SQL", "ALL_SQL", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type sql_level: str

        :param sql_accessed_objects:
            The value to assign to the sql_accessed_objects property of this SqlFirewallAllowedSqlSummary.
        :type sql_accessed_objects: list[str]

        :param version:
            The value to assign to the version property of this SqlFirewallAllowedSqlSummary.
        :type version: float

        :param time_collected:
            The value to assign to the time_collected property of this SqlFirewallAllowedSqlSummary.
        :type time_collected: datetime

        :param time_updated:
            The value to assign to the time_updated property of this SqlFirewallAllowedSqlSummary.
        :type time_updated: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this SqlFirewallAllowedSqlSummary.
            Allowed values for this property are: "ACTIVE", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type lifecycle_state: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this SqlFirewallAllowedSqlSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this SqlFirewallAllowedSqlSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this SqlFirewallAllowedSqlSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'compartment_id': 'str',
            'display_name': 'str',
            'description': 'str',
            'sql_firewall_policy_id': 'str',
            'current_user': 'str',
            'db_user_name': 'str',
            'sql_text': 'str',
            'sql_level': 'str',
            'sql_accessed_objects': 'list[str]',
            'version': 'float',
            'time_collected': 'datetime',
            'time_updated': 'datetime',
            'lifecycle_state': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'compartment_id': 'compartmentId',
            'display_name': 'displayName',
            'description': 'description',
            'sql_firewall_policy_id': 'sqlFirewallPolicyId',
            'current_user': 'currentUser',
            'db_user_name': 'dbUserName',
            'sql_text': 'sqlText',
            'sql_level': 'sqlLevel',
            'sql_accessed_objects': 'sqlAccessedObjects',
            'version': 'version',
            'time_collected': 'timeCollected',
            'time_updated': 'timeUpdated',
            'lifecycle_state': 'lifecycleState',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._compartment_id = None
        self._display_name = None
        self._description = None
        self._sql_firewall_policy_id = None
        self._current_user = None
        self._db_user_name = None
        self._sql_text = None
        self._sql_level = None
        self._sql_accessed_objects = None
        self._version = None
        self._time_collected = None
        self._time_updated = None
        self._lifecycle_state = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this SqlFirewallAllowedSqlSummary.
        The OCID of the SQL Firewall allowed SQL.


        :return: The id of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this SqlFirewallAllowedSqlSummary.
        The OCID of the SQL Firewall allowed SQL.


        :param id: The id of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._id = id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this SqlFirewallAllowedSqlSummary.
        The OCID of the compartment containing the SQL Firewall allowed SQL.


        :return: The compartment_id of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this SqlFirewallAllowedSqlSummary.
        The OCID of the compartment containing the SQL Firewall allowed SQL.


        :param compartment_id: The compartment_id of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this SqlFirewallAllowedSqlSummary.
        The display name of the SQL Firewall allowed SQL.


        :return: The display_name of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this SqlFirewallAllowedSqlSummary.
        The display name of the SQL Firewall allowed SQL.


        :param display_name: The display_name of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this SqlFirewallAllowedSqlSummary.
        The description of the SQL Firewall allowed SQL.


        :return: The description of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this SqlFirewallAllowedSqlSummary.
        The description of the SQL Firewall allowed SQL.


        :param description: The description of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._description = description

    @property
    def sql_firewall_policy_id(self):
        """
        **[Required]** Gets the sql_firewall_policy_id of this SqlFirewallAllowedSqlSummary.
        The OCID of the SQL Firewall policy corresponding to the SQL Firewall allowed SQL.


        :return: The sql_firewall_policy_id of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._sql_firewall_policy_id

    @sql_firewall_policy_id.setter
    def sql_firewall_policy_id(self, sql_firewall_policy_id):
        """
        Sets the sql_firewall_policy_id of this SqlFirewallAllowedSqlSummary.
        The OCID of the SQL Firewall policy corresponding to the SQL Firewall allowed SQL.


        :param sql_firewall_policy_id: The sql_firewall_policy_id of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._sql_firewall_policy_id = sql_firewall_policy_id

    @property
    def current_user(self):
        """
        Gets the current_user of this SqlFirewallAllowedSqlSummary.
        The name of the user that SQL was executed as.


        :return: The current_user of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._current_user

    @current_user.setter
    def current_user(self, current_user):
        """
        Sets the current_user of this SqlFirewallAllowedSqlSummary.
        The name of the user that SQL was executed as.


        :param current_user: The current_user of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._current_user = current_user

    @property
    def db_user_name(self):
        """
        **[Required]** Gets the db_user_name of this SqlFirewallAllowedSqlSummary.
        The database user name.


        :return: The db_user_name of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._db_user_name

    @db_user_name.setter
    def db_user_name(self, db_user_name):
        """
        Sets the db_user_name of this SqlFirewallAllowedSqlSummary.
        The database user name.


        :param db_user_name: The db_user_name of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._db_user_name = db_user_name

    @property
    def sql_text(self):
        """
        **[Required]** Gets the sql_text of this SqlFirewallAllowedSqlSummary.
        The SQL text of the SQL Firewall allowed SQL.


        :return: The sql_text of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._sql_text

    @sql_text.setter
    def sql_text(self, sql_text):
        """
        Sets the sql_text of this SqlFirewallAllowedSqlSummary.
        The SQL text of the SQL Firewall allowed SQL.


        :param sql_text: The sql_text of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        self._sql_text = sql_text

    @property
    def sql_level(self):
        """
        **[Required]** Gets the sql_level of this SqlFirewallAllowedSqlSummary.
        Specifies the level of SQL included for this SQL Firewall policy.
        USER_ISSUED_SQL - User issued SQL statements only.
        ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.

        Allowed values for this property are: "USER_ISSUED_SQL", "ALL_SQL", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The sql_level of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._sql_level

    @sql_level.setter
    def sql_level(self, sql_level):
        """
        Sets the sql_level of this SqlFirewallAllowedSqlSummary.
        Specifies the level of SQL included for this SQL Firewall policy.
        USER_ISSUED_SQL - User issued SQL statements only.
        ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.


        :param sql_level: The sql_level of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        allowed_values = ["USER_ISSUED_SQL", "ALL_SQL"]
        if not value_allowed_none_or_none_sentinel(sql_level, allowed_values):
            sql_level = 'UNKNOWN_ENUM_VALUE'
        self._sql_level = sql_level

    @property
    def sql_accessed_objects(self):
        """
        Gets the sql_accessed_objects of this SqlFirewallAllowedSqlSummary.
        The objects accessed by the SQL.


        :return: The sql_accessed_objects of this SqlFirewallAllowedSqlSummary.
        :rtype: list[str]
        """
        return self._sql_accessed_objects

    @sql_accessed_objects.setter
    def sql_accessed_objects(self, sql_accessed_objects):
        """
        Sets the sql_accessed_objects of this SqlFirewallAllowedSqlSummary.
        The objects accessed by the SQL.


        :param sql_accessed_objects: The sql_accessed_objects of this SqlFirewallAllowedSqlSummary.
        :type: list[str]
        """
        self._sql_accessed_objects = sql_accessed_objects

    @property
    def version(self):
        """
        **[Required]** Gets the version of this SqlFirewallAllowedSqlSummary.
        Version of the associated SQL Firewall policy. This identifies whether the allowed SQLs were added in the same batch or not.


        :return: The version of this SqlFirewallAllowedSqlSummary.
        :rtype: float
        """
        return self._version

    @version.setter
    def version(self, version):
        """
        Sets the version of this SqlFirewallAllowedSqlSummary.
        Version of the associated SQL Firewall policy. This identifies whether the allowed SQLs were added in the same batch or not.


        :param version: The version of this SqlFirewallAllowedSqlSummary.
        :type: float
        """
        self._version = version

    @property
    def time_collected(self):
        """
        **[Required]** Gets the time_collected of this SqlFirewallAllowedSqlSummary.
        The time the the SQL Firewall allowed SQL was collected from the target database, in the format defined by RFC3339.


        :return: The time_collected of this SqlFirewallAllowedSqlSummary.
        :rtype: datetime
        """
        return self._time_collected

    @time_collected.setter
    def time_collected(self, time_collected):
        """
        Sets the time_collected of this SqlFirewallAllowedSqlSummary.
        The time the the SQL Firewall allowed SQL was collected from the target database, in the format defined by RFC3339.


        :param time_collected: The time_collected of this SqlFirewallAllowedSqlSummary.
        :type: datetime
        """
        self._time_collected = time_collected

    @property
    def time_updated(self):
        """
        Gets the time_updated of this SqlFirewallAllowedSqlSummary.
        The last date and time the SQL Firewall allowed SQL was updated, in the format defined by RFC3339.


        :return: The time_updated of this SqlFirewallAllowedSqlSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this SqlFirewallAllowedSqlSummary.
        The last date and time the SQL Firewall allowed SQL was updated, in the format defined by RFC3339.


        :param time_updated: The time_updated of this SqlFirewallAllowedSqlSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this SqlFirewallAllowedSqlSummary.
        The current state of the SQL Firewall allowed SQL.

        Allowed values for this property are: "ACTIVE", "DELETED", "FAILED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The lifecycle_state of this SqlFirewallAllowedSqlSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this SqlFirewallAllowedSqlSummary.
        The current state of the SQL Firewall allowed SQL.


        :param lifecycle_state: The lifecycle_state of this SqlFirewallAllowedSqlSummary.
        :type: str
        """
        allowed_values = ["ACTIVE", "DELETED", "FAILED"]
        if not value_allowed_none_or_none_sentinel(lifecycle_state, allowed_values):
            lifecycle_state = 'UNKNOWN_ENUM_VALUE'
        self._lifecycle_state = lifecycle_state

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this SqlFirewallAllowedSqlSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this SqlFirewallAllowedSqlSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this SqlFirewallAllowedSqlSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see `Resource Tags`__

        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this SqlFirewallAllowedSqlSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this SqlFirewallAllowedSqlSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this SqlFirewallAllowedSqlSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this SqlFirewallAllowedSqlSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see `Resource Tags`__

        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this SqlFirewallAllowedSqlSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this SqlFirewallAllowedSqlSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this SqlFirewallAllowedSqlSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this SqlFirewallAllowedSqlSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this SqlFirewallAllowedSqlSummary.
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
