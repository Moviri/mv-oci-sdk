# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20230831


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class FleetTargetSummary(object):
    """
    Summary of a confirmed target within a fleet.
    """

    #: A constant which can be used with the compliance_state property of a FleetTargetSummary.
    #: This constant has a value of "UNKNOWN"
    COMPLIANCE_STATE_UNKNOWN = "UNKNOWN"

    #: A constant which can be used with the compliance_state property of a FleetTargetSummary.
    #: This constant has a value of "COMPLIANT"
    COMPLIANCE_STATE_COMPLIANT = "COMPLIANT"

    #: A constant which can be used with the compliance_state property of a FleetTargetSummary.
    #: This constant has a value of "NON_COMPLIANT"
    COMPLIANCE_STATE_NON_COMPLIANT = "NON_COMPLIANT"

    #: A constant which can be used with the compliance_state property of a FleetTargetSummary.
    #: This constant has a value of "WARNING"
    COMPLIANCE_STATE_WARNING = "WARNING"

    def __init__(self, **kwargs):
        """
        Initializes a new FleetTargetSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this FleetTargetSummary.
        :type id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this FleetTargetSummary.
        :type compartment_id: str

        :param display_name:
            The value to assign to the display_name property of this FleetTargetSummary.
        :type display_name: str

        :param version:
            The value to assign to the version property of this FleetTargetSummary.
        :type version: str

        :param product:
            The value to assign to the product property of this FleetTargetSummary.
        :type product: str

        :param resource:
            The value to assign to the resource property of this FleetTargetSummary.
        :type resource: oci.fleet_apps_management.models.TargetResource

        :param compliance_state:
            The value to assign to the compliance_state property of this FleetTargetSummary.
            Allowed values for this property are: "UNKNOWN", "COMPLIANT", "NON_COMPLIANT", "WARNING", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type compliance_state: str

        :param time_of_last_successful_discovery:
            The value to assign to the time_of_last_successful_discovery property of this FleetTargetSummary.
        :type time_of_last_successful_discovery: datetime

        :param time_of_last_discovery_attempt:
            The value to assign to the time_of_last_discovery_attempt property of this FleetTargetSummary.
        :type time_of_last_discovery_attempt: datetime

        :param is_last_discovery_attempt_successful:
            The value to assign to the is_last_discovery_attempt_successful property of this FleetTargetSummary.
        :type is_last_discovery_attempt_successful: bool

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this FleetTargetSummary.
        :type lifecycle_state: str

        :param system_tags:
            The value to assign to the system_tags property of this FleetTargetSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'compartment_id': 'str',
            'display_name': 'str',
            'version': 'str',
            'product': 'str',
            'resource': 'TargetResource',
            'compliance_state': 'str',
            'time_of_last_successful_discovery': 'datetime',
            'time_of_last_discovery_attempt': 'datetime',
            'is_last_discovery_attempt_successful': 'bool',
            'lifecycle_state': 'str',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'compartment_id': 'compartmentId',
            'display_name': 'displayName',
            'version': 'version',
            'product': 'product',
            'resource': 'resource',
            'compliance_state': 'complianceState',
            'time_of_last_successful_discovery': 'timeOfLastSuccessfulDiscovery',
            'time_of_last_discovery_attempt': 'timeOfLastDiscoveryAttempt',
            'is_last_discovery_attempt_successful': 'isLastDiscoveryAttemptSuccessful',
            'lifecycle_state': 'lifecycleState',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._compartment_id = None
        self._display_name = None
        self._version = None
        self._product = None
        self._resource = None
        self._compliance_state = None
        self._time_of_last_successful_discovery = None
        self._time_of_last_discovery_attempt = None
        self._is_last_discovery_attempt_successful = None
        self._lifecycle_state = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this FleetTargetSummary.
        The OCID of the resource.


        :return: The id of this FleetTargetSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this FleetTargetSummary.
        The OCID of the resource.


        :param id: The id of this FleetTargetSummary.
        :type: str
        """
        self._id = id

    @property
    def compartment_id(self):
        """
        Gets the compartment_id of this FleetTargetSummary.
        Tenancy OCID


        :return: The compartment_id of this FleetTargetSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this FleetTargetSummary.
        Tenancy OCID


        :param compartment_id: The compartment_id of this FleetTargetSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def display_name(self):
        """
        **[Required]** Gets the display_name of this FleetTargetSummary.
        A user-friendly name. Does not have to be unique, and it's changeable.
        Avoid entering confidential information.

        Example: `My new resource`


        :return: The display_name of this FleetTargetSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this FleetTargetSummary.
        A user-friendly name. Does not have to be unique, and it's changeable.
        Avoid entering confidential information.

        Example: `My new resource`


        :param display_name: The display_name of this FleetTargetSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def version(self):
        """
        Gets the version of this FleetTargetSummary.
        Current version of target.


        :return: The version of this FleetTargetSummary.
        :rtype: str
        """
        return self._version

    @version.setter
    def version(self, version):
        """
        Sets the version of this FleetTargetSummary.
        Current version of target.


        :param version: The version of this FleetTargetSummary.
        :type: str
        """
        self._version = version

    @property
    def product(self):
        """
        Gets the product of this FleetTargetSummary.
        Product to which the target belongs to.


        :return: The product of this FleetTargetSummary.
        :rtype: str
        """
        return self._product

    @product.setter
    def product(self, product):
        """
        Sets the product of this FleetTargetSummary.
        Product to which the target belongs to.


        :param product: The product of this FleetTargetSummary.
        :type: str
        """
        self._product = product

    @property
    def resource(self):
        """
        Gets the resource of this FleetTargetSummary.

        :return: The resource of this FleetTargetSummary.
        :rtype: oci.fleet_apps_management.models.TargetResource
        """
        return self._resource

    @resource.setter
    def resource(self, resource):
        """
        Sets the resource of this FleetTargetSummary.

        :param resource: The resource of this FleetTargetSummary.
        :type: oci.fleet_apps_management.models.TargetResource
        """
        self._resource = resource

    @property
    def compliance_state(self):
        """
        Gets the compliance_state of this FleetTargetSummary.
        The last known compliance state of the target.

        Allowed values for this property are: "UNKNOWN", "COMPLIANT", "NON_COMPLIANT", "WARNING", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The compliance_state of this FleetTargetSummary.
        :rtype: str
        """
        return self._compliance_state

    @compliance_state.setter
    def compliance_state(self, compliance_state):
        """
        Sets the compliance_state of this FleetTargetSummary.
        The last known compliance state of the target.


        :param compliance_state: The compliance_state of this FleetTargetSummary.
        :type: str
        """
        allowed_values = ["UNKNOWN", "COMPLIANT", "NON_COMPLIANT", "WARNING"]
        if not value_allowed_none_or_none_sentinel(compliance_state, allowed_values):
            compliance_state = 'UNKNOWN_ENUM_VALUE'
        self._compliance_state = compliance_state

    @property
    def time_of_last_successful_discovery(self):
        """
        Gets the time_of_last_successful_discovery of this FleetTargetSummary.
        The time when the last successful discovery was made.


        :return: The time_of_last_successful_discovery of this FleetTargetSummary.
        :rtype: datetime
        """
        return self._time_of_last_successful_discovery

    @time_of_last_successful_discovery.setter
    def time_of_last_successful_discovery(self, time_of_last_successful_discovery):
        """
        Sets the time_of_last_successful_discovery of this FleetTargetSummary.
        The time when the last successful discovery was made.


        :param time_of_last_successful_discovery: The time_of_last_successful_discovery of this FleetTargetSummary.
        :type: datetime
        """
        self._time_of_last_successful_discovery = time_of_last_successful_discovery

    @property
    def time_of_last_discovery_attempt(self):
        """
        Gets the time_of_last_discovery_attempt of this FleetTargetSummary.
        The time when last discovery was attempted.


        :return: The time_of_last_discovery_attempt of this FleetTargetSummary.
        :rtype: datetime
        """
        return self._time_of_last_discovery_attempt

    @time_of_last_discovery_attempt.setter
    def time_of_last_discovery_attempt(self, time_of_last_discovery_attempt):
        """
        Sets the time_of_last_discovery_attempt of this FleetTargetSummary.
        The time when last discovery was attempted.


        :param time_of_last_discovery_attempt: The time_of_last_discovery_attempt of this FleetTargetSummary.
        :type: datetime
        """
        self._time_of_last_discovery_attempt = time_of_last_discovery_attempt

    @property
    def is_last_discovery_attempt_successful(self):
        """
        Gets the is_last_discovery_attempt_successful of this FleetTargetSummary.
        A boolean flag that represents whether the last discovery attempt was successful.


        :return: The is_last_discovery_attempt_successful of this FleetTargetSummary.
        :rtype: bool
        """
        return self._is_last_discovery_attempt_successful

    @is_last_discovery_attempt_successful.setter
    def is_last_discovery_attempt_successful(self, is_last_discovery_attempt_successful):
        """
        Sets the is_last_discovery_attempt_successful of this FleetTargetSummary.
        A boolean flag that represents whether the last discovery attempt was successful.


        :param is_last_discovery_attempt_successful: The is_last_discovery_attempt_successful of this FleetTargetSummary.
        :type: bool
        """
        self._is_last_discovery_attempt_successful = is_last_discovery_attempt_successful

    @property
    def lifecycle_state(self):
        """
        Gets the lifecycle_state of this FleetTargetSummary.
        The current state of the FleetTarget.


        :return: The lifecycle_state of this FleetTargetSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this FleetTargetSummary.
        The current state of the FleetTarget.


        :param lifecycle_state: The lifecycle_state of this FleetTargetSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def system_tags(self):
        """
        Gets the system_tags of this FleetTargetSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this FleetTargetSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this FleetTargetSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this FleetTargetSummary.
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
