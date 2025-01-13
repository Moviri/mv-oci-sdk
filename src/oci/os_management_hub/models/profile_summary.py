# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220901


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class ProfileSummary(object):
    """
    Provides summary information for a registration profile.
    """

    #: A constant which can be used with the profile_type property of a ProfileSummary.
    #: This constant has a value of "SOFTWARESOURCE"
    PROFILE_TYPE_SOFTWARESOURCE = "SOFTWARESOURCE"

    #: A constant which can be used with the profile_type property of a ProfileSummary.
    #: This constant has a value of "GROUP"
    PROFILE_TYPE_GROUP = "GROUP"

    #: A constant which can be used with the profile_type property of a ProfileSummary.
    #: This constant has a value of "LIFECYCLE"
    PROFILE_TYPE_LIFECYCLE = "LIFECYCLE"

    #: A constant which can be used with the profile_type property of a ProfileSummary.
    #: This constant has a value of "STATION"
    PROFILE_TYPE_STATION = "STATION"

    #: A constant which can be used with the profile_type property of a ProfileSummary.
    #: This constant has a value of "WINDOWS_STANDALONE"
    PROFILE_TYPE_WINDOWS_STANDALONE = "WINDOWS_STANDALONE"

    #: A constant which can be used with the vendor_name property of a ProfileSummary.
    #: This constant has a value of "ORACLE"
    VENDOR_NAME_ORACLE = "ORACLE"

    #: A constant which can be used with the vendor_name property of a ProfileSummary.
    #: This constant has a value of "MICROSOFT"
    VENDOR_NAME_MICROSOFT = "MICROSOFT"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "ORACLE_LINUX_9"
    OS_FAMILY_ORACLE_LINUX_9 = "ORACLE_LINUX_9"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "ORACLE_LINUX_8"
    OS_FAMILY_ORACLE_LINUX_8 = "ORACLE_LINUX_8"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "ORACLE_LINUX_7"
    OS_FAMILY_ORACLE_LINUX_7 = "ORACLE_LINUX_7"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "ORACLE_LINUX_6"
    OS_FAMILY_ORACLE_LINUX_6 = "ORACLE_LINUX_6"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "WINDOWS_SERVER_2016"
    OS_FAMILY_WINDOWS_SERVER_2016 = "WINDOWS_SERVER_2016"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "WINDOWS_SERVER_2019"
    OS_FAMILY_WINDOWS_SERVER_2019 = "WINDOWS_SERVER_2019"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "WINDOWS_SERVER_2022"
    OS_FAMILY_WINDOWS_SERVER_2022 = "WINDOWS_SERVER_2022"

    #: A constant which can be used with the os_family property of a ProfileSummary.
    #: This constant has a value of "ALL"
    OS_FAMILY_ALL = "ALL"

    #: A constant which can be used with the arch_type property of a ProfileSummary.
    #: This constant has a value of "X86_64"
    ARCH_TYPE_X86_64 = "X86_64"

    #: A constant which can be used with the arch_type property of a ProfileSummary.
    #: This constant has a value of "AARCH64"
    ARCH_TYPE_AARCH64 = "AARCH64"

    #: A constant which can be used with the arch_type property of a ProfileSummary.
    #: This constant has a value of "I686"
    ARCH_TYPE_I686 = "I686"

    #: A constant which can be used with the arch_type property of a ProfileSummary.
    #: This constant has a value of "NOARCH"
    ARCH_TYPE_NOARCH = "NOARCH"

    #: A constant which can be used with the arch_type property of a ProfileSummary.
    #: This constant has a value of "SRC"
    ARCH_TYPE_SRC = "SRC"

    def __init__(self, **kwargs):
        """
        Initializes a new ProfileSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param id:
            The value to assign to the id property of this ProfileSummary.
        :type id: str

        :param display_name:
            The value to assign to the display_name property of this ProfileSummary.
        :type display_name: str

        :param description:
            The value to assign to the description property of this ProfileSummary.
        :type description: str

        :param compartment_id:
            The value to assign to the compartment_id property of this ProfileSummary.
        :type compartment_id: str

        :param management_station_id:
            The value to assign to the management_station_id property of this ProfileSummary.
        :type management_station_id: str

        :param profile_type:
            The value to assign to the profile_type property of this ProfileSummary.
            Allowed values for this property are: "SOFTWARESOURCE", "GROUP", "LIFECYCLE", "STATION", "WINDOWS_STANDALONE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type profile_type: str

        :param registration_type:
            The value to assign to the registration_type property of this ProfileSummary.
        :type registration_type: str

        :param vendor_name:
            The value to assign to the vendor_name property of this ProfileSummary.
            Allowed values for this property are: "ORACLE", "MICROSOFT", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type vendor_name: str

        :param os_family:
            The value to assign to the os_family property of this ProfileSummary.
            Allowed values for this property are: "ORACLE_LINUX_9", "ORACLE_LINUX_8", "ORACLE_LINUX_7", "ORACLE_LINUX_6", "WINDOWS_SERVER_2016", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022", "ALL", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type os_family: str

        :param arch_type:
            The value to assign to the arch_type property of this ProfileSummary.
            Allowed values for this property are: "X86_64", "AARCH64", "I686", "NOARCH", "SRC", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type arch_type: str

        :param time_created:
            The value to assign to the time_created property of this ProfileSummary.
        :type time_created: datetime

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this ProfileSummary.
        :type lifecycle_state: str

        :param is_default_profile:
            The value to assign to the is_default_profile property of this ProfileSummary.
        :type is_default_profile: bool

        :param is_service_provided_profile:
            The value to assign to the is_service_provided_profile property of this ProfileSummary.
        :type is_service_provided_profile: bool

        :param freeform_tags:
            The value to assign to the freeform_tags property of this ProfileSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this ProfileSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this ProfileSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'id': 'str',
            'display_name': 'str',
            'description': 'str',
            'compartment_id': 'str',
            'management_station_id': 'str',
            'profile_type': 'str',
            'registration_type': 'str',
            'vendor_name': 'str',
            'os_family': 'str',
            'arch_type': 'str',
            'time_created': 'datetime',
            'lifecycle_state': 'str',
            'is_default_profile': 'bool',
            'is_service_provided_profile': 'bool',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'id': 'id',
            'display_name': 'displayName',
            'description': 'description',
            'compartment_id': 'compartmentId',
            'management_station_id': 'managementStationId',
            'profile_type': 'profileType',
            'registration_type': 'registrationType',
            'vendor_name': 'vendorName',
            'os_family': 'osFamily',
            'arch_type': 'archType',
            'time_created': 'timeCreated',
            'lifecycle_state': 'lifecycleState',
            'is_default_profile': 'isDefaultProfile',
            'is_service_provided_profile': 'isServiceProvidedProfile',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._id = None
        self._display_name = None
        self._description = None
        self._compartment_id = None
        self._management_station_id = None
        self._profile_type = None
        self._registration_type = None
        self._vendor_name = None
        self._os_family = None
        self._arch_type = None
        self._time_created = None
        self._lifecycle_state = None
        self._is_default_profile = None
        self._is_service_provided_profile = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def id(self):
        """
        **[Required]** Gets the id of this ProfileSummary.
        The `OCID`__ of the registration profile.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The id of this ProfileSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this ProfileSummary.
        The `OCID`__ of the registration profile.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param id: The id of this ProfileSummary.
        :type: str
        """
        self._id = id

    @property
    def display_name(self):
        """
        Gets the display_name of this ProfileSummary.
        A user-friendly name for the profile.


        :return: The display_name of this ProfileSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this ProfileSummary.
        A user-friendly name for the profile.


        :param display_name: The display_name of this ProfileSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def description(self):
        """
        Gets the description of this ProfileSummary.
        User-specified description of the registration profile.


        :return: The description of this ProfileSummary.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this ProfileSummary.
        User-specified description of the registration profile.


        :param description: The description of this ProfileSummary.
        :type: str
        """
        self._description = description

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this ProfileSummary.
        The `OCID`__ of the compartment that contains the registration profile.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this ProfileSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this ProfileSummary.
        The `OCID`__ of the compartment that contains the registration profile.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this ProfileSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def management_station_id(self):
        """
        Gets the management_station_id of this ProfileSummary.
        The `OCID`__ of the management station to associate with an instance once registered. Associating with a management station applies only to non-OCI instances.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The management_station_id of this ProfileSummary.
        :rtype: str
        """
        return self._management_station_id

    @management_station_id.setter
    def management_station_id(self, management_station_id):
        """
        Sets the management_station_id of this ProfileSummary.
        The `OCID`__ of the management station to associate with an instance once registered. Associating with a management station applies only to non-OCI instances.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param management_station_id: The management_station_id of this ProfileSummary.
        :type: str
        """
        self._management_station_id = management_station_id

    @property
    def profile_type(self):
        """
        Gets the profile_type of this ProfileSummary.
        The type of registration profile.

        Allowed values for this property are: "SOFTWARESOURCE", "GROUP", "LIFECYCLE", "STATION", "WINDOWS_STANDALONE", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The profile_type of this ProfileSummary.
        :rtype: str
        """
        return self._profile_type

    @profile_type.setter
    def profile_type(self, profile_type):
        """
        Sets the profile_type of this ProfileSummary.
        The type of registration profile.


        :param profile_type: The profile_type of this ProfileSummary.
        :type: str
        """
        allowed_values = ["SOFTWARESOURCE", "GROUP", "LIFECYCLE", "STATION", "WINDOWS_STANDALONE"]
        if not value_allowed_none_or_none_sentinel(profile_type, allowed_values):
            profile_type = 'UNKNOWN_ENUM_VALUE'
        self._profile_type = profile_type

    @property
    def registration_type(self):
        """
        Gets the registration_type of this ProfileSummary.
        The type of instance to register.


        :return: The registration_type of this ProfileSummary.
        :rtype: str
        """
        return self._registration_type

    @registration_type.setter
    def registration_type(self, registration_type):
        """
        Sets the registration_type of this ProfileSummary.
        The type of instance to register.


        :param registration_type: The registration_type of this ProfileSummary.
        :type: str
        """
        self._registration_type = registration_type

    @property
    def vendor_name(self):
        """
        Gets the vendor_name of this ProfileSummary.
        The vendor of the operating system for the instance.

        Allowed values for this property are: "ORACLE", "MICROSOFT", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The vendor_name of this ProfileSummary.
        :rtype: str
        """
        return self._vendor_name

    @vendor_name.setter
    def vendor_name(self, vendor_name):
        """
        Sets the vendor_name of this ProfileSummary.
        The vendor of the operating system for the instance.


        :param vendor_name: The vendor_name of this ProfileSummary.
        :type: str
        """
        allowed_values = ["ORACLE", "MICROSOFT"]
        if not value_allowed_none_or_none_sentinel(vendor_name, allowed_values):
            vendor_name = 'UNKNOWN_ENUM_VALUE'
        self._vendor_name = vendor_name

    @property
    def os_family(self):
        """
        Gets the os_family of this ProfileSummary.
        The operating system family.

        Allowed values for this property are: "ORACLE_LINUX_9", "ORACLE_LINUX_8", "ORACLE_LINUX_7", "ORACLE_LINUX_6", "WINDOWS_SERVER_2016", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022", "ALL", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The os_family of this ProfileSummary.
        :rtype: str
        """
        return self._os_family

    @os_family.setter
    def os_family(self, os_family):
        """
        Sets the os_family of this ProfileSummary.
        The operating system family.


        :param os_family: The os_family of this ProfileSummary.
        :type: str
        """
        allowed_values = ["ORACLE_LINUX_9", "ORACLE_LINUX_8", "ORACLE_LINUX_7", "ORACLE_LINUX_6", "WINDOWS_SERVER_2016", "WINDOWS_SERVER_2019", "WINDOWS_SERVER_2022", "ALL"]
        if not value_allowed_none_or_none_sentinel(os_family, allowed_values):
            os_family = 'UNKNOWN_ENUM_VALUE'
        self._os_family = os_family

    @property
    def arch_type(self):
        """
        Gets the arch_type of this ProfileSummary.
        The architecture type.

        Allowed values for this property are: "X86_64", "AARCH64", "I686", "NOARCH", "SRC", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The arch_type of this ProfileSummary.
        :rtype: str
        """
        return self._arch_type

    @arch_type.setter
    def arch_type(self, arch_type):
        """
        Sets the arch_type of this ProfileSummary.
        The architecture type.


        :param arch_type: The arch_type of this ProfileSummary.
        :type: str
        """
        allowed_values = ["X86_64", "AARCH64", "I686", "NOARCH", "SRC"]
        if not value_allowed_none_or_none_sentinel(arch_type, allowed_values):
            arch_type = 'UNKNOWN_ENUM_VALUE'
        self._arch_type = arch_type

    @property
    def time_created(self):
        """
        Gets the time_created of this ProfileSummary.
        The time the the Onboarding was created. An RFC3339 formatted datetime string


        :return: The time_created of this ProfileSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this ProfileSummary.
        The time the the Onboarding was created. An RFC3339 formatted datetime string


        :param time_created: The time_created of this ProfileSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def lifecycle_state(self):
        """
        Gets the lifecycle_state of this ProfileSummary.
        The current state of the registration profile.


        :return: The lifecycle_state of this ProfileSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this ProfileSummary.
        The current state of the registration profile.


        :param lifecycle_state: The lifecycle_state of this ProfileSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def is_default_profile(self):
        """
        Gets the is_default_profile of this ProfileSummary.
        Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.


        :return: The is_default_profile of this ProfileSummary.
        :rtype: bool
        """
        return self._is_default_profile

    @is_default_profile.setter
    def is_default_profile(self, is_default_profile):
        """
        Sets the is_default_profile of this ProfileSummary.
        Indicates if the profile is set as the default. There is exactly one default profile for a specified architecture, OS family, registration type, and vendor. When registering an instance with the corresonding characteristics, the default profile is used, unless another profile is specified.


        :param is_default_profile: The is_default_profile of this ProfileSummary.
        :type: bool
        """
        self._is_default_profile = is_default_profile

    @property
    def is_service_provided_profile(self):
        """
        Gets the is_service_provided_profile of this ProfileSummary.
        Indicates if the profile was created by the service. OS Management Hub provides a limited set of standardized profiles that can be used to register Autonomous Linux or Windows instances.


        :return: The is_service_provided_profile of this ProfileSummary.
        :rtype: bool
        """
        return self._is_service_provided_profile

    @is_service_provided_profile.setter
    def is_service_provided_profile(self, is_service_provided_profile):
        """
        Sets the is_service_provided_profile of this ProfileSummary.
        Indicates if the profile was created by the service. OS Management Hub provides a limited set of standardized profiles that can be used to register Autonomous Linux or Windows instances.


        :param is_service_provided_profile: The is_service_provided_profile of this ProfileSummary.
        :type: bool
        """
        self._is_service_provided_profile = is_service_provided_profile

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this ProfileSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this ProfileSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this ProfileSummary.
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this ProfileSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this ProfileSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this ProfileSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this ProfileSummary.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this ProfileSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this ProfileSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :return: The system_tags of this ProfileSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this ProfileSummary.
        System tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`


        :param system_tags: The system_tags of this ProfileSummary.
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
