# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220901


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class WindowsUpdateSummary(object):
    """
    Provides summary information about an update for a Windows instance.
    """

    #: A constant which can be used with the update_type property of a WindowsUpdateSummary.
    #: This constant has a value of "SECURITY"
    UPDATE_TYPE_SECURITY = "SECURITY"

    #: A constant which can be used with the update_type property of a WindowsUpdateSummary.
    #: This constant has a value of "BUGFIX"
    UPDATE_TYPE_BUGFIX = "BUGFIX"

    #: A constant which can be used with the update_type property of a WindowsUpdateSummary.
    #: This constant has a value of "ENHANCEMENT"
    UPDATE_TYPE_ENHANCEMENT = "ENHANCEMENT"

    #: A constant which can be used with the update_type property of a WindowsUpdateSummary.
    #: This constant has a value of "OTHER"
    UPDATE_TYPE_OTHER = "OTHER"

    def __init__(self, **kwargs):
        """
        Initializes a new WindowsUpdateSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param name:
            The value to assign to the name property of this WindowsUpdateSummary.
        :type name: str

        :param update_id:
            The value to assign to the update_id property of this WindowsUpdateSummary.
        :type update_id: str

        :param update_type:
            The value to assign to the update_type property of this WindowsUpdateSummary.
            Allowed values for this property are: "SECURITY", "BUGFIX", "ENHANCEMENT", "OTHER", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type update_type: str

        :param installable:
            The value to assign to the installable property of this WindowsUpdateSummary.
        :type installable: str

        :param is_reboot_required_for_installation:
            The value to assign to the is_reboot_required_for_installation property of this WindowsUpdateSummary.
        :type is_reboot_required_for_installation: bool

        """
        self.swagger_types = {
            'name': 'str',
            'update_id': 'str',
            'update_type': 'str',
            'installable': 'str',
            'is_reboot_required_for_installation': 'bool'
        }

        self.attribute_map = {
            'name': 'name',
            'update_id': 'updateId',
            'update_type': 'updateType',
            'installable': 'installable',
            'is_reboot_required_for_installation': 'isRebootRequiredForInstallation'
        }

        self._name = None
        self._update_id = None
        self._update_type = None
        self._installable = None
        self._is_reboot_required_for_installation = None

    @property
    def name(self):
        """
        **[Required]** Gets the name of this WindowsUpdateSummary.
        Name of the Windows update.


        :return: The name of this WindowsUpdateSummary.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this WindowsUpdateSummary.
        Name of the Windows update.


        :param name: The name of this WindowsUpdateSummary.
        :type: str
        """
        self._name = name

    @property
    def update_id(self):
        """
        **[Required]** Gets the update_id of this WindowsUpdateSummary.
        Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.
        Example: 6981d463-cd91-4a26-b7c4-ea4ded9183ed


        :return: The update_id of this WindowsUpdateSummary.
        :rtype: str
        """
        return self._update_id

    @update_id.setter
    def update_id(self, update_id):
        """
        Sets the update_id of this WindowsUpdateSummary.
        Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.
        Example: 6981d463-cd91-4a26-b7c4-ea4ded9183ed


        :param update_id: The update_id of this WindowsUpdateSummary.
        :type: str
        """
        self._update_id = update_id

    @property
    def update_type(self):
        """
        **[Required]** Gets the update_type of this WindowsUpdateSummary.
        The type of Windows update.

        Allowed values for this property are: "SECURITY", "BUGFIX", "ENHANCEMENT", "OTHER", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The update_type of this WindowsUpdateSummary.
        :rtype: str
        """
        return self._update_type

    @update_type.setter
    def update_type(self, update_type):
        """
        Sets the update_type of this WindowsUpdateSummary.
        The type of Windows update.


        :param update_type: The update_type of this WindowsUpdateSummary.
        :type: str
        """
        allowed_values = ["SECURITY", "BUGFIX", "ENHANCEMENT", "OTHER"]
        if not value_allowed_none_or_none_sentinel(update_type, allowed_values):
            update_type = 'UNKNOWN_ENUM_VALUE'
        self._update_type = update_type

    @property
    def installable(self):
        """
        Gets the installable of this WindowsUpdateSummary.
        Indicates whether the update can be installed using the service.


        :return: The installable of this WindowsUpdateSummary.
        :rtype: str
        """
        return self._installable

    @installable.setter
    def installable(self, installable):
        """
        Sets the installable of this WindowsUpdateSummary.
        Indicates whether the update can be installed using the service.


        :param installable: The installable of this WindowsUpdateSummary.
        :type: str
        """
        self._installable = installable

    @property
    def is_reboot_required_for_installation(self):
        """
        Gets the is_reboot_required_for_installation of this WindowsUpdateSummary.
        Indicates whether a reboot is required to complete the installation of this update.


        :return: The is_reboot_required_for_installation of this WindowsUpdateSummary.
        :rtype: bool
        """
        return self._is_reboot_required_for_installation

    @is_reboot_required_for_installation.setter
    def is_reboot_required_for_installation(self, is_reboot_required_for_installation):
        """
        Sets the is_reboot_required_for_installation of this WindowsUpdateSummary.
        Indicates whether a reboot is required to complete the installation of this update.


        :param is_reboot_required_for_installation: The is_reboot_required_for_installation of this WindowsUpdateSummary.
        :type: bool
        """
        self._is_reboot_required_for_installation = is_reboot_required_for_installation

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
