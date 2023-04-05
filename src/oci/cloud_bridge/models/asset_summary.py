# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class AssetSummary(object):
    """
    Summary of the asset.
    """

    #: A constant which can be used with the asset_type property of a AssetSummary.
    #: This constant has a value of "VMWARE_VM"
    ASSET_TYPE_VMWARE_VM = "VMWARE_VM"

    #: A constant which can be used with the asset_type property of a AssetSummary.
    #: This constant has a value of "VM"
    ASSET_TYPE_VM = "VM"

    def __init__(self, **kwargs):
        """
        Initializes a new AssetSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this AssetSummary.
        :type display_name: str

        :param inventory_id:
            The value to assign to the inventory_id property of this AssetSummary.
        :type inventory_id: str

        :param id:
            The value to assign to the id property of this AssetSummary.
        :type id: str

        :param compartment_id:
            The value to assign to the compartment_id property of this AssetSummary.
        :type compartment_id: str

        :param source_key:
            The value to assign to the source_key property of this AssetSummary.
        :type source_key: str

        :param external_asset_key:
            The value to assign to the external_asset_key property of this AssetSummary.
        :type external_asset_key: str

        :param asset_type:
            The value to assign to the asset_type property of this AssetSummary.
            Allowed values for this property are: "VMWARE_VM", "VM", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type asset_type: str

        :param time_created:
            The value to assign to the time_created property of this AssetSummary.
        :type time_created: datetime

        :param time_updated:
            The value to assign to the time_updated property of this AssetSummary.
        :type time_updated: datetime

        :param asset_source_ids:
            The value to assign to the asset_source_ids property of this AssetSummary.
        :type asset_source_ids: list[str]

        :param lifecycle_state:
            The value to assign to the lifecycle_state property of this AssetSummary.
        :type lifecycle_state: str

        :param freeform_tags:
            The value to assign to the freeform_tags property of this AssetSummary.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this AssetSummary.
        :type defined_tags: dict(str, dict(str, object))

        :param system_tags:
            The value to assign to the system_tags property of this AssetSummary.
        :type system_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'display_name': 'str',
            'inventory_id': 'str',
            'id': 'str',
            'compartment_id': 'str',
            'source_key': 'str',
            'external_asset_key': 'str',
            'asset_type': 'str',
            'time_created': 'datetime',
            'time_updated': 'datetime',
            'asset_source_ids': 'list[str]',
            'lifecycle_state': 'str',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))',
            'system_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'inventory_id': 'inventoryId',
            'id': 'id',
            'compartment_id': 'compartmentId',
            'source_key': 'sourceKey',
            'external_asset_key': 'externalAssetKey',
            'asset_type': 'assetType',
            'time_created': 'timeCreated',
            'time_updated': 'timeUpdated',
            'asset_source_ids': 'assetSourceIds',
            'lifecycle_state': 'lifecycleState',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags',
            'system_tags': 'systemTags'
        }

        self._display_name = None
        self._inventory_id = None
        self._id = None
        self._compartment_id = None
        self._source_key = None
        self._external_asset_key = None
        self._asset_type = None
        self._time_created = None
        self._time_updated = None
        self._asset_source_ids = None
        self._lifecycle_state = None
        self._freeform_tags = None
        self._defined_tags = None
        self._system_tags = None

    @property
    def display_name(self):
        """
        Gets the display_name of this AssetSummary.
        Asset display name.


        :return: The display_name of this AssetSummary.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this AssetSummary.
        Asset display name.


        :param display_name: The display_name of this AssetSummary.
        :type: str
        """
        self._display_name = display_name

    @property
    def inventory_id(self):
        """
        **[Required]** Gets the inventory_id of this AssetSummary.
        Inventory ID that the asset belongs to.


        :return: The inventory_id of this AssetSummary.
        :rtype: str
        """
        return self._inventory_id

    @inventory_id.setter
    def inventory_id(self, inventory_id):
        """
        Sets the inventory_id of this AssetSummary.
        Inventory ID that the asset belongs to.


        :param inventory_id: The inventory_id of this AssetSummary.
        :type: str
        """
        self._inventory_id = inventory_id

    @property
    def id(self):
        """
        **[Required]** Gets the id of this AssetSummary.
        Asset OCID that is immutable on creation.


        :return: The id of this AssetSummary.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this AssetSummary.
        Asset OCID that is immutable on creation.


        :param id: The id of this AssetSummary.
        :type: str
        """
        self._id = id

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this AssetSummary.
        The OCID of the compartment that the asset belongs to.


        :return: The compartment_id of this AssetSummary.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this AssetSummary.
        The OCID of the compartment that the asset belongs to.


        :param compartment_id: The compartment_id of this AssetSummary.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def source_key(self):
        """
        **[Required]** Gets the source_key of this AssetSummary.
        The source key to which the asset belongs.


        :return: The source_key of this AssetSummary.
        :rtype: str
        """
        return self._source_key

    @source_key.setter
    def source_key(self, source_key):
        """
        Sets the source_key of this AssetSummary.
        The source key to which the asset belongs.


        :param source_key: The source_key of this AssetSummary.
        :type: str
        """
        self._source_key = source_key

    @property
    def external_asset_key(self):
        """
        **[Required]** Gets the external_asset_key of this AssetSummary.
        The key of the asset from the external environment.


        :return: The external_asset_key of this AssetSummary.
        :rtype: str
        """
        return self._external_asset_key

    @external_asset_key.setter
    def external_asset_key(self, external_asset_key):
        """
        Sets the external_asset_key of this AssetSummary.
        The key of the asset from the external environment.


        :param external_asset_key: The external_asset_key of this AssetSummary.
        :type: str
        """
        self._external_asset_key = external_asset_key

    @property
    def asset_type(self):
        """
        **[Required]** Gets the asset_type of this AssetSummary.
        The type of asset.

        Allowed values for this property are: "VMWARE_VM", "VM", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The asset_type of this AssetSummary.
        :rtype: str
        """
        return self._asset_type

    @asset_type.setter
    def asset_type(self, asset_type):
        """
        Sets the asset_type of this AssetSummary.
        The type of asset.


        :param asset_type: The asset_type of this AssetSummary.
        :type: str
        """
        allowed_values = ["VMWARE_VM", "VM"]
        if not value_allowed_none_or_none_sentinel(asset_type, allowed_values):
            asset_type = 'UNKNOWN_ENUM_VALUE'
        self._asset_type = asset_type

    @property
    def time_created(self):
        """
        **[Required]** Gets the time_created of this AssetSummary.
        The time when the asset was created. An RFC3339 formatted datetime string.


        :return: The time_created of this AssetSummary.
        :rtype: datetime
        """
        return self._time_created

    @time_created.setter
    def time_created(self, time_created):
        """
        Sets the time_created of this AssetSummary.
        The time when the asset was created. An RFC3339 formatted datetime string.


        :param time_created: The time_created of this AssetSummary.
        :type: datetime
        """
        self._time_created = time_created

    @property
    def time_updated(self):
        """
        **[Required]** Gets the time_updated of this AssetSummary.
        The time when the asset was updated. An RFC3339 formatted datetime string.


        :return: The time_updated of this AssetSummary.
        :rtype: datetime
        """
        return self._time_updated

    @time_updated.setter
    def time_updated(self, time_updated):
        """
        Sets the time_updated of this AssetSummary.
        The time when the asset was updated. An RFC3339 formatted datetime string.


        :param time_updated: The time_updated of this AssetSummary.
        :type: datetime
        """
        self._time_updated = time_updated

    @property
    def asset_source_ids(self):
        """
        Gets the asset_source_ids of this AssetSummary.
        List of asset source OCID.


        :return: The asset_source_ids of this AssetSummary.
        :rtype: list[str]
        """
        return self._asset_source_ids

    @asset_source_ids.setter
    def asset_source_ids(self, asset_source_ids):
        """
        Sets the asset_source_ids of this AssetSummary.
        List of asset source OCID.


        :param asset_source_ids: The asset_source_ids of this AssetSummary.
        :type: list[str]
        """
        self._asset_source_ids = asset_source_ids

    @property
    def lifecycle_state(self):
        """
        **[Required]** Gets the lifecycle_state of this AssetSummary.
        The current state of the asset.


        :return: The lifecycle_state of this AssetSummary.
        :rtype: str
        """
        return self._lifecycle_state

    @lifecycle_state.setter
    def lifecycle_state(self, lifecycle_state):
        """
        Sets the lifecycle_state of this AssetSummary.
        The current state of the asset.


        :param lifecycle_state: The lifecycle_state of this AssetSummary.
        :type: str
        """
        self._lifecycle_state = lifecycle_state

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this AssetSummary.
        The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no
        predefined name, type, or namespace/scope. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The freeform_tags of this AssetSummary.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this AssetSummary.
        The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no
        predefined name, type, or namespace/scope. For more information, see `Resource Tags`__.
        Example: `{\"Department\": \"Finance\"}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param freeform_tags: The freeform_tags of this AssetSummary.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this AssetSummary.
        The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The defined_tags of this AssetSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this AssetSummary.
        The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces.
        For more information, see `Resource Tags`__.
        Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param defined_tags: The defined_tags of this AssetSummary.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    @property
    def system_tags(self):
        """
        Gets the system_tags of this AssetSummary.
        The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces.
        For more information, see `Resource Tags`__.
        Example: `{orcl-cloud: {free-tier-retain: true}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :return: The system_tags of this AssetSummary.
        :rtype: dict(str, dict(str, object))
        """
        return self._system_tags

    @system_tags.setter
    def system_tags(self, system_tags):
        """
        Sets the system_tags of this AssetSummary.
        The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces.
        For more information, see `Resource Tags`__.
        Example: `{orcl-cloud: {free-tier-retain: true}}`

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm


        :param system_tags: The system_tags of this AssetSummary.
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