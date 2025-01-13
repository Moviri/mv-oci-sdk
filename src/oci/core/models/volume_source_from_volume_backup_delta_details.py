# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918

from .volume_source_details import VolumeSourceDetails
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class VolumeSourceFromVolumeBackupDeltaDetails(VolumeSourceDetails):
    """
    Specifies the volume backups (first & second) and block size in bytes.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new VolumeSourceFromVolumeBackupDeltaDetails object with values from keyword arguments. The default value of the :py:attr:`~oci.core.models.VolumeSourceFromVolumeBackupDeltaDetails.type` attribute
        of this class is ``volumeBackupDelta`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param type:
            The value to assign to the type property of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type type: str

        :param first_backup_id:
            The value to assign to the first_backup_id property of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type first_backup_id: str

        :param second_backup_id:
            The value to assign to the second_backup_id property of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type second_backup_id: str

        :param change_block_size_in_bytes:
            The value to assign to the change_block_size_in_bytes property of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type change_block_size_in_bytes: int

        """
        self.swagger_types = {
            'type': 'str',
            'first_backup_id': 'str',
            'second_backup_id': 'str',
            'change_block_size_in_bytes': 'int'
        }

        self.attribute_map = {
            'type': 'type',
            'first_backup_id': 'firstBackupId',
            'second_backup_id': 'secondBackupId',
            'change_block_size_in_bytes': 'changeBlockSizeInBytes'
        }

        self._type = None
        self._first_backup_id = None
        self._second_backup_id = None
        self._change_block_size_in_bytes = None
        self._type = 'volumeBackupDelta'

    @property
    def first_backup_id(self):
        """
        **[Required]** Gets the first_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        The OCID of the first volume backup.


        :return: The first_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        :rtype: str
        """
        return self._first_backup_id

    @first_backup_id.setter
    def first_backup_id(self, first_backup_id):
        """
        Sets the first_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        The OCID of the first volume backup.


        :param first_backup_id: The first_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type: str
        """
        self._first_backup_id = first_backup_id

    @property
    def second_backup_id(self):
        """
        **[Required]** Gets the second_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        The OCID of the second volume backup.


        :return: The second_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        :rtype: str
        """
        return self._second_backup_id

    @second_backup_id.setter
    def second_backup_id(self, second_backup_id):
        """
        Sets the second_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        The OCID of the second volume backup.


        :param second_backup_id: The second_backup_id of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type: str
        """
        self._second_backup_id = second_backup_id

    @property
    def change_block_size_in_bytes(self):
        """
        Gets the change_block_size_in_bytes of this VolumeSourceFromVolumeBackupDeltaDetails.
        Block size in bytes to be considered while performing volume restore. The value must be a power of 2; ranging from 4KB (4096 bytes) to 1MB (1048576 bytes). If omitted, defaults to 4,096 bytes (4 KiB).


        :return: The change_block_size_in_bytes of this VolumeSourceFromVolumeBackupDeltaDetails.
        :rtype: int
        """
        return self._change_block_size_in_bytes

    @change_block_size_in_bytes.setter
    def change_block_size_in_bytes(self, change_block_size_in_bytes):
        """
        Sets the change_block_size_in_bytes of this VolumeSourceFromVolumeBackupDeltaDetails.
        Block size in bytes to be considered while performing volume restore. The value must be a power of 2; ranging from 4KB (4096 bytes) to 1MB (1048576 bytes). If omitted, defaults to 4,096 bytes (4 KiB).


        :param change_block_size_in_bytes: The change_block_size_in_bytes of this VolumeSourceFromVolumeBackupDeltaDetails.
        :type: int
        """
        self._change_block_size_in_bytes = change_block_size_in_bytes

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
