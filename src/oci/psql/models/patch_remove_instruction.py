# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220915

from .patch_instruction import PatchInstruction
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class PatchRemoveInstruction(PatchInstruction):
    """
    An operation that deletes items, ignoring NOT_FOUND exceptions.
    To avoid referential errors if an item's descendant is also in the selection, items of the selection are processed in order of decreasing depth.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new PatchRemoveInstruction object with values from keyword arguments. The default value of the :py:attr:`~oci.psql.models.PatchRemoveInstruction.operation` attribute
        of this class is ``REMOVE`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param operation:
            The value to assign to the operation property of this PatchRemoveInstruction.
            Allowed values for this property are: "REQUIRE", "PROHIBIT", "REPLACE", "INSERT", "REMOVE", "MOVE", "MERGE"
        :type operation: str

        :param selection:
            The value to assign to the selection property of this PatchRemoveInstruction.
        :type selection: str

        """
        self.swagger_types = {
            'operation': 'str',
            'selection': 'str'
        }

        self.attribute_map = {
            'operation': 'operation',
            'selection': 'selection'
        }

        self._operation = None
        self._selection = None
        self._operation = 'REMOVE'

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
