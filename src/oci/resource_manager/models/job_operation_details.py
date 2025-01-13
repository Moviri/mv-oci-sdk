# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20180917


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class JobOperationDetails(object):
    """
    Job details that are specific to the operation type.
    """

    def __init__(self, **kwargs):
        """
        Initializes a new JobOperationDetails object with values from keyword arguments. This class has the following subclasses and if you are using this class as input
        to a service operations then you should favor using a subclass over the base class:

        * :class:`~oci.resource_manager.models.ImportTfStateJobOperationDetails`
        * :class:`~oci.resource_manager.models.PlanJobOperationDetails`
        * :class:`~oci.resource_manager.models.ApplyRollbackJobOperationDetails`
        * :class:`~oci.resource_manager.models.PlanRollbackJobOperationDetails`
        * :class:`~oci.resource_manager.models.ApplyJobOperationDetails`
        * :class:`~oci.resource_manager.models.DestroyJobOperationDetails`

        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param operation:
            The value to assign to the operation property of this JobOperationDetails.
        :type operation: str

        """
        self.swagger_types = {
            'operation': 'str'
        }

        self.attribute_map = {
            'operation': 'operation'
        }

        self._operation = None

    @staticmethod
    def get_subtype(object_dictionary):
        """
        Given the hash representation of a subtype of this class,
        use the info in the hash to return the class of the subtype.
        """
        type = object_dictionary['operation']

        if type == 'IMPORT_TF_STATE':
            return 'ImportTfStateJobOperationDetails'

        if type == 'PLAN':
            return 'PlanJobOperationDetails'

        if type == 'APPLY_ROLLBACK':
            return 'ApplyRollbackJobOperationDetails'

        if type == 'PLAN_ROLLBACK':
            return 'PlanRollbackJobOperationDetails'

        if type == 'APPLY':
            return 'ApplyJobOperationDetails'

        if type == 'DESTROY':
            return 'DestroyJobOperationDetails'
        else:
            return 'JobOperationDetails'

    @property
    def operation(self):
        """
        **[Required]** Gets the operation of this JobOperationDetails.
        Terraform-specific operation to execute.


        :return: The operation of this JobOperationDetails.
        :rtype: str
        """
        return self._operation

    @operation.setter
    def operation(self, operation):
        """
        Sets the operation of this JobOperationDetails.
        Terraform-specific operation to execute.


        :param operation: The operation of this JobOperationDetails.
        :type: str
        """
        self._operation = operation

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
