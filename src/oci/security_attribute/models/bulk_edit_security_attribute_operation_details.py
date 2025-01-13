# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20240815


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class BulkEditSecurityAttributeOperationDetails(object):
    """
    BulkEditSecurityAttributeOperationDetails model.
    """

    #: A constant which can be used with the operation_type property of a BulkEditSecurityAttributeOperationDetails.
    #: This constant has a value of "ADD_WHERE_ABSENT"
    OPERATION_TYPE_ADD_WHERE_ABSENT = "ADD_WHERE_ABSENT"

    #: A constant which can be used with the operation_type property of a BulkEditSecurityAttributeOperationDetails.
    #: This constant has a value of "SET_WHERE_PRESENT"
    OPERATION_TYPE_SET_WHERE_PRESENT = "SET_WHERE_PRESENT"

    #: A constant which can be used with the operation_type property of a BulkEditSecurityAttributeOperationDetails.
    #: This constant has a value of "ADD_OR_SET"
    OPERATION_TYPE_ADD_OR_SET = "ADD_OR_SET"

    #: A constant which can be used with the operation_type property of a BulkEditSecurityAttributeOperationDetails.
    #: This constant has a value of "REMOVE"
    OPERATION_TYPE_REMOVE = "REMOVE"

    def __init__(self, **kwargs):
        """
        Initializes a new BulkEditSecurityAttributeOperationDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param operation_type:
            The value to assign to the operation_type property of this BulkEditSecurityAttributeOperationDetails.
            Allowed values for this property are: "ADD_WHERE_ABSENT", "SET_WHERE_PRESENT", "ADD_OR_SET", "REMOVE"
        :type operation_type: str

        :param security_attributes:
            The value to assign to the security_attributes property of this BulkEditSecurityAttributeOperationDetails.
        :type security_attributes: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'operation_type': 'str',
            'security_attributes': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'operation_type': 'operationType',
            'security_attributes': 'securityAttributes'
        }

        self._operation_type = None
        self._security_attributes = None

    @property
    def operation_type(self):
        """
        **[Required]** Gets the operation_type of this BulkEditSecurityAttributeOperationDetails.
        An enum-like description of the type of operation.

        * `ADD_WHERE_ABSENT` adds a security attribute only if it does not already exist on the resource.
        * `SET_WHERE_PRESENT` updates the value for a security attribute only if it is present on the resource.
        * `ADD_OR_SET` combines the first two operations to add a security attribute if it does not already exist on the resource
        or update the value if it is present on the resource.
        * `REMOVE` removes the security attribute from the resource. It's removed from the resource regardless of the value.

        Allowed values for this property are: "ADD_WHERE_ABSENT", "SET_WHERE_PRESENT", "ADD_OR_SET", "REMOVE"


        :return: The operation_type of this BulkEditSecurityAttributeOperationDetails.
        :rtype: str
        """
        return self._operation_type

    @operation_type.setter
    def operation_type(self, operation_type):
        """
        Sets the operation_type of this BulkEditSecurityAttributeOperationDetails.
        An enum-like description of the type of operation.

        * `ADD_WHERE_ABSENT` adds a security attribute only if it does not already exist on the resource.
        * `SET_WHERE_PRESENT` updates the value for a security attribute only if it is present on the resource.
        * `ADD_OR_SET` combines the first two operations to add a security attribute if it does not already exist on the resource
        or update the value if it is present on the resource.
        * `REMOVE` removes the security attribute from the resource. It's removed from the resource regardless of the value.


        :param operation_type: The operation_type of this BulkEditSecurityAttributeOperationDetails.
        :type: str
        """
        allowed_values = ["ADD_WHERE_ABSENT", "SET_WHERE_PRESENT", "ADD_OR_SET", "REMOVE"]
        if not value_allowed_none_or_none_sentinel(operation_type, allowed_values):
            raise ValueError(
                f"Invalid value for `operation_type`, must be None or one of {allowed_values}"
            )
        self._operation_type = operation_type

    @property
    def security_attributes(self):
        """
        **[Required]** Gets the security_attributes of this BulkEditSecurityAttributeOperationDetails.
        Security attributes for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: ``{\"oracle-zpr\": {\"td\": {\"value\": \"42\", \"mode\": \"audit\"}}}``

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :return: The security_attributes of this BulkEditSecurityAttributeOperationDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._security_attributes

    @security_attributes.setter
    def security_attributes(self, security_attributes):
        """
        Sets the security_attributes of this BulkEditSecurityAttributeOperationDetails.
        Security attributes for this resource. Each key is predefined and scoped to a namespace.
        For more information, see `Resource Tags`__.
        Example: ``{\"oracle-zpr\": {\"td\": {\"value\": \"42\", \"mode\": \"audit\"}}}``

        __ https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm


        :param security_attributes: The security_attributes of this BulkEditSecurityAttributeOperationDetails.
        :type: dict(str, dict(str, object))
        """
        self._security_attributes = security_attributes

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
