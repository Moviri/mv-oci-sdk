# coding: utf-8
# Copyright (c) 2016, 2021, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

from .condition import Condition
from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CompositeCondition(Condition):
    """
    Composite Condition object with nested Condition
    """

    #: A constant which can be used with the composite_operator property of a CompositeCondition.
    #: This constant has a value of "AND"
    COMPOSITE_OPERATOR_AND = "AND"

    #: A constant which can be used with the composite_operator property of a CompositeCondition.
    #: This constant has a value of "OR"
    COMPOSITE_OPERATOR_OR = "OR"

    def __init__(self, **kwargs):
        """
        Initializes a new CompositeCondition object with values from keyword arguments. The default value of the :py:attr:`~oci.cloud_guard.models.CompositeCondition.kind` attribute
        of this class is ``COMPOSITE`` and it should not be changed.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param kind:
            The value to assign to the kind property of this CompositeCondition.
            Allowed values for this property are: "COMPOSITE", "SIMPLE", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type kind: str

        :param left_operand:
            The value to assign to the left_operand property of this CompositeCondition.
        :type left_operand: oci.cloud_guard.models.Condition

        :param composite_operator:
            The value to assign to the composite_operator property of this CompositeCondition.
            Allowed values for this property are: "AND", "OR", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type composite_operator: str

        :param right_operand:
            The value to assign to the right_operand property of this CompositeCondition.
        :type right_operand: oci.cloud_guard.models.Condition

        """
        self.swagger_types = {
            'kind': 'str',
            'left_operand': 'Condition',
            'composite_operator': 'str',
            'right_operand': 'Condition'
        }

        self.attribute_map = {
            'kind': 'kind',
            'left_operand': 'leftOperand',
            'composite_operator': 'compositeOperator',
            'right_operand': 'rightOperand'
        }

        self._kind = None
        self._left_operand = None
        self._composite_operator = None
        self._right_operand = None
        self._kind = 'COMPOSITE'

    @property
    def left_operand(self):
        """
        Gets the left_operand of this CompositeCondition.

        :return: The left_operand of this CompositeCondition.
        :rtype: oci.cloud_guard.models.Condition
        """
        return self._left_operand

    @left_operand.setter
    def left_operand(self, left_operand):
        """
        Sets the left_operand of this CompositeCondition.

        :param left_operand: The left_operand of this CompositeCondition.
        :type: oci.cloud_guard.models.Condition
        """
        self._left_operand = left_operand

    @property
    def composite_operator(self):
        """
        Gets the composite_operator of this CompositeCondition.
        Allowed values for this property are: "AND", "OR", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The composite_operator of this CompositeCondition.
        :rtype: str
        """
        return self._composite_operator

    @composite_operator.setter
    def composite_operator(self, composite_operator):
        """
        Sets the composite_operator of this CompositeCondition.

        :param composite_operator: The composite_operator of this CompositeCondition.
        :type: str
        """
        allowed_values = ["AND", "OR"]
        if not value_allowed_none_or_none_sentinel(composite_operator, allowed_values):
            composite_operator = 'UNKNOWN_ENUM_VALUE'
        self._composite_operator = composite_operator

    @property
    def right_operand(self):
        """
        Gets the right_operand of this CompositeCondition.

        :return: The right_operand of this CompositeCondition.
        :rtype: oci.cloud_guard.models.Condition
        """
        return self._right_operand

    @right_operand.setter
    def right_operand(self, right_operand):
        """
        Sets the right_operand of this CompositeCondition.

        :param right_operand: The right_operand of this CompositeCondition.
        :type: oci.cloud_guard.models.Condition
        """
        self._right_operand = right_operand

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other