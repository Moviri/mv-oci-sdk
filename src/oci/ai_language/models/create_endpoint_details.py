# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20221001


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CreateEndpointDetails(object):
    """
    The information needed to create a new endpoint and expose to end users.
    """

    #: A constant which can be used with the compute_type property of a CreateEndpointDetails.
    #: This constant has a value of "CPU"
    COMPUTE_TYPE_CPU = "CPU"

    #: A constant which can be used with the compute_type property of a CreateEndpointDetails.
    #: This constant has a value of "GPU"
    COMPUTE_TYPE_GPU = "GPU"

    def __init__(self, **kwargs):
        """
        Initializes a new CreateEndpointDetails object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param display_name:
            The value to assign to the display_name property of this CreateEndpointDetails.
        :type display_name: str

        :param compute_type:
            The value to assign to the compute_type property of this CreateEndpointDetails.
            Allowed values for this property are: "CPU", "GPU"
        :type compute_type: str

        :param alias:
            The value to assign to the alias property of this CreateEndpointDetails.
        :type alias: str

        :param description:
            The value to assign to the description property of this CreateEndpointDetails.
        :type description: str

        :param compartment_id:
            The value to assign to the compartment_id property of this CreateEndpointDetails.
        :type compartment_id: str

        :param model_id:
            The value to assign to the model_id property of this CreateEndpointDetails.
        :type model_id: str

        :param inference_units:
            The value to assign to the inference_units property of this CreateEndpointDetails.
        :type inference_units: int

        :param freeform_tags:
            The value to assign to the freeform_tags property of this CreateEndpointDetails.
        :type freeform_tags: dict(str, str)

        :param defined_tags:
            The value to assign to the defined_tags property of this CreateEndpointDetails.
        :type defined_tags: dict(str, dict(str, object))

        """
        self.swagger_types = {
            'display_name': 'str',
            'compute_type': 'str',
            'alias': 'str',
            'description': 'str',
            'compartment_id': 'str',
            'model_id': 'str',
            'inference_units': 'int',
            'freeform_tags': 'dict(str, str)',
            'defined_tags': 'dict(str, dict(str, object))'
        }

        self.attribute_map = {
            'display_name': 'displayName',
            'compute_type': 'computeType',
            'alias': 'alias',
            'description': 'description',
            'compartment_id': 'compartmentId',
            'model_id': 'modelId',
            'inference_units': 'inferenceUnits',
            'freeform_tags': 'freeformTags',
            'defined_tags': 'definedTags'
        }

        self._display_name = None
        self._compute_type = None
        self._alias = None
        self._description = None
        self._compartment_id = None
        self._model_id = None
        self._inference_units = None
        self._freeform_tags = None
        self._defined_tags = None

    @property
    def display_name(self):
        """
        Gets the display_name of this CreateEndpointDetails.
        A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.


        :return: The display_name of this CreateEndpointDetails.
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """
        Sets the display_name of this CreateEndpointDetails.
        A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.


        :param display_name: The display_name of this CreateEndpointDetails.
        :type: str
        """
        self._display_name = display_name

    @property
    def compute_type(self):
        """
        Gets the compute_type of this CreateEndpointDetails.
        Compute infra type for endpoint.

        Allowed values for this property are: "CPU", "GPU"


        :return: The compute_type of this CreateEndpointDetails.
        :rtype: str
        """
        return self._compute_type

    @compute_type.setter
    def compute_type(self, compute_type):
        """
        Sets the compute_type of this CreateEndpointDetails.
        Compute infra type for endpoint.


        :param compute_type: The compute_type of this CreateEndpointDetails.
        :type: str
        """
        allowed_values = ["CPU", "GPU"]
        if not value_allowed_none_or_none_sentinel(compute_type, allowed_values):
            raise ValueError(
                f"Invalid value for `compute_type`, must be None or one of {allowed_values}"
            )
        self._compute_type = compute_type

    @property
    def alias(self):
        """
        Gets the alias of this CreateEndpointDetails.
        Unique name across user tenancy in a region to identify an endpoint to be used for inferencing.


        :return: The alias of this CreateEndpointDetails.
        :rtype: str
        """
        return self._alias

    @alias.setter
    def alias(self, alias):
        """
        Sets the alias of this CreateEndpointDetails.
        Unique name across user tenancy in a region to identify an endpoint to be used for inferencing.


        :param alias: The alias of this CreateEndpointDetails.
        :type: str
        """
        self._alias = alias

    @property
    def description(self):
        """
        Gets the description of this CreateEndpointDetails.
        A short description of the an endpoint.


        :return: The description of this CreateEndpointDetails.
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """
        Sets the description of this CreateEndpointDetails.
        A short description of the an endpoint.


        :param description: The description of this CreateEndpointDetails.
        :type: str
        """
        self._description = description

    @property
    def compartment_id(self):
        """
        **[Required]** Gets the compartment_id of this CreateEndpointDetails.
        The `OCID`__ compartment identifier for the endpoint

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :return: The compartment_id of this CreateEndpointDetails.
        :rtype: str
        """
        return self._compartment_id

    @compartment_id.setter
    def compartment_id(self, compartment_id):
        """
        Sets the compartment_id of this CreateEndpointDetails.
        The `OCID`__ compartment identifier for the endpoint

        __ https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm


        :param compartment_id: The compartment_id of this CreateEndpointDetails.
        :type: str
        """
        self._compartment_id = compartment_id

    @property
    def model_id(self):
        """
        **[Required]** Gets the model_id of this CreateEndpointDetails.
        The `OCID`__ of the model to associate with the endpoint.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :return: The model_id of this CreateEndpointDetails.
        :rtype: str
        """
        return self._model_id

    @model_id.setter
    def model_id(self, model_id):
        """
        Sets the model_id of this CreateEndpointDetails.
        The `OCID`__ of the model to associate with the endpoint.

        __ https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm


        :param model_id: The model_id of this CreateEndpointDetails.
        :type: str
        """
        self._model_id = model_id

    @property
    def inference_units(self):
        """
        Gets the inference_units of this CreateEndpointDetails.
        Number of replicas required for this endpoint. This will be optional parameter. Default will be 1.


        :return: The inference_units of this CreateEndpointDetails.
        :rtype: int
        """
        return self._inference_units

    @inference_units.setter
    def inference_units(self, inference_units):
        """
        Sets the inference_units of this CreateEndpointDetails.
        Number of replicas required for this endpoint. This will be optional parameter. Default will be 1.


        :param inference_units: The inference_units of this CreateEndpointDetails.
        :type: int
        """
        self._inference_units = inference_units

    @property
    def freeform_tags(self):
        """
        Gets the freeform_tags of this CreateEndpointDetails.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :return: The freeform_tags of this CreateEndpointDetails.
        :rtype: dict(str, str)
        """
        return self._freeform_tags

    @freeform_tags.setter
    def freeform_tags(self, freeform_tags):
        """
        Sets the freeform_tags of this CreateEndpointDetails.
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
        Example: `{\"bar-key\": \"value\"}`


        :param freeform_tags: The freeform_tags of this CreateEndpointDetails.
        :type: dict(str, str)
        """
        self._freeform_tags = freeform_tags

    @property
    def defined_tags(self):
        """
        Gets the defined_tags of this CreateEndpointDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :return: The defined_tags of this CreateEndpointDetails.
        :rtype: dict(str, dict(str, object))
        """
        return self._defined_tags

    @defined_tags.setter
    def defined_tags(self, defined_tags):
        """
        Sets the defined_tags of this CreateEndpointDetails.
        Defined tags for this resource. Each key is predefined and scoped to a namespace.
        Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`


        :param defined_tags: The defined_tags of this CreateEndpointDetails.
        :type: dict(str, dict(str, object))
        """
        self._defined_tags = defined_tags

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
