# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200430


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class RuntimeOperatorSummary(object):
    """
    The information about RuntimeOperator.
    """

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "NOT_STARTED"
    STATUS_NOT_STARTED = "NOT_STARTED"

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "QUEUED"
    STATUS_QUEUED = "QUEUED"

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "RUNNING"
    STATUS_RUNNING = "RUNNING"

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "TERMINATING"
    STATUS_TERMINATING = "TERMINATING"

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "TERMINATED"
    STATUS_TERMINATED = "TERMINATED"

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "SUCCESS"
    STATUS_SUCCESS = "SUCCESS"

    #: A constant which can be used with the status property of a RuntimeOperatorSummary.
    #: This constant has a value of "ERROR"
    STATUS_ERROR = "ERROR"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "NOT_STARTED"
    EXECUTION_STATE_NOT_STARTED = "NOT_STARTED"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "RUNNING"
    EXECUTION_STATE_RUNNING = "RUNNING"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "TERMINATED"
    EXECUTION_STATE_TERMINATED = "TERMINATED"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "SUCCESS"
    EXECUTION_STATE_SUCCESS = "SUCCESS"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "ERROR"
    EXECUTION_STATE_ERROR = "ERROR"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "SKIPPED"
    EXECUTION_STATE_SKIPPED = "SKIPPED"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "UNKNOWN"
    EXECUTION_STATE_UNKNOWN = "UNKNOWN"

    #: A constant which can be used with the execution_state property of a RuntimeOperatorSummary.
    #: This constant has a value of "IGNORED"
    EXECUTION_STATE_IGNORED = "IGNORED"

    #: A constant which can be used with the task_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "INTEGRATION_TASK"
    TASK_TYPE_INTEGRATION_TASK = "INTEGRATION_TASK"

    #: A constant which can be used with the task_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "DATA_LOADER_TASK"
    TASK_TYPE_DATA_LOADER_TASK = "DATA_LOADER_TASK"

    #: A constant which can be used with the task_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "PIPELINE_TASK"
    TASK_TYPE_PIPELINE_TASK = "PIPELINE_TASK"

    #: A constant which can be used with the task_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "SQL_TASK"
    TASK_TYPE_SQL_TASK = "SQL_TASK"

    #: A constant which can be used with the task_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "OCI_DATAFLOW_TASK"
    TASK_TYPE_OCI_DATAFLOW_TASK = "OCI_DATAFLOW_TASK"

    #: A constant which can be used with the task_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "REST_TASK"
    TASK_TYPE_REST_TASK = "REST_TASK"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "BASH_OPERATOR"
    OPERATOR_TYPE_BASH_OPERATOR = "BASH_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "TASK_OPERATOR"
    OPERATOR_TYPE_TASK_OPERATOR = "TASK_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "REST_OPERATOR"
    OPERATOR_TYPE_REST_OPERATOR = "REST_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "START_OPERATOR"
    OPERATOR_TYPE_START_OPERATOR = "START_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "END_OPERATOR"
    OPERATOR_TYPE_END_OPERATOR = "END_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "EXPRESSION_OPERATOR"
    OPERATOR_TYPE_EXPRESSION_OPERATOR = "EXPRESSION_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "MERGE_OPERATOR"
    OPERATOR_TYPE_MERGE_OPERATOR = "MERGE_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "DECISION_OPERATOR"
    OPERATOR_TYPE_DECISION_OPERATOR = "DECISION_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "LOOP_OPERATOR"
    OPERATOR_TYPE_LOOP_OPERATOR = "LOOP_OPERATOR"

    #: A constant which can be used with the operator_type property of a RuntimeOperatorSummary.
    #: This constant has a value of "ACTUAL_END_OPERATOR"
    OPERATOR_TYPE_ACTUAL_END_OPERATOR = "ACTUAL_END_OPERATOR"

    def __init__(self, **kwargs):
        """
        Initializes a new RuntimeOperatorSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param key:
            The value to assign to the key property of this RuntimeOperatorSummary.
        :type key: str

        :param task_run_key:
            The value to assign to the task_run_key property of this RuntimeOperatorSummary.
        :type task_run_key: str

        :param start_time_in_millis:
            The value to assign to the start_time_in_millis property of this RuntimeOperatorSummary.
        :type start_time_in_millis: int

        :param end_time_in_millis:
            The value to assign to the end_time_in_millis property of this RuntimeOperatorSummary.
        :type end_time_in_millis: int

        :param status:
            The value to assign to the status property of this RuntimeOperatorSummary.
            Allowed values for this property are: "NOT_STARTED", "QUEUED", "RUNNING", "TERMINATING", "TERMINATED", "SUCCESS", "ERROR", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type status: str

        :param model_type:
            The value to assign to the model_type property of this RuntimeOperatorSummary.
        :type model_type: str

        :param model_version:
            The value to assign to the model_version property of this RuntimeOperatorSummary.
        :type model_version: str

        :param parent_ref:
            The value to assign to the parent_ref property of this RuntimeOperatorSummary.
        :type parent_ref: oci.data_integration.models.ParentReference

        :param name:
            The value to assign to the name property of this RuntimeOperatorSummary.
        :type name: str

        :param object_version:
            The value to assign to the object_version property of this RuntimeOperatorSummary.
        :type object_version: int

        :param identifier:
            The value to assign to the identifier property of this RuntimeOperatorSummary.
        :type identifier: str

        :param execution_state:
            The value to assign to the execution_state property of this RuntimeOperatorSummary.
            Allowed values for this property are: "NOT_STARTED", "RUNNING", "TERMINATED", "SUCCESS", "ERROR", "SKIPPED", "UNKNOWN", "IGNORED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type execution_state: str

        :param parameters:
            The value to assign to the parameters property of this RuntimeOperatorSummary.
        :type parameters: list[oci.data_integration.models.Parameter]

        :param object_status:
            The value to assign to the object_status property of this RuntimeOperatorSummary.
        :type object_status: int

        :param metadata:
            The value to assign to the metadata property of this RuntimeOperatorSummary.
        :type metadata: oci.data_integration.models.ObjectMetadata

        :param operator:
            The value to assign to the operator property of this RuntimeOperatorSummary.
        :type operator: oci.data_integration.models.Operator

        :param inputs:
            The value to assign to the inputs property of this RuntimeOperatorSummary.
        :type inputs: dict(str, ParameterValue)

        :param outputs:
            The value to assign to the outputs property of this RuntimeOperatorSummary.
        :type outputs: dict(str, ParameterValue)

        :param task_type:
            The value to assign to the task_type property of this RuntimeOperatorSummary.
            Allowed values for this property are: "INTEGRATION_TASK", "DATA_LOADER_TASK", "PIPELINE_TASK", "SQL_TASK", "OCI_DATAFLOW_TASK", "REST_TASK", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type task_type: str

        :param config_provider:
            The value to assign to the config_provider property of this RuntimeOperatorSummary.
        :type config_provider: oci.data_integration.models.ConfigProvider

        :param operator_type:
            The value to assign to the operator_type property of this RuntimeOperatorSummary.
            Allowed values for this property are: "BASH_OPERATOR", "TASK_OPERATOR", "REST_OPERATOR", "START_OPERATOR", "END_OPERATOR", "EXPRESSION_OPERATOR", "MERGE_OPERATOR", "DECISION_OPERATOR", "LOOP_OPERATOR", "ACTUAL_END_OPERATOR", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type operator_type: str

        :param metrics:
            The value to assign to the metrics property of this RuntimeOperatorSummary.
        :type metrics: dict(str, float)

        """
        self.swagger_types = {
            'key': 'str',
            'task_run_key': 'str',
            'start_time_in_millis': 'int',
            'end_time_in_millis': 'int',
            'status': 'str',
            'model_type': 'str',
            'model_version': 'str',
            'parent_ref': 'ParentReference',
            'name': 'str',
            'object_version': 'int',
            'identifier': 'str',
            'execution_state': 'str',
            'parameters': 'list[Parameter]',
            'object_status': 'int',
            'metadata': 'ObjectMetadata',
            'operator': 'Operator',
            'inputs': 'dict(str, ParameterValue)',
            'outputs': 'dict(str, ParameterValue)',
            'task_type': 'str',
            'config_provider': 'ConfigProvider',
            'operator_type': 'str',
            'metrics': 'dict(str, float)'
        }

        self.attribute_map = {
            'key': 'key',
            'task_run_key': 'taskRunKey',
            'start_time_in_millis': 'startTimeInMillis',
            'end_time_in_millis': 'endTimeInMillis',
            'status': 'status',
            'model_type': 'modelType',
            'model_version': 'modelVersion',
            'parent_ref': 'parentRef',
            'name': 'name',
            'object_version': 'objectVersion',
            'identifier': 'identifier',
            'execution_state': 'executionState',
            'parameters': 'parameters',
            'object_status': 'objectStatus',
            'metadata': 'metadata',
            'operator': 'operator',
            'inputs': 'inputs',
            'outputs': 'outputs',
            'task_type': 'taskType',
            'config_provider': 'configProvider',
            'operator_type': 'operatorType',
            'metrics': 'metrics'
        }

        self._key = None
        self._task_run_key = None
        self._start_time_in_millis = None
        self._end_time_in_millis = None
        self._status = None
        self._model_type = None
        self._model_version = None
        self._parent_ref = None
        self._name = None
        self._object_version = None
        self._identifier = None
        self._execution_state = None
        self._parameters = None
        self._object_status = None
        self._metadata = None
        self._operator = None
        self._inputs = None
        self._outputs = None
        self._task_type = None
        self._config_provider = None
        self._operator_type = None
        self._metrics = None

    @property
    def key(self):
        """
        Gets the key of this RuntimeOperatorSummary.
        The RuntimeOperator key.


        :return: The key of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """
        Sets the key of this RuntimeOperatorSummary.
        The RuntimeOperator key.


        :param key: The key of this RuntimeOperatorSummary.
        :type: str
        """
        self._key = key

    @property
    def task_run_key(self):
        """
        Gets the task_run_key of this RuntimeOperatorSummary.
        The TaskRun key.


        :return: The task_run_key of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._task_run_key

    @task_run_key.setter
    def task_run_key(self, task_run_key):
        """
        Sets the task_run_key of this RuntimeOperatorSummary.
        The TaskRun key.


        :param task_run_key: The task_run_key of this RuntimeOperatorSummary.
        :type: str
        """
        self._task_run_key = task_run_key

    @property
    def start_time_in_millis(self):
        """
        Gets the start_time_in_millis of this RuntimeOperatorSummary.
        The runtime operator start time.


        :return: The start_time_in_millis of this RuntimeOperatorSummary.
        :rtype: int
        """
        return self._start_time_in_millis

    @start_time_in_millis.setter
    def start_time_in_millis(self, start_time_in_millis):
        """
        Sets the start_time_in_millis of this RuntimeOperatorSummary.
        The runtime operator start time.


        :param start_time_in_millis: The start_time_in_millis of this RuntimeOperatorSummary.
        :type: int
        """
        self._start_time_in_millis = start_time_in_millis

    @property
    def end_time_in_millis(self):
        """
        Gets the end_time_in_millis of this RuntimeOperatorSummary.
        The runtime operator end time.


        :return: The end_time_in_millis of this RuntimeOperatorSummary.
        :rtype: int
        """
        return self._end_time_in_millis

    @end_time_in_millis.setter
    def end_time_in_millis(self, end_time_in_millis):
        """
        Sets the end_time_in_millis of this RuntimeOperatorSummary.
        The runtime operator end time.


        :param end_time_in_millis: The end_time_in_millis of this RuntimeOperatorSummary.
        :type: int
        """
        self._end_time_in_millis = end_time_in_millis

    @property
    def status(self):
        """
        Gets the status of this RuntimeOperatorSummary.
        Status of RuntimeOperator. This field is deprecated, use RuntimeOperator's executionState field instead.

        Allowed values for this property are: "NOT_STARTED", "QUEUED", "RUNNING", "TERMINATING", "TERMINATED", "SUCCESS", "ERROR", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The status of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """
        Sets the status of this RuntimeOperatorSummary.
        Status of RuntimeOperator. This field is deprecated, use RuntimeOperator's executionState field instead.


        :param status: The status of this RuntimeOperatorSummary.
        :type: str
        """
        allowed_values = ["NOT_STARTED", "QUEUED", "RUNNING", "TERMINATING", "TERMINATED", "SUCCESS", "ERROR"]
        if not value_allowed_none_or_none_sentinel(status, allowed_values):
            status = 'UNKNOWN_ENUM_VALUE'
        self._status = status

    @property
    def model_type(self):
        """
        Gets the model_type of this RuntimeOperatorSummary.
        The type of the object.


        :return: The model_type of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._model_type

    @model_type.setter
    def model_type(self, model_type):
        """
        Sets the model_type of this RuntimeOperatorSummary.
        The type of the object.


        :param model_type: The model_type of this RuntimeOperatorSummary.
        :type: str
        """
        self._model_type = model_type

    @property
    def model_version(self):
        """
        Gets the model_version of this RuntimeOperatorSummary.
        The model version of an object.


        :return: The model_version of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._model_version

    @model_version.setter
    def model_version(self, model_version):
        """
        Sets the model_version of this RuntimeOperatorSummary.
        The model version of an object.


        :param model_version: The model_version of this RuntimeOperatorSummary.
        :type: str
        """
        self._model_version = model_version

    @property
    def parent_ref(self):
        """
        Gets the parent_ref of this RuntimeOperatorSummary.

        :return: The parent_ref of this RuntimeOperatorSummary.
        :rtype: oci.data_integration.models.ParentReference
        """
        return self._parent_ref

    @parent_ref.setter
    def parent_ref(self, parent_ref):
        """
        Sets the parent_ref of this RuntimeOperatorSummary.

        :param parent_ref: The parent_ref of this RuntimeOperatorSummary.
        :type: oci.data_integration.models.ParentReference
        """
        self._parent_ref = parent_ref

    @property
    def name(self):
        """
        Gets the name of this RuntimeOperatorSummary.
        Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.


        :return: The name of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """
        Sets the name of this RuntimeOperatorSummary.
        Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.


        :param name: The name of this RuntimeOperatorSummary.
        :type: str
        """
        self._name = name

    @property
    def object_version(self):
        """
        Gets the object_version of this RuntimeOperatorSummary.
        The version of the object that is used to track changes in the object instance.


        :return: The object_version of this RuntimeOperatorSummary.
        :rtype: int
        """
        return self._object_version

    @object_version.setter
    def object_version(self, object_version):
        """
        Sets the object_version of this RuntimeOperatorSummary.
        The version of the object that is used to track changes in the object instance.


        :param object_version: The object_version of this RuntimeOperatorSummary.
        :type: int
        """
        self._object_version = object_version

    @property
    def identifier(self):
        """
        Gets the identifier of this RuntimeOperatorSummary.
        Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.


        :return: The identifier of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._identifier

    @identifier.setter
    def identifier(self, identifier):
        """
        Sets the identifier of this RuntimeOperatorSummary.
        Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.


        :param identifier: The identifier of this RuntimeOperatorSummary.
        :type: str
        """
        self._identifier = identifier

    @property
    def execution_state(self):
        """
        Gets the execution_state of this RuntimeOperatorSummary.
        status

        Allowed values for this property are: "NOT_STARTED", "RUNNING", "TERMINATED", "SUCCESS", "ERROR", "SKIPPED", "UNKNOWN", "IGNORED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The execution_state of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._execution_state

    @execution_state.setter
    def execution_state(self, execution_state):
        """
        Sets the execution_state of this RuntimeOperatorSummary.
        status


        :param execution_state: The execution_state of this RuntimeOperatorSummary.
        :type: str
        """
        allowed_values = ["NOT_STARTED", "RUNNING", "TERMINATED", "SUCCESS", "ERROR", "SKIPPED", "UNKNOWN", "IGNORED"]
        if not value_allowed_none_or_none_sentinel(execution_state, allowed_values):
            execution_state = 'UNKNOWN_ENUM_VALUE'
        self._execution_state = execution_state

    @property
    def parameters(self):
        """
        Gets the parameters of this RuntimeOperatorSummary.
        A list of parameters for the pipeline, this allows certain aspects of the pipeline to be configured when the pipeline is executed.


        :return: The parameters of this RuntimeOperatorSummary.
        :rtype: list[oci.data_integration.models.Parameter]
        """
        return self._parameters

    @parameters.setter
    def parameters(self, parameters):
        """
        Sets the parameters of this RuntimeOperatorSummary.
        A list of parameters for the pipeline, this allows certain aspects of the pipeline to be configured when the pipeline is executed.


        :param parameters: The parameters of this RuntimeOperatorSummary.
        :type: list[oci.data_integration.models.Parameter]
        """
        self._parameters = parameters

    @property
    def object_status(self):
        """
        Gets the object_status of this RuntimeOperatorSummary.
        The status of an object that can be set to value 1 for shallow references across objects, other values reserved.


        :return: The object_status of this RuntimeOperatorSummary.
        :rtype: int
        """
        return self._object_status

    @object_status.setter
    def object_status(self, object_status):
        """
        Sets the object_status of this RuntimeOperatorSummary.
        The status of an object that can be set to value 1 for shallow references across objects, other values reserved.


        :param object_status: The object_status of this RuntimeOperatorSummary.
        :type: int
        """
        self._object_status = object_status

    @property
    def metadata(self):
        """
        Gets the metadata of this RuntimeOperatorSummary.

        :return: The metadata of this RuntimeOperatorSummary.
        :rtype: oci.data_integration.models.ObjectMetadata
        """
        return self._metadata

    @metadata.setter
    def metadata(self, metadata):
        """
        Sets the metadata of this RuntimeOperatorSummary.

        :param metadata: The metadata of this RuntimeOperatorSummary.
        :type: oci.data_integration.models.ObjectMetadata
        """
        self._metadata = metadata

    @property
    def operator(self):
        """
        Gets the operator of this RuntimeOperatorSummary.

        :return: The operator of this RuntimeOperatorSummary.
        :rtype: oci.data_integration.models.Operator
        """
        return self._operator

    @operator.setter
    def operator(self, operator):
        """
        Sets the operator of this RuntimeOperatorSummary.

        :param operator: The operator of this RuntimeOperatorSummary.
        :type: oci.data_integration.models.Operator
        """
        self._operator = operator

    @property
    def inputs(self):
        """
        Gets the inputs of this RuntimeOperatorSummary.
        The configuration provider bindings.


        :return: The inputs of this RuntimeOperatorSummary.
        :rtype: dict(str, ParameterValue)
        """
        return self._inputs

    @inputs.setter
    def inputs(self, inputs):
        """
        Sets the inputs of this RuntimeOperatorSummary.
        The configuration provider bindings.


        :param inputs: The inputs of this RuntimeOperatorSummary.
        :type: dict(str, ParameterValue)
        """
        self._inputs = inputs

    @property
    def outputs(self):
        """
        Gets the outputs of this RuntimeOperatorSummary.
        The configuration provider bindings.


        :return: The outputs of this RuntimeOperatorSummary.
        :rtype: dict(str, ParameterValue)
        """
        return self._outputs

    @outputs.setter
    def outputs(self, outputs):
        """
        Sets the outputs of this RuntimeOperatorSummary.
        The configuration provider bindings.


        :param outputs: The outputs of this RuntimeOperatorSummary.
        :type: dict(str, ParameterValue)
        """
        self._outputs = outputs

    @property
    def task_type(self):
        """
        Gets the task_type of this RuntimeOperatorSummary.
        The type of task run.

        Allowed values for this property are: "INTEGRATION_TASK", "DATA_LOADER_TASK", "PIPELINE_TASK", "SQL_TASK", "OCI_DATAFLOW_TASK", "REST_TASK", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The task_type of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._task_type

    @task_type.setter
    def task_type(self, task_type):
        """
        Sets the task_type of this RuntimeOperatorSummary.
        The type of task run.


        :param task_type: The task_type of this RuntimeOperatorSummary.
        :type: str
        """
        allowed_values = ["INTEGRATION_TASK", "DATA_LOADER_TASK", "PIPELINE_TASK", "SQL_TASK", "OCI_DATAFLOW_TASK", "REST_TASK"]
        if not value_allowed_none_or_none_sentinel(task_type, allowed_values):
            task_type = 'UNKNOWN_ENUM_VALUE'
        self._task_type = task_type

    @property
    def config_provider(self):
        """
        Gets the config_provider of this RuntimeOperatorSummary.

        :return: The config_provider of this RuntimeOperatorSummary.
        :rtype: oci.data_integration.models.ConfigProvider
        """
        return self._config_provider

    @config_provider.setter
    def config_provider(self, config_provider):
        """
        Sets the config_provider of this RuntimeOperatorSummary.

        :param config_provider: The config_provider of this RuntimeOperatorSummary.
        :type: oci.data_integration.models.ConfigProvider
        """
        self._config_provider = config_provider

    @property
    def operator_type(self):
        """
        Gets the operator_type of this RuntimeOperatorSummary.
        The type of Runtime Operator

        Allowed values for this property are: "BASH_OPERATOR", "TASK_OPERATOR", "REST_OPERATOR", "START_OPERATOR", "END_OPERATOR", "EXPRESSION_OPERATOR", "MERGE_OPERATOR", "DECISION_OPERATOR", "LOOP_OPERATOR", "ACTUAL_END_OPERATOR", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The operator_type of this RuntimeOperatorSummary.
        :rtype: str
        """
        return self._operator_type

    @operator_type.setter
    def operator_type(self, operator_type):
        """
        Sets the operator_type of this RuntimeOperatorSummary.
        The type of Runtime Operator


        :param operator_type: The operator_type of this RuntimeOperatorSummary.
        :type: str
        """
        allowed_values = ["BASH_OPERATOR", "TASK_OPERATOR", "REST_OPERATOR", "START_OPERATOR", "END_OPERATOR", "EXPRESSION_OPERATOR", "MERGE_OPERATOR", "DECISION_OPERATOR", "LOOP_OPERATOR", "ACTUAL_END_OPERATOR"]
        if not value_allowed_none_or_none_sentinel(operator_type, allowed_values):
            operator_type = 'UNKNOWN_ENUM_VALUE'
        self._operator_type = operator_type

    @property
    def metrics(self):
        """
        Gets the metrics of this RuntimeOperatorSummary.
        A map metrics for the task run.


        :return: The metrics of this RuntimeOperatorSummary.
        :rtype: dict(str, float)
        """
        return self._metrics

    @metrics.setter
    def metrics(self, metrics):
        """
        Sets the metrics of this RuntimeOperatorSummary.
        A map metrics for the task run.


        :param metrics: The metrics of this RuntimeOperatorSummary.
        :type: dict(str, float)
        """
        self._metrics = metrics

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
