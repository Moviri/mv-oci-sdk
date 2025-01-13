# coding: utf-8
# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20190101

from __future__ import absolute_import

from .artifact_export_details import ArtifactExportDetails
from .artifact_export_details_object_storage import ArtifactExportDetailsObjectStorage
from .artifact_import_details import ArtifactImportDetails
from .artifact_import_details_object_storage import ArtifactImportDetailsObjectStorage
from .auto_scaling_policy import AutoScalingPolicy
from .auto_scaling_policy_details import AutoScalingPolicyDetails
from .backup_operation_details import BackupOperationDetails
from .backup_setting import BackupSetting
from .category_log_details import CategoryLogDetails
from .change_data_science_private_endpoint_compartment_details import ChangeDataSciencePrivateEndpointCompartmentDetails
from .change_job_compartment_details import ChangeJobCompartmentDetails
from .change_job_run_compartment_details import ChangeJobRunCompartmentDetails
from .change_model_compartment_details import ChangeModelCompartmentDetails
from .change_model_deployment_compartment_details import ChangeModelDeploymentCompartmentDetails
from .change_model_version_set_compartment_details import ChangeModelVersionSetCompartmentDetails
from .change_notebook_session_compartment_details import ChangeNotebookSessionCompartmentDetails
from .change_pipeline_compartment_details import ChangePipelineCompartmentDetails
from .change_pipeline_run_compartment_details import ChangePipelineRunCompartmentDetails
from .change_project_compartment_details import ChangeProjectCompartmentDetails
from .create_data_science_private_endpoint_details import CreateDataSciencePrivateEndpointDetails
from .create_job_details import CreateJobDetails
from .create_job_run_details import CreateJobRunDetails
from .create_model_deployment_details import CreateModelDeploymentDetails
from .create_model_details import CreateModelDetails
from .create_model_provenance_details import CreateModelProvenanceDetails
from .create_model_version_set_details import CreateModelVersionSetDetails
from .create_notebook_session_details import CreateNotebookSessionDetails
from .create_pipeline_details import CreatePipelineDetails
from .create_pipeline_run_details import CreatePipelineRunDetails
from .create_project_details import CreateProjectDetails
from .custom_expression_query_scaling_configuration import CustomExpressionQueryScalingConfiguration
from .custom_metric_expression_rule import CustomMetricExpressionRule
from .data_science_private_endpoint import DataSciencePrivateEndpoint
from .data_science_private_endpoint_summary import DataSciencePrivateEndpointSummary
from .default_job_configuration_details import DefaultJobConfigurationDetails
from .default_model_deployment_environment_configuration_details import DefaultModelDeploymentEnvironmentConfigurationDetails
from .export_model_artifact_details import ExportModelArtifactDetails
from .fast_launch_job_config_summary import FastLaunchJobConfigSummary
from .file_storage_mount_configuration_details import FileStorageMountConfigurationDetails
from .fixed_size_scaling_policy import FixedSizeScalingPolicy
from .import_model_artifact_details import ImportModelArtifactDetails
from .instance_configuration import InstanceConfiguration
from .instance_pool_model_deployment_system_data import InstancePoolModelDeploymentSystemData
from .job import Job
from .job_configuration_details import JobConfigurationDetails
from .job_environment_configuration_details import JobEnvironmentConfigurationDetails
from .job_infrastructure_configuration_details import JobInfrastructureConfigurationDetails
from .job_log_configuration_details import JobLogConfigurationDetails
from .job_run import JobRun
from .job_run_log_details import JobRunLogDetails
from .job_run_summary import JobRunSummary
from .job_shape_config_details import JobShapeConfigDetails
from .job_shape_summary import JobShapeSummary
from .job_summary import JobSummary
from .log_details import LogDetails
from .managed_egress_standalone_job_infrastructure_configuration_details import ManagedEgressStandaloneJobInfrastructureConfigurationDetails
from .metadata import Metadata
from .metric_expression_rule import MetricExpressionRule
from .model import Model
from .model_configuration_details import ModelConfigurationDetails
from .model_deployment import ModelDeployment
from .model_deployment_configuration_details import ModelDeploymentConfigurationDetails
from .model_deployment_environment_configuration_details import ModelDeploymentEnvironmentConfigurationDetails
from .model_deployment_instance_shape_config_details import ModelDeploymentInstanceShapeConfigDetails
from .model_deployment_shape_summary import ModelDeploymentShapeSummary
from .model_deployment_summary import ModelDeploymentSummary
from .model_deployment_system_data import ModelDeploymentSystemData
from .model_provenance import ModelProvenance
from .model_summary import ModelSummary
from .model_version_set import ModelVersionSet
from .model_version_set_summary import ModelVersionSetSummary
from .notebook_session import NotebookSession
from .notebook_session_config_details import NotebookSessionConfigDetails
from .notebook_session_configuration_details import NotebookSessionConfigurationDetails
from .notebook_session_git_config_details import NotebookSessionGitConfigDetails
from .notebook_session_git_repo_config_details import NotebookSessionGitRepoConfigDetails
from .notebook_session_runtime_config_details import NotebookSessionRuntimeConfigDetails
from .notebook_session_shape_config_details import NotebookSessionShapeConfigDetails
from .notebook_session_shape_summary import NotebookSessionShapeSummary
from .notebook_session_summary import NotebookSessionSummary
from .object_storage_mount_configuration_details import ObjectStorageMountConfigurationDetails
from .ocir_container_job_environment_configuration_details import OcirContainerJobEnvironmentConfigurationDetails
from .ocir_model_deployment_environment_configuration_details import OcirModelDeploymentEnvironmentConfigurationDetails
from .pipeline import Pipeline
from .pipeline_configuration_details import PipelineConfigurationDetails
from .pipeline_container_configuration_details import PipelineContainerConfigurationDetails
from .pipeline_container_step_details import PipelineContainerStepDetails
from .pipeline_container_step_run import PipelineContainerStepRun
from .pipeline_container_step_update_details import PipelineContainerStepUpdateDetails
from .pipeline_custom_script_step_details import PipelineCustomScriptStepDetails
from .pipeline_custom_script_step_run import PipelineCustomScriptStepRun
from .pipeline_custom_script_step_update_details import PipelineCustomScriptStepUpdateDetails
from .pipeline_default_configuration_details import PipelineDefaultConfigurationDetails
from .pipeline_infrastructure_configuration_details import PipelineInfrastructureConfigurationDetails
from .pipeline_log_configuration_details import PipelineLogConfigurationDetails
from .pipeline_ml_job_step_details import PipelineMLJobStepDetails
from .pipeline_ml_job_step_run import PipelineMLJobStepRun
from .pipeline_ml_job_step_update_details import PipelineMLJobStepUpdateDetails
from .pipeline_ocir_container_configuration_details import PipelineOcirContainerConfigurationDetails
from .pipeline_run import PipelineRun
from .pipeline_run_log_details import PipelineRunLogDetails
from .pipeline_run_summary import PipelineRunSummary
from .pipeline_shape_config_details import PipelineShapeConfigDetails
from .pipeline_step_configuration_details import PipelineStepConfigurationDetails
from .pipeline_step_details import PipelineStepDetails
from .pipeline_step_override_details import PipelineStepOverrideDetails
from .pipeline_step_run import PipelineStepRun
from .pipeline_step_update_details import PipelineStepUpdateDetails
from .pipeline_summary import PipelineSummary
from .predefined_expression_threshold_scaling_configuration import PredefinedExpressionThresholdScalingConfiguration
from .predefined_metric_expression_rule import PredefinedMetricExpressionRule
from .project import Project
from .project_summary import ProjectSummary
from .retention_operation_details import RetentionOperationDetails
from .retention_setting import RetentionSetting
from .scaling_configuration import ScalingConfiguration
from .scaling_policy import ScalingPolicy
from .single_model_deployment_configuration_details import SingleModelDeploymentConfigurationDetails
from .standalone_job_infrastructure_configuration_details import StandaloneJobInfrastructureConfigurationDetails
from .storage_mount_configuration_details import StorageMountConfigurationDetails
from .threshold_based_auto_scaling_policy_details import ThresholdBasedAutoScalingPolicyDetails
from .update_category_log_details import UpdateCategoryLogDetails
from .update_data_science_private_endpoint_details import UpdateDataSciencePrivateEndpointDetails
from .update_default_model_deployment_environment_configuration_details import UpdateDefaultModelDeploymentEnvironmentConfigurationDetails
from .update_job_details import UpdateJobDetails
from .update_job_run_details import UpdateJobRunDetails
from .update_model_configuration_details import UpdateModelConfigurationDetails
from .update_model_deployment_configuration_details import UpdateModelDeploymentConfigurationDetails
from .update_model_deployment_details import UpdateModelDeploymentDetails
from .update_model_deployment_environment_configuration_details import UpdateModelDeploymentEnvironmentConfigurationDetails
from .update_model_details import UpdateModelDetails
from .update_model_provenance_details import UpdateModelProvenanceDetails
from .update_model_version_set_details import UpdateModelVersionSetDetails
from .update_notebook_session_details import UpdateNotebookSessionDetails
from .update_ocir_model_deployment_environment_configuration_details import UpdateOcirModelDeploymentEnvironmentConfigurationDetails
from .update_pipeline_details import UpdatePipelineDetails
from .update_pipeline_run_details import UpdatePipelineRunDetails
from .update_project_details import UpdateProjectDetails
from .update_single_model_deployment_configuration_details import UpdateSingleModelDeploymentConfigurationDetails
from .work_request import WorkRequest
from .work_request_error import WorkRequestError
from .work_request_log_entry import WorkRequestLogEntry
from .work_request_resource import WorkRequestResource
from .work_request_summary import WorkRequestSummary

# Maps type names to classes for data_science services.
data_science_type_mapping = {
    "ArtifactExportDetails": ArtifactExportDetails,
    "ArtifactExportDetailsObjectStorage": ArtifactExportDetailsObjectStorage,
    "ArtifactImportDetails": ArtifactImportDetails,
    "ArtifactImportDetailsObjectStorage": ArtifactImportDetailsObjectStorage,
    "AutoScalingPolicy": AutoScalingPolicy,
    "AutoScalingPolicyDetails": AutoScalingPolicyDetails,
    "BackupOperationDetails": BackupOperationDetails,
    "BackupSetting": BackupSetting,
    "CategoryLogDetails": CategoryLogDetails,
    "ChangeDataSciencePrivateEndpointCompartmentDetails": ChangeDataSciencePrivateEndpointCompartmentDetails,
    "ChangeJobCompartmentDetails": ChangeJobCompartmentDetails,
    "ChangeJobRunCompartmentDetails": ChangeJobRunCompartmentDetails,
    "ChangeModelCompartmentDetails": ChangeModelCompartmentDetails,
    "ChangeModelDeploymentCompartmentDetails": ChangeModelDeploymentCompartmentDetails,
    "ChangeModelVersionSetCompartmentDetails": ChangeModelVersionSetCompartmentDetails,
    "ChangeNotebookSessionCompartmentDetails": ChangeNotebookSessionCompartmentDetails,
    "ChangePipelineCompartmentDetails": ChangePipelineCompartmentDetails,
    "ChangePipelineRunCompartmentDetails": ChangePipelineRunCompartmentDetails,
    "ChangeProjectCompartmentDetails": ChangeProjectCompartmentDetails,
    "CreateDataSciencePrivateEndpointDetails": CreateDataSciencePrivateEndpointDetails,
    "CreateJobDetails": CreateJobDetails,
    "CreateJobRunDetails": CreateJobRunDetails,
    "CreateModelDeploymentDetails": CreateModelDeploymentDetails,
    "CreateModelDetails": CreateModelDetails,
    "CreateModelProvenanceDetails": CreateModelProvenanceDetails,
    "CreateModelVersionSetDetails": CreateModelVersionSetDetails,
    "CreateNotebookSessionDetails": CreateNotebookSessionDetails,
    "CreatePipelineDetails": CreatePipelineDetails,
    "CreatePipelineRunDetails": CreatePipelineRunDetails,
    "CreateProjectDetails": CreateProjectDetails,
    "CustomExpressionQueryScalingConfiguration": CustomExpressionQueryScalingConfiguration,
    "CustomMetricExpressionRule": CustomMetricExpressionRule,
    "DataSciencePrivateEndpoint": DataSciencePrivateEndpoint,
    "DataSciencePrivateEndpointSummary": DataSciencePrivateEndpointSummary,
    "DefaultJobConfigurationDetails": DefaultJobConfigurationDetails,
    "DefaultModelDeploymentEnvironmentConfigurationDetails": DefaultModelDeploymentEnvironmentConfigurationDetails,
    "ExportModelArtifactDetails": ExportModelArtifactDetails,
    "FastLaunchJobConfigSummary": FastLaunchJobConfigSummary,
    "FileStorageMountConfigurationDetails": FileStorageMountConfigurationDetails,
    "FixedSizeScalingPolicy": FixedSizeScalingPolicy,
    "ImportModelArtifactDetails": ImportModelArtifactDetails,
    "InstanceConfiguration": InstanceConfiguration,
    "InstancePoolModelDeploymentSystemData": InstancePoolModelDeploymentSystemData,
    "Job": Job,
    "JobConfigurationDetails": JobConfigurationDetails,
    "JobEnvironmentConfigurationDetails": JobEnvironmentConfigurationDetails,
    "JobInfrastructureConfigurationDetails": JobInfrastructureConfigurationDetails,
    "JobLogConfigurationDetails": JobLogConfigurationDetails,
    "JobRun": JobRun,
    "JobRunLogDetails": JobRunLogDetails,
    "JobRunSummary": JobRunSummary,
    "JobShapeConfigDetails": JobShapeConfigDetails,
    "JobShapeSummary": JobShapeSummary,
    "JobSummary": JobSummary,
    "LogDetails": LogDetails,
    "ManagedEgressStandaloneJobInfrastructureConfigurationDetails": ManagedEgressStandaloneJobInfrastructureConfigurationDetails,
    "Metadata": Metadata,
    "MetricExpressionRule": MetricExpressionRule,
    "Model": Model,
    "ModelConfigurationDetails": ModelConfigurationDetails,
    "ModelDeployment": ModelDeployment,
    "ModelDeploymentConfigurationDetails": ModelDeploymentConfigurationDetails,
    "ModelDeploymentEnvironmentConfigurationDetails": ModelDeploymentEnvironmentConfigurationDetails,
    "ModelDeploymentInstanceShapeConfigDetails": ModelDeploymentInstanceShapeConfigDetails,
    "ModelDeploymentShapeSummary": ModelDeploymentShapeSummary,
    "ModelDeploymentSummary": ModelDeploymentSummary,
    "ModelDeploymentSystemData": ModelDeploymentSystemData,
    "ModelProvenance": ModelProvenance,
    "ModelSummary": ModelSummary,
    "ModelVersionSet": ModelVersionSet,
    "ModelVersionSetSummary": ModelVersionSetSummary,
    "NotebookSession": NotebookSession,
    "NotebookSessionConfigDetails": NotebookSessionConfigDetails,
    "NotebookSessionConfigurationDetails": NotebookSessionConfigurationDetails,
    "NotebookSessionGitConfigDetails": NotebookSessionGitConfigDetails,
    "NotebookSessionGitRepoConfigDetails": NotebookSessionGitRepoConfigDetails,
    "NotebookSessionRuntimeConfigDetails": NotebookSessionRuntimeConfigDetails,
    "NotebookSessionShapeConfigDetails": NotebookSessionShapeConfigDetails,
    "NotebookSessionShapeSummary": NotebookSessionShapeSummary,
    "NotebookSessionSummary": NotebookSessionSummary,
    "ObjectStorageMountConfigurationDetails": ObjectStorageMountConfigurationDetails,
    "OcirContainerJobEnvironmentConfigurationDetails": OcirContainerJobEnvironmentConfigurationDetails,
    "OcirModelDeploymentEnvironmentConfigurationDetails": OcirModelDeploymentEnvironmentConfigurationDetails,
    "Pipeline": Pipeline,
    "PipelineConfigurationDetails": PipelineConfigurationDetails,
    "PipelineContainerConfigurationDetails": PipelineContainerConfigurationDetails,
    "PipelineContainerStepDetails": PipelineContainerStepDetails,
    "PipelineContainerStepRun": PipelineContainerStepRun,
    "PipelineContainerStepUpdateDetails": PipelineContainerStepUpdateDetails,
    "PipelineCustomScriptStepDetails": PipelineCustomScriptStepDetails,
    "PipelineCustomScriptStepRun": PipelineCustomScriptStepRun,
    "PipelineCustomScriptStepUpdateDetails": PipelineCustomScriptStepUpdateDetails,
    "PipelineDefaultConfigurationDetails": PipelineDefaultConfigurationDetails,
    "PipelineInfrastructureConfigurationDetails": PipelineInfrastructureConfigurationDetails,
    "PipelineLogConfigurationDetails": PipelineLogConfigurationDetails,
    "PipelineMLJobStepDetails": PipelineMLJobStepDetails,
    "PipelineMLJobStepRun": PipelineMLJobStepRun,
    "PipelineMLJobStepUpdateDetails": PipelineMLJobStepUpdateDetails,
    "PipelineOcirContainerConfigurationDetails": PipelineOcirContainerConfigurationDetails,
    "PipelineRun": PipelineRun,
    "PipelineRunLogDetails": PipelineRunLogDetails,
    "PipelineRunSummary": PipelineRunSummary,
    "PipelineShapeConfigDetails": PipelineShapeConfigDetails,
    "PipelineStepConfigurationDetails": PipelineStepConfigurationDetails,
    "PipelineStepDetails": PipelineStepDetails,
    "PipelineStepOverrideDetails": PipelineStepOverrideDetails,
    "PipelineStepRun": PipelineStepRun,
    "PipelineStepUpdateDetails": PipelineStepUpdateDetails,
    "PipelineSummary": PipelineSummary,
    "PredefinedExpressionThresholdScalingConfiguration": PredefinedExpressionThresholdScalingConfiguration,
    "PredefinedMetricExpressionRule": PredefinedMetricExpressionRule,
    "Project": Project,
    "ProjectSummary": ProjectSummary,
    "RetentionOperationDetails": RetentionOperationDetails,
    "RetentionSetting": RetentionSetting,
    "ScalingConfiguration": ScalingConfiguration,
    "ScalingPolicy": ScalingPolicy,
    "SingleModelDeploymentConfigurationDetails": SingleModelDeploymentConfigurationDetails,
    "StandaloneJobInfrastructureConfigurationDetails": StandaloneJobInfrastructureConfigurationDetails,
    "StorageMountConfigurationDetails": StorageMountConfigurationDetails,
    "ThresholdBasedAutoScalingPolicyDetails": ThresholdBasedAutoScalingPolicyDetails,
    "UpdateCategoryLogDetails": UpdateCategoryLogDetails,
    "UpdateDataSciencePrivateEndpointDetails": UpdateDataSciencePrivateEndpointDetails,
    "UpdateDefaultModelDeploymentEnvironmentConfigurationDetails": UpdateDefaultModelDeploymentEnvironmentConfigurationDetails,
    "UpdateJobDetails": UpdateJobDetails,
    "UpdateJobRunDetails": UpdateJobRunDetails,
    "UpdateModelConfigurationDetails": UpdateModelConfigurationDetails,
    "UpdateModelDeploymentConfigurationDetails": UpdateModelDeploymentConfigurationDetails,
    "UpdateModelDeploymentDetails": UpdateModelDeploymentDetails,
    "UpdateModelDeploymentEnvironmentConfigurationDetails": UpdateModelDeploymentEnvironmentConfigurationDetails,
    "UpdateModelDetails": UpdateModelDetails,
    "UpdateModelProvenanceDetails": UpdateModelProvenanceDetails,
    "UpdateModelVersionSetDetails": UpdateModelVersionSetDetails,
    "UpdateNotebookSessionDetails": UpdateNotebookSessionDetails,
    "UpdateOcirModelDeploymentEnvironmentConfigurationDetails": UpdateOcirModelDeploymentEnvironmentConfigurationDetails,
    "UpdatePipelineDetails": UpdatePipelineDetails,
    "UpdatePipelineRunDetails": UpdatePipelineRunDetails,
    "UpdateProjectDetails": UpdateProjectDetails,
    "UpdateSingleModelDeploymentConfigurationDetails": UpdateSingleModelDeploymentConfigurationDetails,
    "WorkRequest": WorkRequest,
    "WorkRequestError": WorkRequestError,
    "WorkRequestLogEntry": WorkRequestLogEntry,
    "WorkRequestResource": WorkRequestResource,
    "WorkRequestSummary": WorkRequestSummary
}
