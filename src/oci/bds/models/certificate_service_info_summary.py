# coding: utf-8
# Copyright (c) 2016, 2023, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20190531


from oci.util import formatted_flat_dict, NONE_SENTINEL, value_allowed_none_or_none_sentinel  # noqa: F401
from oci.decorators import init_model_state_from_kwargs


@init_model_state_from_kwargs
class CertificateServiceInfoSummary(object):
    """
    List of TLS/SSL information of services
    """

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "ZOOKEEPER"
    SERVICE_ZOOKEEPER = "ZOOKEEPER"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "AMS"
    SERVICE_AMS = "AMS"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "HDFS"
    SERVICE_HDFS = "HDFS"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "YARN"
    SERVICE_YARN = "YARN"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "MAPREDUCE"
    SERVICE_MAPREDUCE = "MAPREDUCE"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "OOZIE"
    SERVICE_OOZIE = "OOZIE"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "HBASE"
    SERVICE_HBASE = "HBASE"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "SPARK"
    SERVICE_SPARK = "SPARK"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "HIVE"
    SERVICE_HIVE = "HIVE"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "KAFKA"
    SERVICE_KAFKA = "KAFKA"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "FLINK"
    SERVICE_FLINK = "FLINK"

    #: A constant which can be used with the service property of a CertificateServiceInfoSummary.
    #: This constant has a value of "REGISTRY"
    SERVICE_REGISTRY = "REGISTRY"

    #: A constant which can be used with the service_certificate_status property of a CertificateServiceInfoSummary.
    #: This constant has a value of "ENABLED"
    SERVICE_CERTIFICATE_STATUS_ENABLED = "ENABLED"

    #: A constant which can be used with the service_certificate_status property of a CertificateServiceInfoSummary.
    #: This constant has a value of "DISABLED"
    SERVICE_CERTIFICATE_STATUS_DISABLED = "DISABLED"

    def __init__(self, **kwargs):
        """
        Initializes a new CertificateServiceInfoSummary object with values from keyword arguments.
        The following keyword arguments are supported (corresponding to the getters/setters of this class):

        :param service:
            The value to assign to the service property of this CertificateServiceInfoSummary.
            Allowed values for this property are: "ZOOKEEPER", "AMS", "HDFS", "YARN", "MAPREDUCE", "OOZIE", "HBASE", "SPARK", "HIVE", "KAFKA", "FLINK", "REGISTRY", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type service: str

        :param service_certificate_status:
            The value to assign to the service_certificate_status property of this CertificateServiceInfoSummary.
            Allowed values for this property are: "ENABLED", "DISABLED", 'UNKNOWN_ENUM_VALUE'.
            Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.
        :type service_certificate_status: str

        :param host_specific_certificate_details:
            The value to assign to the host_specific_certificate_details property of this CertificateServiceInfoSummary.
        :type host_specific_certificate_details: list[oci.bds.models.HostSpecificCertificateDetails]

        """
        self.swagger_types = {
            'service': 'str',
            'service_certificate_status': 'str',
            'host_specific_certificate_details': 'list[HostSpecificCertificateDetails]'
        }

        self.attribute_map = {
            'service': 'service',
            'service_certificate_status': 'serviceCertificateStatus',
            'host_specific_certificate_details': 'hostSpecificCertificateDetails'
        }

        self._service = None
        self._service_certificate_status = None
        self._host_specific_certificate_details = None

    @property
    def service(self):
        """
        **[Required]** Gets the service of this CertificateServiceInfoSummary.
        Name of the service

        Allowed values for this property are: "ZOOKEEPER", "AMS", "HDFS", "YARN", "MAPREDUCE", "OOZIE", "HBASE", "SPARK", "HIVE", "KAFKA", "FLINK", "REGISTRY", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The service of this CertificateServiceInfoSummary.
        :rtype: str
        """
        return self._service

    @service.setter
    def service(self, service):
        """
        Sets the service of this CertificateServiceInfoSummary.
        Name of the service


        :param service: The service of this CertificateServiceInfoSummary.
        :type: str
        """
        allowed_values = ["ZOOKEEPER", "AMS", "HDFS", "YARN", "MAPREDUCE", "OOZIE", "HBASE", "SPARK", "HIVE", "KAFKA", "FLINK", "REGISTRY"]
        if not value_allowed_none_or_none_sentinel(service, allowed_values):
            service = 'UNKNOWN_ENUM_VALUE'
        self._service = service

    @property
    def service_certificate_status(self):
        """
        **[Required]** Gets the service_certificate_status of this CertificateServiceInfoSummary.
        Whether certificate is enabled or disabled

        Allowed values for this property are: "ENABLED", "DISABLED", 'UNKNOWN_ENUM_VALUE'.
        Any unrecognized values returned by a service will be mapped to 'UNKNOWN_ENUM_VALUE'.


        :return: The service_certificate_status of this CertificateServiceInfoSummary.
        :rtype: str
        """
        return self._service_certificate_status

    @service_certificate_status.setter
    def service_certificate_status(self, service_certificate_status):
        """
        Sets the service_certificate_status of this CertificateServiceInfoSummary.
        Whether certificate is enabled or disabled


        :param service_certificate_status: The service_certificate_status of this CertificateServiceInfoSummary.
        :type: str
        """
        allowed_values = ["ENABLED", "DISABLED"]
        if not value_allowed_none_or_none_sentinel(service_certificate_status, allowed_values):
            service_certificate_status = 'UNKNOWN_ENUM_VALUE'
        self._service_certificate_status = service_certificate_status

    @property
    def host_specific_certificate_details(self):
        """
        **[Required]** Gets the host_specific_certificate_details of this CertificateServiceInfoSummary.
        List of Host specific certificate details


        :return: The host_specific_certificate_details of this CertificateServiceInfoSummary.
        :rtype: list[oci.bds.models.HostSpecificCertificateDetails]
        """
        return self._host_specific_certificate_details

    @host_specific_certificate_details.setter
    def host_specific_certificate_details(self, host_specific_certificate_details):
        """
        Sets the host_specific_certificate_details of this CertificateServiceInfoSummary.
        List of Host specific certificate details


        :param host_specific_certificate_details: The host_specific_certificate_details of this CertificateServiceInfoSummary.
        :type: list[oci.bds.models.HostSpecificCertificateDetails]
        """
        self._host_specific_certificate_details = host_specific_certificate_details

    def __repr__(self):
        return formatted_flat_dict(self)

    def __eq__(self, other):
        if other is None:
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other
