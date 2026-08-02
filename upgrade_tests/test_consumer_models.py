import json

import oci
import pytest


MODEL_FIELD_CONTRACT = [
        (
            oci.core.models.Instance,
            {"id", "compartment_id", "defined_tags", "freeform_tags", "system_tags"},
        ),
        (
            oci.core.models.VnicAttachment,
            {"id", "instance_id", "vnic_id"},
        ),
        (
            oci.core.models.Vnic,
            {"id", "display_name", "is_primary", "private_ip", "subnet_id"},
        ),
        (
            oci.core.models.Subnet,
            {"id", "display_name", "vcn_id"},
        ),
        (
            oci.core.models.Vcn,
            {"id", "display_name"},
        ),
        (
            oci.core.models.PrivateIp,
            {"id", "ip_address", "vnic_id"},
        ),
        (
            oci.functions.models.Application,
            {"id", "compartment_id", "defined_tags", "freeform_tags"},
        ),
        (
            oci.functions.models.Function,
            {"id", "compartment_id", "defined_tags", "freeform_tags"},
        ),
        (
            oci.file_storage.models.FileSystem,
            {"id", "compartment_id", "display_name", "defined_tags", "freeform_tags"},
        ),
        (
            oci.identity.models.Compartment,
            {"id", "name"},
        ),
        (
            oci.identity.models.AvailabilityDomain,
            {"name"},
        ),
        (
            oci.identity.models.Tenancy,
            {"name"},
        ),
        (
            oci.load_balancer.models.LoadBalancer,
            {
                "id",
                "ip_addresses",
                "listeners",
                "backend_sets",
                "subnet_ids",
                "defined_tags",
                "freeform_tags",
            },
        ),
        (
            oci.monitoring.models.MetricData,
            {
                "compartment_id",
                "dimensions",
                "resource_group",
                "aggregated_datapoints",
            },
        ),
        (
            oci.monitoring.models.AlarmStatusSummary,
            {"id", "display_name", "status", "severity"},
        ),
        (
            oci.monitoring.models.Alarm,
            {"id", "query", "namespace"},
        ),
        (
            oci.network_load_balancer.models.NetworkLoadBalancerSummary,
            {
                "id",
                "compartment_id",
                "ip_addresses",
                "listeners",
                "backend_sets",
                "defined_tags",
                "freeform_tags",
            },
        ),
        (
            oci.network_load_balancer.models.NetworkLoadBalancerCollection,
            {"items"},
        ),
        (
            oci.object_storage.models.Bucket,
            {
                "etag",
                "name",
                "namespace",
                "compartment_id",
                "defined_tags",
                "freeform_tags",
            },
        ),
        (
            oci.object_storage.models.ObjectSummary,
            {"name", "size"},
        ),
        (
            oci.object_storage.models.ListObjects,
            {"objects", "next_start_with"},
        ),
]


@pytest.mark.parametrize(("model_class", "required_fields"), MODEL_FIELD_CONTRACT)
def test_python_oci_compute_consumed_model_fields(model_class, required_fields):
    values = {
        field: {
            "status": oci.monitoring.models.AlarmStatusSummary.STATUS_FIRING,
            "severity": oci.monitoring.models.AlarmStatusSummary.SEVERITY_CRITICAL,
            "aggregated_datapoints": ["datapoint-sentinel"],
        }.get(field, f"{field}-sentinel")
        for field in required_fields
    }
    model = model_class(**values)

    assert required_fields <= set(model.attribute_map)
    for field, value in values.items():
        assert getattr(model, field) == value


def test_python_oci_compute_model_inventory_is_complete():
    assert len(MODEL_FIELD_CONTRACT) == 21
    assert oci.monitoring.models.Alarm.LIFECYCLE_STATE_ACTIVE == "ACTIVE"


@pytest.mark.parametrize(
    ("client_class", "response_type", "payload", "expected"),
    [
        (
            oci.core.VirtualNetworkClient,
            "Subnet",
            {"id": "subnet-id", "displayName": "Subnet name", "vcnId": "vcn-id"},
            {"id": "subnet-id", "display_name": "Subnet name", "vcn_id": "vcn-id"},
        ),
        (
            oci.core.VirtualNetworkClient,
            "Vcn",
            {"id": "vcn-id", "displayName": "VCN name"},
            {"id": "vcn-id", "display_name": "VCN name"},
        ),
        (
            oci.core.VirtualNetworkClient,
            "Vnic",
            {
                "id": "vnic-id",
                "displayName": "VNIC name",
                "isPrimary": True,
                "privateIp": "10.0.0.10",
                "subnetId": "subnet-id",
            },
            {
                "id": "vnic-id",
                "display_name": "VNIC name",
                "is_primary": True,
                "private_ip": "10.0.0.10",
                "subnet_id": "subnet-id",
            },
        ),
        (
            oci.monitoring.MonitoringClient,
            "MetricData",
            {
                "compartmentId": "compartment-id",
                "dimensions": {"resourceId": "resource-id"},
                "resourceGroup": "resource-group",
                "aggregatedDatapoints": [
                    {"timestamp": "2026-08-01T12:00:00Z", "value": 42.5}
                ],
            },
            {
                "compartment_id": "compartment-id",
                "dimensions": {"resourceId": "resource-id"},
                "resource_group": "resource-group",
                "aggregated_datapoints": [42.5],
            },
        ),
        (
            oci.monitoring.MonitoringClient,
            "AlarmStatusSummary",
            {
                "id": "alarm-id",
                "displayName": "Alarm name",
                "status": "FIRING",
                "severity": "CRITICAL",
            },
            {
                "id": "alarm-id",
                "display_name": "Alarm name",
                "status": "FIRING",
                "severity": "CRITICAL",
            },
        ),
        (
            oci.monitoring.MonitoringClient,
            "Alarm",
            {
                "id": "alarm-id",
                "query": "CpuUtilization[1m].mean() > 90",
                "namespace": "oci_computeagent",
            },
            {
                "id": "alarm-id",
                "query": "CpuUtilization[1m].mean() > 90",
                "namespace": "oci_computeagent",
            },
        ),
    ],
)
def test_consumer_models_deserialize_from_api_payloads(
    client_class,
    response_type,
    payload,
    expected,
):
    client = client_class(
        {},
        signer=object.__new__(oci.auth.signers.SecurityTokenSigner),
        service_endpoint="https://service.example.com",
    )

    model = client.base_client.deserialize_response_data(
        json.dumps(payload).encode("utf-8"),
        response_type,
    )

    for field, expected_value in expected.items():
        actual_value = getattr(model, field)
        if field == "aggregated_datapoints":
            actual_value = [datapoint.value for datapoint in actual_value]
        assert actual_value == expected_value
