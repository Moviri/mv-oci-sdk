import oci
import pytest


@pytest.mark.parametrize(
    ("model_class", "required_fields"),
    [
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
            {"id", "is_primary", "private_ip", "subnet_id"},
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
            {"compartment_id", "dimensions", "resource_group"},
        ),
        (
            oci.monitoring.models.AlarmStatusSummary,
            {"id", "display_name"},
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
    ],
)
def test_python_oci_compute_consumed_model_fields(model_class, required_fields):
    model = model_class()
    assert required_fields <= set(model.attribute_map)
