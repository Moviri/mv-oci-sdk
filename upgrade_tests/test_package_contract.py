import importlib
import importlib.metadata
import importlib.util
import inspect
from pathlib import Path

import jwt
import oci
import urllib3


RETAINED_SERVICES = (
    "core",
    "database",
    "database_management",
    "database_tools",
    "dns",
    "file_storage",
    "functions",
    "identity",
    "load_balancer",
    "monitoring",
    "network_load_balancer",
    "object_storage",
    "queue",
    "work_requests",
)


def test_version_and_every_retained_service_import():
    assert oci.__version__ == "2.183.0.1"
    assert importlib.metadata.version("mv-oci-sdk") == "2.183.0.1"

    for service in RETAINED_SERVICES:
        assert importlib.import_module(f"oci.{service}") is not None
        assert service in oci.__all__


def test_excluded_service_is_not_advertised_or_packaged():
    assert "audit" not in oci.__all__
    assert importlib.util.find_spec("oci.audit") is None


def test_urllib3_and_pyjwt_are_external_dependencies():
    package_root = Path(oci.__file__).resolve().parent

    assert not (package_root / "_vendor" / "urllib3").exists()
    assert not (package_root / "_vendor" / "jwt").exists()
    assert package_root not in Path(urllib3.__file__).resolve().parents
    assert package_root not in Path(jwt.__file__).resolve().parents


def test_python_oci_compute_method_signatures():
    expected = {
        (oci.core.ComputeClient, "list_instances"): "(self, compartment_id, **kwargs)",
        (oci.core.ComputeClient, "list_vnic_attachments"): "(self, compartment_id, **kwargs)",
        (oci.core.BlockstorageClient, "list_volumes"): "(self, **kwargs)",
        (oci.core.BlockstorageClient, "list_boot_volumes"): "(self, **kwargs)",
        (oci.core.ComputeManagementClient, "list_instance_pools"): "(self, compartment_id, **kwargs)",
        (oci.core.VirtualNetworkClient, "list_vcns"): "(self, compartment_id, **kwargs)",
        (oci.core.VirtualNetworkClient, "list_ip_sec_connections"): "(self, compartment_id, **kwargs)",
        (oci.core.VirtualNetworkClient, "get_vnic"): "(self, vnic_id, **kwargs)",
        (oci.core.VirtualNetworkClient, "get_private_ip"): "(self, private_ip_id, **kwargs)",
        (oci.file_storage.FileStorageClient, "list_file_systems"): "(self, compartment_id, availability_domain, **kwargs)",
        (oci.file_storage.FileStorageClient, "get_file_system"): "(self, file_system_id, **kwargs)",
        (oci.functions.FunctionsManagementClient, "list_applications"): "(self, compartment_id, **kwargs)",
        (oci.functions.FunctionsManagementClient, "list_functions"): "(self, application_id, **kwargs)",
        (oci.identity.IdentityClient, "list_compartments"): "(self, compartment_id, **kwargs)",
        (oci.identity.IdentityClient, "list_availability_domains"): "(self, compartment_id, **kwargs)",
        (oci.identity.IdentityClient, "get_tenancy"): "(self, tenancy_id, **kwargs)",
        (oci.identity.IdentityClient, "get_compartment"): "(self, compartment_id, **kwargs)",
        (oci.load_balancer.LoadBalancerClient, "list_load_balancers"): "(self, compartment_id, **kwargs)",
        (oci.monitoring.MonitoringClient, "summarize_metrics_data"): "(self, compartment_id, summarize_metrics_data_details, **kwargs)",
        (oci.monitoring.MonitoringClient, "list_alarms_status"): "(self, compartment_id, **kwargs)",
        (oci.network_load_balancer.NetworkLoadBalancerClient, "list_network_load_balancers"): "(self, compartment_id, **kwargs)",
        (oci.object_storage.ObjectStorageClient, "get_namespace"): "(self, **kwargs)",
        (oci.object_storage.ObjectStorageClient, "list_buckets"): "(self, namespace_name, compartment_id, **kwargs)",
        (oci.object_storage.ObjectStorageClient, "get_bucket"): "(self, namespace_name, bucket_name, **kwargs)",
        (oci.object_storage.ObjectStorageClient, "list_objects"): "(self, namespace_name, bucket_name, **kwargs)",
    }

    assert len(expected) == 25
    for (client_class, method_name), expected_signature in expected.items():
        method = getattr(client_class, method_name)
        assert str(inspect.signature(method)) == expected_signature
