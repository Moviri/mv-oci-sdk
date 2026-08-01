import ast
import importlib
import importlib.metadata
import importlib.util
import inspect
import pkgutil
import re
from pathlib import Path

import jwt
import oci
import pytest
import urllib3
from packaging.requirements import Requirement

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


RETAINED_SERVICES = (
    "core",
    "file_storage",
    "functions",
    "identity",
    "load_balancer",
    "monitoring",
    "network_load_balancer",
    "object_storage",
)

INTERNAL_PACKAGES = (
    "_vendor",
    "auth",
    "circuit_breaker",
    "dns",
    "pagination",
    "retry",
)

EXCLUDED_SERVICES = (
    "database",
    "database_management",
    "database_tools",
    "queue",
    "work_requests",
)


def test_version_and_every_retained_service_import():
    assert oci.__version__ == "2.183.0.1"
    assert importlib.metadata.version("mv-oci-sdk") == "2.183.0.1"
    assert oci._RETAINED_SERVICES == list(RETAINED_SERVICES)

    for service in RETAINED_SERVICES:
        assert importlib.import_module(f"oci.{service}") is not None
        assert service in oci.__all__


def test_top_level_package_boundary_is_exact():
    package_root = Path(oci.__file__).resolve().parent
    packaged_directories = {
        path.name
        for path in package_root.iterdir()
        if path.is_dir() and (path / "__init__.py").is_file()
    }

    assert packaged_directories == set(RETAINED_SERVICES + INTERNAL_PACKAGES)


@pytest.mark.parametrize("service", ("audit", *EXCLUDED_SERVICES))
def test_excluded_service_is_not_advertised_or_packaged(service):
    assert service not in oci.__all__
    assert importlib.util.find_spec(f"oci.{service}") is None


@pytest.mark.parametrize(
    "module_name",
    (
        "oci.waiter",
        "oci.core.compute_client_composite_operations",
        "oci.dns.dns_client",
        "oci.dns.dns_client_composite_operations",
        "oci.file_storage.file_storage_client_composite_operations",
        "oci.functions.functions_invoke_client",
        "oci.functions.functions_management_client_composite_operations",
        "oci.identity.identity_client_composite_operations",
        "oci.load_balancer.load_balancer_client_composite_operations",
        "oci.monitoring.monitoring_client_composite_operations",
        "oci.network_load_balancer.network_load_balancer_client_composite_operations",
        "oci.object_storage.object_storage_client_composite_operations",
        "oci.object_storage.transfer",
    ),
)
def test_unused_optional_module_is_not_packaged(module_name):
    assert importlib.util.find_spec(module_name) is None


def test_every_packaged_module_imports():
    failures = {}
    for module in pkgutil.walk_packages(oci.__path__, prefix="oci."):
        try:
            importlib.import_module(module.name)
        except Exception as error:  # pragma: no cover - assertion reports exact module
            failures[module.name] = f"{type(error).__name__}: {error}"

    assert not failures


def test_urllib3_and_pyjwt_are_external_dependencies():
    package_root = Path(oci.__file__).resolve().parent

    assert not (package_root / "_vendor" / "urllib3").exists()
    assert not (package_root / "_vendor" / "jwt").exists()
    assert package_root not in Path(urllib3.__file__).resolve().parents
    assert package_root not in Path(jwt.__file__).resolve().parents


def test_dependency_and_build_safety_floors():
    root = Path(__file__).resolve().parents[1]
    setup_tree = ast.parse((root / "setup.py").read_text(encoding="utf-8"))
    setup_requires = next(
        ast.literal_eval(node.value)
        for node in setup_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "requires"
            for target in node.targets
        )
    )
    setup_requirements = {
        Requirement(value).name.lower(): Requirement(value)
        for value in setup_requires
    }
    readable_requirements = {
        Requirement(value).name.lower(): Requirement(value)
        for value in (root / "requirements.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        if value and not value.startswith("#")
    }

    for requirements in (setup_requirements, readable_requirements):
        assert str(requirements["cryptography"].specifier) == "<50.0.0,>=46.0.5"
        assert str(requirements["pyopenssl"].specifier) == "<27.0.0,>=26.0.0"
        assert "crc32c" not in requirements

    assert str(readable_requirements["pytest"].specifier) == "<10,>=9.0.3"

    build_metadata = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8")
    )
    build_requirements = {
        Requirement(value).name.lower(): Requirement(value)
        for value in build_metadata["build-system"]["requires"]
    }
    assert str(build_requirements["wheel"].specifier) == ">=0.46.2"


def test_public_package_metadata_describes_consumer_exclusive_contract():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.rst").read_text(encoding="utf-8")
    documented_services = tuple(
        re.findall(r"^\* ``([^`]+)``$", readme, flags=re.MULTILINE)
    )
    normalized_readme = " ".join(readme.split())

    assert "Moviri-maintained, consumer-exclusive runtime" in normalized_readme
    assert "curated for ``python-oci-compute``" in normalized_readme
    assert documented_services == RETAINED_SERVICES
    assert "Python 3.10, 3.11, 3.12, 3.13, and 3.14 are the tested support matrix" in normalized_readme
    assert "DNS models are retained only as an internal pagination dependency" in normalized_readme
    assert "The DNS client is not packaged or supported" in normalized_readme
    for excluded_helper in (
        "standalone waiter",
        "generated composite-operation wrappers",
        "Functions Invoke client",
        "Object Storage transfer helpers",
    ):
        assert excluded_helper in normalized_readme
    assert "Oracle does not maintain this Moviri distribution" in normalized_readme

    setup_tree = ast.parse((root / "setup.py").read_text(encoding="utf-8"))
    setup_call = next(
        node.value
        for node in setup_tree.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "setup"
    )
    setup_keywords = {
        keyword.arg: ast.literal_eval(keyword.value)
        for keyword in setup_call.keywords
        if keyword.arg in {"description", "python_requires"}
    }
    assert setup_keywords == {
        "description": "Moviri-maintained OCI SDK runtime curated exclusively for python-oci-compute",
        "python_requires": ">=3.10",
    }


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
