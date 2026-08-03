PRUNED_SOURCE_TARGETS = frozenset(
    {
        "src/oci/alloy.py",
        "src/oci/database/database_client_composite_operations.py",
        "src/oci/database_management",
        "src/oci/database_tools",
        "src/oci/queue",
        "src/oci/work_requests",
        "src/oci/waiter.py",
        "src/oci/core/blockstorage_client_composite_operations.py",
        "src/oci/core/compute_client_composite_operations.py",
        "src/oci/core/compute_management_client_composite_operations.py",
        "src/oci/core/virtual_network_client_composite_operations.py",
        "src/oci/dns/dns_client.py",
        "src/oci/dns/dns_client_composite_operations.py",
        "src/oci/file_storage/file_storage_client_composite_operations.py",
        "src/oci/functions/functions_invoke_client.py",
        "src/oci/functions/functions_invoke_client_composite_operations.py",
        "src/oci/functions/functions_management_client_composite_operations.py",
        "src/oci/identity/identity_client_composite_operations.py",
        "src/oci/load_balancer/load_balancer_client_composite_operations.py",
        "src/oci/monitoring/monitoring_client_composite_operations.py",
        "src/oci/network_load_balancer/network_load_balancer_client_composite_operations.py",
        "src/oci/object_storage/object_storage_client_composite_operations.py",
        "src/oci/object_storage/transfer",
    }
)


def source_target_to_module(source_target):
    module_path = source_target.removeprefix("src/")
    if module_path.endswith(".py"):
        module_path = module_path[:-3]
    return module_path.replace("/", ".")


PRUNED_IMPORTABLE_MODULES = tuple(
    sorted(source_target_to_module(target) for target in PRUNED_SOURCE_TARGETS)
)
