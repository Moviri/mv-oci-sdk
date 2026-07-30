import ast
import importlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import oci
import pytest

from oci.database_management import (
    ManagedMySqlDatabasesClient,
    ManagedMySqlDatabasesClientCompositeOperations,
)
from oci.response import Response


ROOT = Path(__file__).resolve().parents[1]


def operation_response(headers=None):
    return Response(202, headers or {}, None, None)


def test_managed_mysql_get_work_request_uses_database_management_operation():
    client = object.__new__(ManagedMySqlDatabasesClient)
    client.base_client = Mock()
    client.base_client.get_preferred_retry_strategy.return_value = None
    client.base_client.call_api.return_value = Response(
        200,
        {},
        SimpleNamespace(status="SUCCEEDED"),
        None,
    )
    client.retry_strategy = None
    client.circuit_breaker_callback = None

    result = client.get_work_request("work-request-id")

    assert result.data.status == "SUCCEEDED"
    client.base_client.call_api.assert_called_once_with(
        resource_path="/workRequests/{workRequestId}",
        method="GET",
        path_params={"workRequestId": "work-request-id"},
        header_params={
            "accept": "application/json",
            "content-type": "application/json",
        },
        response_type="WorkRequest",
        allow_control_chars=None,
        enable_strict_url_encoding=None,
        operation_name="get_work_request",
        api_reference_link="https://docs.oracle.com/iaas/api/#/en/database-management/20201101/WorkRequest/GetWorkRequest",
        required_arguments=["workRequestId"],
    )


def test_managed_mysql_composite_polls_work_request():
    client = Mock(spec=ManagedMySqlDatabasesClient)
    operation_result = operation_response(
        {"opc-work-request-id": "work-request-id"}
    )
    initial_work_request = Response(
        200,
        {},
        SimpleNamespace(status="IN_PROGRESS"),
        None,
    )
    completed_work_request = Response(
        200,
        {},
        SimpleNamespace(status="SUCCEEDED"),
        None,
    )
    client.change_mysql_database_management_type.return_value = operation_result
    client.get_work_request.return_value = initial_work_request
    composite = ManagedMySqlDatabasesClientCompositeOperations(client)

    with patch("oci.wait_until", return_value=completed_work_request) as wait_until:
        result = composite.change_mysql_database_management_type_and_wait_for_state(
            "managed-mysql-id",
            Mock(),
            wait_for_states=["SUCCEEDED"],
        )

    assert result is completed_work_request
    client.get_work_request.assert_called_once_with("work-request-id")
    wait_until.assert_called_once()
    assert wait_until.call_args.args[:2] == (client, initial_work_request)


@pytest.mark.parametrize(
    "wait_states,headers",
    [
        ([], {"opc-work-request-id": "work-request-id"}),
        (["SUCCEEDED"], {}),
    ],
)
def test_managed_mysql_composite_immediate_return_paths(wait_states, headers):
    client = Mock(spec=ManagedMySqlDatabasesClient)
    operation_result = operation_response(headers)
    client.change_mysql_database_management_type.return_value = operation_result
    composite = ManagedMySqlDatabasesClientCompositeOperations(client)

    result = composite.change_mysql_database_management_type_and_wait_for_state(
        "managed-mysql-id",
        Mock(),
        wait_for_states=wait_states,
    )

    assert result is operation_result
    client.get_work_request.assert_not_called()


def test_managed_mysql_composite_preserves_partial_result_on_poll_failure():
    client = Mock(spec=ManagedMySqlDatabasesClient)
    operation_result = operation_response(
        {"opc-work-request-id": "work-request-id"}
    )
    poll_failure = RuntimeError("poll failed")
    client.change_mysql_database_management_type.return_value = operation_result
    client.get_work_request.side_effect = poll_failure
    composite = ManagedMySqlDatabasesClientCompositeOperations(client)

    with pytest.raises(oci.exceptions.CompositeOperationError) as raised:
        composite.change_mysql_database_management_type_and_wait_for_state(
            "managed-mysql-id",
            Mock(),
            wait_for_states=["SUCCEEDED"],
        )

    assert raised.value.partial_results == [operation_result]
    assert raised.value.cause is poll_failure


def test_every_retained_composite_client_call_exists_on_wrapped_client():
    missing_methods = []
    for composite_path in sorted(
        (ROOT / "src" / "oci").glob("*/*_client_composite_operations.py")
    ):
        service = composite_path.parent.name
        composite_module_name = composite_path.stem
        client_module_name = composite_module_name.removesuffix(
            "_composite_operations"
        )
        composite_module = importlib.import_module(
            f"oci.{service}.{composite_module_name}"
        )
        client_module = importlib.import_module(
            f"oci.{service}.{client_module_name}"
        )
        tree = ast.parse(composite_path.read_text(encoding="utf-8"))

        for class_node in (
            node for node in tree.body if isinstance(node, ast.ClassDef)
        ):
            if not class_node.name.endswith("ClientCompositeOperations"):
                continue
            client_class_name = class_node.name.removesuffix(
                "CompositeOperations"
            )
            client_class = getattr(client_module, client_class_name)
            getattr(composite_module, class_node.name)

            for node in ast.walk(class_node):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Attribute)
                    and isinstance(node.func.value.value, ast.Name)
                    and node.func.value.value.id == "self"
                    and node.func.value.attr == "client"
                    and not hasattr(client_class, node.func.attr)
                ):
                    missing_methods.append(
                        f"{class_node.name}.{node.func.attr}"
                    )

    assert not missing_methods
