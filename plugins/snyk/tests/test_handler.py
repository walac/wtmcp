"""Tests for Snyk handler tool functions."""

import base64
import json
from unittest import mock

import handler


def _mock_http(status, body):
    """Create a mock http() that returns a fixed response."""
    return mock.patch.object(handler, "http", return_value=(status, body, {}))


# ---------- Tier 1: Write Tool Safety ----------


class TestIgnoreIssue:
    BASE_PARAMS = {
        "org_id": "org-1",
        "project_id": "proj-1",
        "issue_id": "issue-1",
        "reason": "false positive",
    }

    def test_dry_run_true_returns_preview(self):
        params = {**self.BASE_PARAMS, "dry_run": True}
        result = handler.snyk_ignore_issue(params)
        assert result["dry_run"] is True
        assert result["action"] == "snyk_ignore_issue"
        assert result["issue_id"] == "issue-1"

    def test_dry_run_omitted_defaults_to_true(self):
        result = handler.snyk_ignore_issue(self.BASE_PARAMS)
        assert result["dry_run"] is True

    def test_dry_run_none_treated_as_true(self):
        params = {**self.BASE_PARAMS, "dry_run": None}
        result = handler.snyk_ignore_issue(params)
        assert result["dry_run"] is True

    def test_dry_run_false_calls_api(self):
        params = {**self.BASE_PARAMS, "dry_run": False}
        with _mock_http(200, {"ok": True}) as mock_h:
            result = handler.snyk_ignore_issue(params)
        assert result["success"] is True
        mock_h.assert_called_once()
        call_args = mock_h.call_args
        assert call_args[0][0] == "POST"

    def test_request_body_structure(self):
        params = {**self.BASE_PARAMS, "dry_run": True}
        result = handler.snyk_ignore_issue(params)
        body = result["body"]
        assert body["ignorePath"] == "*"
        assert body["reason"] == "false positive"
        assert body["reasonType"] == "not-vulnerable"
        assert body["disregardIfFixable"] is False

    def test_valid_reason_types(self):
        for rt in ("not-vulnerable", "wont-fix", "temporary-ignore"):
            params = {**self.BASE_PARAMS, "reason_type": rt}
            result = handler.snyk_ignore_issue(params)
            assert result["body"]["reasonType"] == rt

    def test_invalid_reason_type_raises(self):
        params = {**self.BASE_PARAMS, "reason_type": "invalid"}
        try:
            handler.snyk_ignore_issue(params)
            assert False, "expected ValueError"
        except ValueError as e:
            assert "invalid" in str(e).lower()


class TestDeleteIgnore:
    BASE_PARAMS = {
        "org_id": "org-1",
        "project_id": "proj-1",
        "issue_id": "issue-1",
    }

    def test_dry_run_true_returns_preview(self):
        params = {**self.BASE_PARAMS, "dry_run": True}
        result = handler.snyk_delete_ignore(params)
        assert result["dry_run"] is True
        assert result["action"] == "snyk_delete_ignore"

    def test_dry_run_omitted_defaults_to_true(self):
        result = handler.snyk_delete_ignore(self.BASE_PARAMS)
        assert result["dry_run"] is True

    def test_dry_run_none_treated_as_true(self):
        params = {**self.BASE_PARAMS, "dry_run": None}
        result = handler.snyk_delete_ignore(params)
        assert result["dry_run"] is True

    def test_dry_run_false_calls_api(self):
        params = {**self.BASE_PARAMS, "dry_run": False}
        with _mock_http(200, {}) as mock_h:
            result = handler.snyk_delete_ignore(params)
        assert result["success"] is True
        mock_h.assert_called_once()
        call_args = mock_h.call_args
        assert call_args[0][0] == "DELETE"

    def test_missing_required_params(self):
        for key in ("org_id", "project_id", "issue_id"):
            params = {**{k: v for k, v in self.BASE_PARAMS.items() if k != key}, "dry_run": False}
            try:
                handler.snyk_delete_ignore(params)
                assert False, f"expected KeyError for missing {key}"
            except KeyError:
                pass


# ---------- Tier 2: Pagination Logic ----------


class TestRestGetPaginated:
    def test_single_page(self):
        body = {"data": [{"id": "1"}, {"id": "2"}], "links": {}}
        with _mock_http(200, body):
            result = handler._rest_get_paginated("orgs")
        assert len(result) == 2

    def test_multi_page_relative_link(self):
        page1 = {"data": [{"id": "1"}], "links": {"next": "/rest/orgs?page=2"}}
        page2 = {"data": [{"id": "2"}], "links": {}}
        with mock.patch.object(
            handler,
            "http",
            side_effect=[
                (200, page1, {}),
                (200, page2, {}),
            ],
        ):
            result = handler._rest_get_paginated("orgs")
        assert len(result) == 2
        assert result[0]["id"] == "1"
        assert result[1]["id"] == "2"

    def test_multi_page_absolute_url(self):
        page1 = {"data": [{"id": "1"}], "links": {"next": "https://api.snyk.io/rest/orgs?page=2"}}
        page2 = {"data": [{"id": "2"}], "links": {}}
        with mock.patch.object(
            handler,
            "http",
            side_effect=[
                (200, page1, {}),
                (200, page2, {}),
            ],
        ):
            result = handler._rest_get_paginated("orgs")
        assert len(result) == 2

    def test_http_error_mid_pagination_returns_partial(self):
        page1 = {"data": [{"id": "1"}], "links": {"next": "https://api.snyk.io/rest/orgs?page=2"}}
        with mock.patch.object(
            handler,
            "http",
            side_effect=[
                (200, page1, {}),
                (500, {"error": "server error"}, {}),
            ],
        ):
            result = handler._rest_get_paginated("orgs")
        assert len(result) == 1

    def test_empty_data_array(self):
        with _mock_http(200, {"data": [], "links": {}}):
            result = handler._rest_get_paginated("orgs")
        assert result == []

    def test_missing_links_key(self):
        with _mock_http(200, {"data": [{"id": "1"}]}):
            result = handler._rest_get_paginated("orgs")
        assert len(result) == 1

    def test_links_null(self):
        with _mock_http(200, {"data": [{"id": "1"}], "links": None}):
            result = handler._rest_get_paginated("orgs")
        assert len(result) == 1

    def test_default_limit_set(self):
        with _mock_http(200, {"data": [], "links": {}}) as mock_h:
            handler._rest_get_paginated("orgs")
        query = mock_h.call_args[1].get("query") or mock_h.call_args[0][2]
        assert query["limit"] == "100"

    def test_caller_limit_preserved(self):
        with _mock_http(200, {"data": [], "links": {}}) as mock_h:
            handler._rest_get_paginated("orgs", {"limit": "25"})
        query = mock_h.call_args[1].get("query") or mock_h.call_args[0][2]
        assert query["limit"] == "25"


# ---------- Tier 3: HTTP Helpers ----------


class TestRestGet:
    def test_version_param_included(self):
        with _mock_http(200, {"data": []}) as mock_h:
            handler._rest_get("orgs")
        query = mock_h.call_args[1].get("query") or mock_h.call_args[0][2]
        assert query["version"] == handler.REST_VERSION

    def test_rest_prefix_added(self):
        with _mock_http(200, {}) as mock_h:
            handler._rest_get("orgs")
        assert mock_h.call_args[0][1] == "/rest/orgs"

    def test_rest_prefix_not_doubled(self):
        with _mock_http(200, {}) as mock_h:
            handler._rest_get("/rest/orgs")
        assert mock_h.call_args[0][1] == "/rest/orgs"

    def test_additional_params_merged(self):
        with _mock_http(200, {}) as mock_h:
            handler._rest_get("orgs", {"severity": "high"})
        query = mock_h.call_args[1].get("query") or mock_h.call_args[0][2]
        assert query["version"] == handler.REST_VERSION
        assert query["severity"] == "high"

    def test_error_status_raises(self):
        with _mock_http(404, {"error": "not found"}):
            try:
                handler._rest_get("orgs/bad")
                assert False, "expected RuntimeError"
            except RuntimeError as e:
                assert "404" in str(e)


class TestV1Request:
    def test_v1_prefix_added(self):
        with _mock_http(200, {}) as mock_h:
            handler._v1_request("GET", "org/1/projects")
        assert mock_h.call_args[0][1] == "/v1/org/1/projects"

    def test_v1_prefix_not_doubled(self):
        with _mock_http(200, {}) as mock_h:
            handler._v1_request("GET", "/v1/org/1/projects")
        assert mock_h.call_args[0][1] == "/v1/org/1/projects"

    def test_content_type_header_set(self):
        with _mock_http(200, {}) as mock_h:
            handler._v1_request("POST", "org/1/test", body={"key": "val"})
        headers = mock_h.call_args[1].get("headers") or mock_h.call_args[0][4]
        assert headers["Content-Type"] == "application/json"

    def test_body_passed_through(self):
        with _mock_http(200, {}) as mock_h:
            handler._v1_request("POST", "org/1/test", body={"key": "val"})
        body = mock_h.call_args[1].get("body") or mock_h.call_args[0][3]
        assert body == {"key": "val"}

    def test_error_status_raises(self):
        with _mock_http(403, {"error": "forbidden"}):
            try:
                handler._v1_request("GET", "org/1/projects")
                assert False, "expected RuntimeError"
            except RuntimeError as e:
                assert "403" in str(e)


class TestHttpHelper:
    def test_status_zero_returns_error(self):
        with (
            mock.patch.object(handler, "_send"),
            mock.patch.object(handler, "_recv", return_value={"status": 0, "error": "timeout"}),
        ):
            status, body, _ = handler.http("GET", "/test")
        assert status == 0
        assert "error" in body

    def test_base64_json_body_decoded(self):
        encoded = base64.b64encode(json.dumps({"key": "val"}).encode()).decode()
        with (
            mock.patch.object(handler, "_send"),
            mock.patch.object(
                handler,
                "_recv",
                return_value={
                    "status": 200,
                    "body": encoded,
                    "body_encoding": "base64",
                },
            ),
        ):
            status, body, _ = handler.http("GET", "/test")
        assert status == 200
        assert body == {"key": "val"}

    def test_base64_non_json_body_returns_string(self):
        encoded = base64.b64encode(b"not json").decode()
        with (
            mock.patch.object(handler, "_send"),
            mock.patch.object(
                handler,
                "_recv",
                return_value={
                    "status": 200,
                    "body": encoded,
                    "body_encoding": "base64",
                },
            ),
        ):
            status, body, _ = handler.http("GET", "/test")
        assert status == 200
        assert body == "not json"

    def test_string_body_auto_parsed(self):
        with (
            mock.patch.object(handler, "_send"),
            mock.patch.object(
                handler,
                "_recv",
                return_value={
                    "status": 200,
                    "body": '{"key": "val"}',
                },
            ),
        ):
            _, body, _ = handler.http("GET", "/test")
        assert body == {"key": "val"}

    def test_non_json_string_body_passthrough(self):
        with (
            mock.patch.object(handler, "_send"),
            mock.patch.object(
                handler,
                "_recv",
                return_value={
                    "status": 200,
                    "body": "plain text",
                },
            ),
        ):
            _, body, _ = handler.http("GET", "/test")
        assert body == "plain text"


# ---------- Tier 4: Tool Logic + Input Validation ----------


class TestInputValidation:
    def test_path_traversal_not_validated(self):
        with _mock_http(200, {"data": [], "links": {}}) as mock_h:
            handler.snyk_list_projects({"org_id": "../../admin"})
        path = mock_h.call_args[0][1]
        assert "../../admin" in path

    def test_invalid_reason_type_none_raises(self):
        params = {
            "org_id": "org-1",
            "project_id": "proj-1",
            "issue_id": "issue-1",
            "reason": "test",
            "reason_type": None,
        }
        try:
            handler.snyk_ignore_issue(params)
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestListOrgs:
    def test_extracts_fields(self):
        items = [
            {"id": "org-1", "attributes": {"name": "My Org", "slug": "my-org"}},
            {"id": "org-2", "attributes": {"name": "Other", "slug": "other"}},
        ]
        with _mock_http(200, {"data": items, "links": {}}):
            result = handler.snyk_list_orgs({})
        assert result["count"] == 2
        assert result["orgs"][0]["id"] == "org-1"
        assert result["orgs"][0]["name"] == "My Org"
        assert result["orgs"][0]["slug"] == "my-org"

    def test_empty_orgs(self):
        with _mock_http(200, {"data": [], "links": {}}):
            result = handler.snyk_list_orgs({})
        assert result["count"] == 0


class TestListProjects:
    def test_extracts_all_fields(self):
        items = [
            {
                "id": "p-1",
                "attributes": {
                    "name": "my-project",
                    "type": "npm",
                    "origin": "github",
                    "status": "active",
                },
            },
        ]
        with _mock_http(200, {"data": items, "links": {}}):
            result = handler.snyk_list_projects({"org_id": "org-1"})
        assert result["count"] == 1
        p = result["projects"][0]
        assert p["name"] == "my-project"
        assert p["type"] == "npm"
        assert p["origin"] == "github"

    def test_name_filter_case_insensitive(self):
        items = [
            {"id": "1", "attributes": {"name": "Frontend-App"}},
            {"id": "2", "attributes": {"name": "backend-api"}},
        ]
        with _mock_http(200, {"data": items, "links": {}}):
            result = handler.snyk_list_projects({"org_id": "org-1", "name_filter": "frontend"})
        assert result["count"] == 1
        assert result["projects"][0]["id"] == "1"

    def test_no_filter_returns_all(self):
        items = [
            {"id": "1", "attributes": {"name": "a"}},
            {"id": "2", "attributes": {"name": "b"}},
        ]
        with _mock_http(200, {"data": items, "links": {}}):
            result = handler.snyk_list_projects({"org_id": "org-1"})
        assert result["count"] == 2


class TestListIssues:
    def test_extracts_key_field(self):
        items = [
            {
                "id": "global-id-1",
                "attributes": {
                    "title": "XSS vuln",
                    "effective_severity_level": "high",
                    "status": "open",
                    "type": "package_vulnerability",
                    "ignored": False,
                    "key": "proj-scoped-key-1",
                },
            },
        ]
        with _mock_http(200, {"data": items, "links": {}}):
            result = handler.snyk_list_issues({"org_id": "org-1"})
        assert result["issues"][0]["id"] == "global-id-1"
        assert result["issues"][0]["key"] == "proj-scoped-key-1"

    def test_project_id_filter_sets_scan_item(self):
        with _mock_http(200, {"data": [], "links": {}}) as mock_h:
            handler.snyk_list_issues({"org_id": "org-1", "project_id": "proj-1"})
        query = mock_h.call_args[1].get("query") or mock_h.call_args[0][2]
        assert query["scan_item.id"] == "proj-1"
        assert query["scan_item.type"] == "project"

    def test_severity_fallback(self):
        items = [
            {"id": "1", "attributes": {"severity": "medium"}},
        ]
        with _mock_http(200, {"data": items, "links": {}}):
            result = handler.snyk_list_issues({"org_id": "org-1"})
        assert result["issues"][0]["severity"] == "medium"


class TestGetIssue:
    def test_returns_data_key(self):
        with _mock_http(200, {"data": {"id": "issue-1", "title": "vuln"}}):
            result = handler.snyk_get_issue({"org_id": "org-1", "issue_id": "issue-1"})
        assert result["id"] == "issue-1"


class TestListIgnores:
    def test_returns_v1_response(self):
        with _mock_http(200, {"SNYK-123": [{"reason": "fp"}]}) as mock_h:
            result = handler.snyk_list_ignores({"org_id": "org-1", "project_id": "proj-1"})
        assert "SNYK-123" in result
        assert mock_h.call_args[0][1] == "/v1/org/org-1/project/proj-1/ignores"


# ---------- Tier 5: Protocol ----------


def _unexpected_recv():
    raise AssertionError("unexpected _recv call")


class TestMainLoop:
    def test_init_stores_config(self):
        handler.config = {}
        handler._init({"config": {"api_version": "2025-01-01"}})
        assert handler.config["api_version"] == "2025-01-01"

    def test_shutdown_responds(self):
        sent = []
        with (
            mock.patch.object(handler, "_send", side_effect=sent.append),
            mock.patch.object(
                handler,
                "_recv",
                side_effect=[
                    {"id": "1", "type": "init", "config": {}},
                    {"id": "2", "type": "shutdown"},
                    _unexpected_recv,
                ],
            ),
        ):
            handler.main()
        types = [m["type"] for m in sent]
        assert "init_ok" in types
        assert "shutdown_ok" in types

    def test_unknown_tool_returns_error(self):
        sent = []
        with (
            mock.patch.object(handler, "_send", side_effect=sent.append),
            mock.patch.object(
                handler,
                "_recv",
                side_effect=[
                    {"id": "1", "type": "init", "config": {}},
                    {"id": "2", "type": "tool_call", "tool": "nonexistent", "params": {}},
                    {"id": "3", "type": "shutdown"},
                    _unexpected_recv,
                ],
            ),
        ):
            handler.main()
        error_msgs = [m for m in sent if m.get("error")]
        assert len(error_msgs) == 1
        assert error_msgs[0]["error"]["code"] == "unknown_tool"

    def test_exception_returns_handler_error(self):
        sent = []
        with (
            mock.patch.object(handler, "_send", side_effect=sent.append),
            mock.patch.object(
                handler,
                "_recv",
                side_effect=[
                    {"id": "1", "type": "init", "config": {}},
                    {"id": "2", "type": "tool_call", "tool": "snyk_list_orgs", "params": {}},
                    {"id": "3", "type": "shutdown"},
                    _unexpected_recv,
                ],
            ),
            mock.patch.object(handler, "http", side_effect=RuntimeError("boom")),
        ):
            handler.main()
        error_msgs = [m for m in sent if m.get("error")]
        assert len(error_msgs) == 1
        assert error_msgs[0]["error"]["code"] == "handler_error"
