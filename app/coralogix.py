"""Coralogix Alerts API client for export and bulk import."""

import copy
import httpx
from typing import Any, Optional

try:
    import grpc
    from grpc import aio as grpc_aio
    from grpc_requests.aio import AsyncClient as GrpcAsyncClient
except ImportError:
    grpc = None  # type: ignore
    grpc_aio = None  # type: ignore
    GrpcAsyncClient = None  # type: ignore


def _metadata_interceptor(metadata: list[tuple[str, str]]):
    """Inject auth metadata into every gRPC call."""
    extra = list(metadata)

    class _UnaryUnary(grpc_aio.UnaryUnaryClientInterceptor):
        async def intercept_unary_unary(self, continuation, client_call_details, request):
            md = list(client_call_details.metadata or []) + extra
            new_details = client_call_details._replace(metadata=md)
            return await continuation(new_details, request)

    class _UnaryStream(grpc_aio.UnaryStreamClientInterceptor):
        async def intercept_unary_stream(self, continuation, client_call_details, request):
            md = list(client_call_details.metadata or []) + extra
            new_details = client_call_details._replace(metadata=md)
            return await continuation(new_details, request)

    class _StreamUnary(grpc_aio.StreamUnaryClientInterceptor):
        async def intercept_stream_unary(self, continuation, client_call_details, request_iterator):
            md = list(client_call_details.metadata or []) + extra
            new_details = client_call_details._replace(metadata=md)
            return await continuation(new_details, request_iterator)

    class _StreamStream(grpc_aio.StreamStreamClientInterceptor):
        async def intercept_stream_stream(self, continuation, client_call_details, request_iterator):
            md = list(client_call_details.metadata or []) + extra
            new_details = client_call_details._replace(metadata=md)
            return await continuation(new_details, request_iterator)

    return [_UnaryUnary(), _UnaryStream(), _StreamUnary(), _StreamStream()]

CORALOGIX_DOMAINS = {
    "us1": "api.us1.coralogix.com",
    "us2": "api.us2.coralogix.com",
    "eu1": "api.eu1.coralogix.com",
    "eu2": "api.eu2.coralogix.com",
    "ap1": "api.ap1.coralogix.com",
    "ap2": "api.ap2.coralogix.com",
    "ap3": "api.ap3.coralogix.com",
}

# gRPC hosts for v3 Alerts API (ng-api-grpc.<domain>:443)
CORALOGIX_GRPC_HOSTS = {
    "us1": "ng-api-grpc.us1.coralogix.com:443",
    "us2": "ng-api-grpc.us2.coralogix.com:443",
    "eu1": "ng-api-grpc.eu1.coralogix.com:443",
    "eu2": "ng-api-grpc.eu2.coralogix.com:443",
    "ap1": "ng-api-grpc.ap1.coralogix.com:443",
    "ap2": "ng-api-grpc.ap2.coralogix.com:443",
    "ap3": "ng-api-grpc.ap3.coralogix.com:443",
}


def validate_domain(domain: str) -> str:
    """Validate domain is an allowed Coralogix region. Returns normalized domain or raises ValueError."""
    domain_lower = domain.lower().strip()
    if domain_lower not in CORALOGIX_DOMAINS:
        raise ValueError(
            f"Invalid domain: {domain!r}. Must be one of: {', '.join(CORALOGIX_DOMAINS.keys())}"
        )
    return domain_lower


def _get_base_url(domain: str) -> str:
    """Resolve domain key to full API base URL. Domain must be pre-validated."""
    domain_lower = validate_domain(domain)
    return f"https://{CORALOGIX_DOMAINS[domain_lower]}"


def _get_grpc_host(domain: str) -> str:
    """Resolve domain key to gRPC host for v3 Alerts API. Domain must be pre-validated."""
    domain_lower = validate_domain(domain)
    return CORALOGIX_GRPC_HOSTS[domain_lower]


V2_TO_V3_TIMEFRAME = {
    "5MIN": "LOGS_TIME_WINDOW_VALUE_MINUTES_5_OR_UNSPECIFIED",
    "10MIN": "LOGS_TIME_WINDOW_VALUE_MINUTES_10",
    "15MIN": "LOGS_TIME_WINDOW_VALUE_MINUTES_15",
    "20MIN": "LOGS_TIME_WINDOW_VALUE_MINUTES_20",
    "30MIN": "LOGS_TIME_WINDOW_VALUE_MINUTES_30",
    "1H": "LOGS_TIME_WINDOW_VALUE_HOUR_1",
    "2H": "LOGS_TIME_WINDOW_VALUE_HOURS_2",
    "3H": "LOGS_TIME_WINDOW_VALUE_HOURS_4",
    "4H": "LOGS_TIME_WINDOW_VALUE_HOURS_4",
    "6H": "LOGS_TIME_WINDOW_VALUE_HOURS_6",
    "12H": "LOGS_TIME_WINDOW_VALUE_HOURS_12",
    "24H": "LOGS_TIME_WINDOW_VALUE_HOURS_24",
}

V2_TO_METRIC_TIME_WINDOW = {
    "5MIN": "METRIC_TIME_WINDOW_VALUE_MINUTES_10",  # 5MIN enum may not exist, use 10
    "10MIN": "METRIC_TIME_WINDOW_VALUE_MINUTES_10",
    "15MIN": "METRIC_TIME_WINDOW_VALUE_MINUTES_15",
    "20MIN": "METRIC_TIME_WINDOW_VALUE_MINUTES_20",
    "30MIN": "METRIC_TIME_WINDOW_VALUE_MINUTES_30",
    "1H": "METRIC_TIME_WINDOW_VALUE_HOUR_1",
    "2H": "METRIC_TIME_WINDOW_VALUE_HOURS_2",
    "3H": "METRIC_TIME_WINDOW_VALUE_HOURS_4",  # 3H may map to 4H if no 3H enum
    "4H": "METRIC_TIME_WINDOW_VALUE_HOURS_4",
    "6H": "METRIC_TIME_WINDOW_VALUE_HOURS_6",
    "12H": "METRIC_TIME_WINDOW_VALUE_HOURS_12",
    "24H": "METRIC_TIME_WINDOW_VALUE_HOURS_24",
}

V2_CONDITION_TYPE_TO_METRIC = {
    "more_than": "METRIC_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED",
    "less_than": "METRIC_THRESHOLD_CONDITION_TYPE_LESS_THAN",
    "more_than_or_equals": "METRIC_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_EQUALS",
    "less_than_or_equals": "METRIC_THRESHOLD_CONDITION_TYPE_LESS_THAN_OR_EQUALS",
}

SEVERITY_TO_PRIORITY = {
    "critical": "ALERT_DEF_PRIORITY_P1",
    "warning": "ALERT_DEF_PRIORITY_P2",
    "info": "ALERT_DEF_PRIORITY_P3",
}


def _v2_log_filter_to_label_filters(log_filter: dict[str, Any]) -> dict[str, Any]:
    """Map v2 log_filter to v3 labelFilters. v3 expects empty {} or specific format - use empty to avoid API errors."""
    return {}


def _v2_to_v3_alert(v2: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Convert v2 alert to v3 alertDefProperties format. Returns None for unsupported types."""
    v2 = copy.deepcopy(v2)
    for k in ("id", "unique_identifier", "created_at", "lastTriggered", "expiration"):
        v2.pop(k, None)

    name = v2.get("name") or "Imported Alert"
    description = v2.get("description") or ""
    enabled = v2.get("is_active", True)
    severity = (v2.get("severity") or "info").lower()
    priority = SEVERITY_TO_PRIORITY.get(severity, "ALERT_DEF_PRIORITY_P3")

    log_filter = v2.get("log_filter") or {}
    condition = v2.get("condition") or {}
    filter_type = (log_filter.get("filter_type") or "text").lower()

    # Alert group-by keys (notification groupByKeys must be a subset)
    alert_group_by_keys = []
    for k in (condition.get("group_by"), condition.get("group_by_lvl2")):
        if k and k not in alert_group_by_keys:
            alert_group_by_keys.append(k)

    notification_group = {
        "groupByKeys": [],
        "webhooks": [],
        "destinations": [],
    }
    # API rejects groupByKeys for logs threshold, metric, etc.; keep empty to avoid "unknown field" errors

    # Preserve source labels from GET response (try common field names)
    entity_labels = {}
    for key in ("labels", "entity_labels", "entityLabels", "tags", "meta_labels"):
        val = v2.get(key)
        if isinstance(val, dict):
            entity_labels.update({str(k): str(v) for k, v in val.items() if v is not None})
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and ":" in item:
                    k, _, v = item.partition(":")
                    entity_labels[k.strip()] = v.strip()
                elif isinstance(item, dict) and "key" in item and "value" in item:
                    entity_labels[str(item["key"])] = str(item["value"])

    # Preserve notify_every from source (retriggering interval in seconds)
    notify_minutes = 10
    if v2.get("notify_every") is not None:
        try:
            notify_minutes = max(1, int(v2["notify_every"]) // 60)  # seconds -> minutes
        except (TypeError, ValueError):
            pass

    base = {
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "incidentsSettings": {"minutes": notify_minutes},
        "notificationGroup": notification_group,
        "entityLabels": entity_labels,
        "phantomMode": False,
        "deleted": False,
    }

    if filter_type == "text" and condition.get("condition_type") in ("more_than", "less_than"):
        text = log_filter.get("text") or "*"
        timeframe = (condition.get("timeframe") or "10MIN").upper()
        tw = V2_TO_V3_TIMEFRAME.get(timeframe, "LOGS_TIME_WINDOW_VALUE_MINUTES_10")
        threshold = condition.get("threshold") or 1
        cond_type = condition.get("condition_type")
        # v3 uses LOGS_THRESHOLD_CONDITION_TYPE_MORE_THAN or LESS_THAN
        logs_cond_type = "LOGS_THRESHOLD_CONDITION_TYPE_LESS_THAN" if cond_type == "less_than" else "LOGS_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED"
        base["type"] = "ALERT_DEF_TYPE_LOGS_THRESHOLD"
        logs_threshold = {
            "logsFilter": {
                "simpleFilter": {"luceneQuery": text, "labelFilters": _v2_log_filter_to_label_filters(log_filter)},
            },
            "rules": [
                {
                    "condition": {
                        "threshold": threshold,
                        "conditionType": logs_cond_type,
                        "timeWindow": {"logsTimeWindowSpecificValue": tw},
                    },
                    "override": {"priority": priority},
                }
            ],
        }
        # Omit groupByKeys from logsThreshold - API rejects "unknown field groupByKeys" for some types
        base["logsThreshold"] = logs_threshold
        return base

    if filter_type == "text" and condition.get("condition_type") in (None, "immediate"):
        text = log_filter.get("text") or "*"
        base["type"] = "ALERT_DEF_TYPE_LOGS_IMMEDIATE_OR_UNSPECIFIED"
        base["logsImmediate"] = {
            "logsFilter": {
                "simpleFilter": {"luceneQuery": text, "labelFilters": _v2_log_filter_to_label_filters(log_filter)},
            },
        }
        return base

    if filter_type == "metric":
        promql = condition.get("promql_text") or ""
        if promql:
            timeframe = (condition.get("timeframe") or "10MIN").upper()
            tw_enum = V2_TO_METRIC_TIME_WINDOW.get(timeframe, "METRIC_TIME_WINDOW_VALUE_MINUTES_10")
            cond_type = condition.get("condition_type") or "more_than"
            metric_cond_type = V2_CONDITION_TYPE_TO_METRIC.get(
                cond_type, "METRIC_THRESHOLD_CONDITION_TYPE_MORE_THAN_OR_UNSPECIFIED"
            )
            base["type"] = "ALERT_DEF_TYPE_METRIC_THRESHOLD"
            base["incidentsSettings"] = {"notify_on": "NOTIFY_ON_TRIGGERED_AND_RESOLVED", "minutes": notify_minutes}
            # Metric API doesn't support groupByKeys in payload; clear notification groupByKeys to avoid "not a subset" error
            if alert_group_by_keys:
                base["notificationGroup"]["groupByKeys"] = []
            metric_threshold = {
                "metric_filter": {"promql": promql},
                "missing_values": {"replace_with_zero": condition.get("swap_null_values", False)},
                "rules": [
                    {
                        "condition": {
                            "condition_type": metric_cond_type,
                            "of_the_last": {
                                "metric_time_window_specific_value": tw_enum,
                            },
                            "threshold": condition.get("threshold") or 1,
                        },
                        "override": {"priority": priority},
                    }
                ],
            }
            # Note: metric_threshold does not support groupByKeys; omit to avoid API error
            base["metric_threshold"] = metric_threshold
            return base

    return None


def transform_payload_for_import(response: dict) -> list[dict[str, Any]]:
    """Transform v2 GET response to v3 alertDefProperties format for create."""
    alerts = response.get("alerts") or response.get("message") or []
    result = []
    for a in alerts:
        v3 = _v2_to_v3_alert(a)
        if v3:
            result.append({"alertDefProperties": v3})
    return result


async def fetch_alerts(domain: str, api_key: str) -> dict:
    """
    Fetch all alerts from a Coralogix team.
    GET https://api.<domain>/api/v2/external/alerts
    """
    base_url = _get_base_url(domain)
    url = f"{base_url}/api/v2/external/alerts/"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()


async def fetch_alerts_v3(domain: str, api_key: str) -> dict:
    """
    Fetch all alerts from a Coralogix team using v3 gRPC ListAlertDefs.
    Uses ng-api-grpc.<domain>:443 with grpc-requests (reflection).
    """
    if GrpcAsyncClient is None:
        raise RuntimeError(
            "grpc-requests is required for v3 API. Install with: pip install grpc-requests"
        )
    host = _get_grpc_host(domain)
    metadata = [("authorization", f"Bearer {api_key}")]
    # Register only AlertDefsService - grpc-requests create() registers ALL services and fails
    # on Coralogix (e.g. ApdexService descriptor not found). Register our service only.
    interceptors = _metadata_interceptor(metadata)
    try:
        client = GrpcAsyncClient(host, ssl=True, interceptors=interceptors, lazy=True)
        await client.register_service("com.coralogixapis.alerts.v3.AlertDefsService")
        client.has_server_registered = True
    except Exception:
        raise
    # Step 1: ListAlertDefs - get alert IDs (List may return summaries, not full defs)
    all_ids = []
    page_token = None
    service = "com.coralogixapis.alerts.v3.AlertDefsService"
    while True:
        req = {"pagination": {"pageToken": page_token, "pageSize": 100}} if page_token else {}
        try:
            data = await client.request(service, "ListAlertDefs", req)
        except Exception:
            raise
        items = data.get("alertDefs") or data.get("alert_defs") or []
        for item in items:
            # id can be at top level or inside alertDef
            aid = item.get("id") or (item.get("alertDef") or item.get("alert_def") or {}).get("id")
            if aid:
                all_ids.append(aid)
        pag = data.get("pagination") or {}
        page_token = pag.get("nextPageToken") or pag.get("next_page_token")
        if not page_token:
            break
    # Step 2: GetAlertDef for each ID to fetch full definition (per Coralogix docs)
    all_alert_defs = []
    for i, aid in enumerate(all_ids):
        try:
            full_def = await client.request(service, "GetAlertDef", {"id": aid})
            # GetAlertDef returns alertDef; use it or the whole response
            ad = full_def.get("alertDef") or full_def.get("alert_def") or full_def
            all_alert_defs.append(ad)
        except Exception:
            # Skip this alert but continue
            pass
    return {"alertDefs": all_alert_defs}


def _extract_alert_names_v2(response: dict) -> set[str]:
    """Extract alert names from v2 API response."""
    alerts = response.get("alerts") or response.get("message") or []
    return {str(a.get("name", "")).strip() for a in alerts if isinstance(a, dict) and a.get("name")}


def _extract_alert_names_v3(response: dict) -> set[str]:
    """Extract alert names from v3 API response (alertDefs with alertDefProperties)."""
    alert_defs = response.get("alertDefs") or response.get("alert_defs") or []
    names = set()
    for ad in alert_defs:
        props = ad.get("alertDefProperties") or ad.get("alert_def_properties") or ad
        if isinstance(props, dict) and props.get("name"):
            names.add(str(props.get("name", "")).strip())
    return names


async def fetch_dest_alert_names(domain: str, api_key: str, api_version: str) -> set[str]:
    """Fetch destination alert names for duplicate check. Returns set of names."""
    if api_version == "v3":
        try:
            response = await fetch_alerts_v3(domain, api_key)
            return _extract_alert_names_v3(response)
        except Exception:
            return set()
    else:
        try:
            response = await fetch_alerts(domain, api_key)
            return _extract_alert_names_v2(response)
        except Exception:
            return set()


def filter_alerts_by_name_prefix(
    alerts_list: list[tuple[str, Any]], prefix: str
) -> list[tuple[str, Any]]:
    """Filter v3 alerts to those whose name starts with prefix (case-sensitive)."""
    if not prefix:
        return alerts_list
    result = []
    for source_id, item in alerts_list:
        props = item.get("alert_def_properties") or {}
        name = (props.get("name") or "").strip()
        if name.startswith(prefix):
            result.append((source_id, item))
    return result


def filter_alerts_v1v2_by_prefix(alerts_v3: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    """Filter v1/v2 transformed alerts by name prefix (case-sensitive)."""
    if not prefix:
        return alerts_v3
    return [
        a for a in alerts_v3
        if ((a.get("alertDefProperties") or a.get("alert_def_properties") or {}).get("name") or "").strip().startswith(prefix)
    ]


def extract_source_names_for_check(api_version: str, response: dict, prepared: Optional[dict] = None) -> set[str]:
    """Extract source alert names for duplicate check."""
    if api_version == "v3" and prepared:
        names = set()
        for _, item in prepared.get("alerts") or []:
            props = item.get("alert_def_properties", {})
            if isinstance(props, dict) and props.get("name"):
                names.add(str(props.get("name", "")).strip())
        return names
    return _extract_alert_names_v2(response)


_ID_KEYS = frozenset({
    "id", "alertVersionId", "unique_identifier", "created_at", "createdTime",
    "updatedTime", "lastTriggeredTime", "lastTriggered", "expiration",
})


def _has_integration_ref(w: dict) -> bool:
    """True if webhook references a team-specific integration."""
    if "integrationId" in w or "integration_id" in w:
        return True
    integ = w.get("integration")
    if isinstance(integ, dict) and ("integrationId" in integ or "integration_id" in integ):
        return True
    return False


def _clear_team_specific_notifications(obj: Any) -> Any:
    """
    Remove webhooks/destinations that reference integrations (team-specific).
    Keeping them causes "Integration id X not found" or "integrationType Required".
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("webhooks", "webhook") and isinstance(v, list):
                filtered = [
                    _clear_team_specific_notifications(w)
                    for w in v
                    if isinstance(w, dict) and not _has_integration_ref(w)
                ]
                out[k] = filtered
            elif k in ("destinations",) and isinstance(v, list):
                out[k] = []
            else:
                out[k] = _clear_team_specific_notifications(v)
        return out
    if isinstance(obj, list):
        return [_clear_team_specific_notifications(x) for x in obj]
    return obj


def _strip_ids_recursive(obj: Any) -> Any:
    """Recursively remove ID-like keys from dicts. Returns copy."""
    if isinstance(obj, dict):
        return {
            k: _strip_ids_recursive(v)
            for k, v in obj.items()
            if k not in _ID_KEYS
        }
    if isinstance(obj, list):
        return [_strip_ids_recursive(item) for item in obj]
    return obj


def prepare_v3_for_import(response: dict) -> dict[str, Any]:
    """
    Prepare v3 List response for import. Skips flow alerts (not supported).
    Returns {alerts: [(source_id, payload), ...], skipped_flow: int}.
    """
    alert_defs = response.get("alertDefs") or response.get("alert_defs") or []
    alerts = []
    skipped_flow = 0
    for alert_def in alert_defs:
        source_id = alert_def.get("id") or ""
        props = alert_def.get("alertDefProperties") or alert_def.get("alert_def_properties")
        if not props:
            continue
        td = props.get("typeDefinition") or props.get("type_definition") or {}
        if td.get("$case") == "flow":
            skipped_flow += 1
            continue  # Skip flow alerts - not supported
        cleared = _clear_team_specific_notifications(copy.deepcopy(props))
        stripped = _strip_ids_recursive(cleared)
        alerts.append((source_id, {"alert_def_properties": stripped}))
    return {"alerts": alerts, "skipped_flow": skipped_flow}


async def bulk_import_alerts(domain: str, api_key: str, alerts_v3: list[dict[str, Any]]) -> dict:
    """
    Import alerts into a Coralogix team using v3 HTTP Create API.
    Used for v1/v2 workflow (transformed payloads with alertDefProperties).
    POST https://api.<domain>/mgmt/openapi/latest/alerts/alerts-general/v3 per alert.
    """
    base_url = _get_base_url(domain)
    url = f"{base_url}/mgmt/openapi/latest/alerts/alerts-general/v3"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    created = 0
    errors = []
    async with httpx.AsyncClient(timeout=60.0) as client:
        for i, item in enumerate(alerts_v3):
            try:
                resp = await client.post(url, json=item, headers=headers)
                if resp.status_code in (200, 201):
                    created += 1
                else:
                    name = item.get("alertDefProperties", {}).get("name") or item.get("alert_def_properties", {}).get("name")
                    errors.append({"index": i, "name": name, "status": resp.status_code, "body": resp.text[:200]})
            except Exception as e:
                name = item.get("alertDefProperties", {}).get("name") or item.get("alert_def_properties", {}).get("name")
                errors.append({"index": i, "name": name, "error": str(e)})
    return {"created": created, "total": len(alerts_v3), "errors": errors}


async def bulk_import_alerts_v3_grpc(
    domain: str, api_key: str, prepared: dict[str, Any]
) -> dict:
    """
    Import alerts via v3 gRPC CreateAlertDef.
    prepared: {alerts: [(source_id, payload), ...]}
    """
    if GrpcAsyncClient is None:
        raise RuntimeError(
            "grpc-requests is required for v3 API. Install with: pip install grpc-requests"
        )
    host = _get_grpc_host(domain)
    metadata = [("authorization", f"Bearer {api_key}")]
    interceptors = _metadata_interceptor(metadata)
    client = GrpcAsyncClient(host, ssl=True, interceptors=interceptors, lazy=True)
    await client.register_service("com.coralogixapis.alerts.v3.AlertDefsService")
    client.has_server_registered = True
    service = "com.coralogixapis.alerts.v3.AlertDefsService"
    method = "CreateAlertDef"

    alerts = prepared.get("alerts") or []
    created = 0
    errors = []

    for i, (source_id, item) in enumerate(alerts):
        try:
            await client.request(service, method, item)
            created += 1
        except Exception as e:
            name = item.get("alert_def_properties", {}).get("name", "")
            errors.append({"index": i, "name": name, "error": str(e)})

    return {"created": created, "total": len(alerts), "errors": errors}
