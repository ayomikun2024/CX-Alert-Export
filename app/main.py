import os
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from pathlib import Path

from app.coralogix import (
    CORALOGIX_DOMAINS,
    validate_domain,
    fetch_alerts,
    fetch_alerts_v3,
    bulk_import_alerts,
    bulk_import_alerts_v3_grpc,
    transform_payload_for_import,
    prepare_v3_for_import,
    fetch_dest_alert_names,
    extract_source_names_for_check,
    filter_alerts_by_name_prefix,
    filter_alerts_v1v2_by_prefix,
)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Coralogix Alerts Export")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: same-origin only by default; set CORS_ORIGINS env (comma-separated) for allowed origins
_cors_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Optional API key auth: if APP_API_KEY env is set, require X-API-Key header
APP_API_KEY = os.environ.get("APP_API_KEY")


async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """If APP_API_KEY is set, require matching X-API-Key header."""
    if APP_API_KEY and x_api_key != APP_API_KEY:
        raise HTTPException(401, "Invalid or missing API key")


class ExportRequest(BaseModel):
    api_version: str = Field(default="v1/v2", description="API version: v1/v2 or v3")
    source_domain: str = Field(..., min_length=1, max_length=32, description="Source team domain (e.g. us1, eu1)")
    source_api_key: str = Field(..., min_length=1, max_length=512, description="Source team API key")
    dest_domain: str = Field(..., min_length=1, max_length=32, description="Destination team domain")
    dest_api_key: str = Field(..., min_length=1, max_length=512, description="Destination team API key")
    alert_names_prefix_filter: Optional[str] = Field(default=None, description="Only migrate alerts whose names start with this prefix (case-sensitive)")


def _domain_choices() -> list[dict[str, str]]:
    return [
        {"value": k, "label": f"{k.upper()} ({v})"}
        for k, v in CORALOGIX_DOMAINS.items()
    ]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "domains": _domain_choices(), "auth_required": bool(APP_API_KEY)},
    )


@app.post("/export")
@limiter.limit("10/minute")
async def export_alerts(
    request: Request,
    body: ExportRequest,
    _: None = Depends(verify_api_key),
):
    # Validate domains to prevent SSRF
    try:
        validate_domain(body.source_domain)
        validate_domain(body.dest_domain)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if body.api_version == "v3":
        # v3 workflow: fetch from v3 List API, strip IDs only, pass as-is to Create
        try:
            response = await fetch_alerts_v3(body.source_domain, body.source_api_key)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise HTTPException(401, "Invalid or expired source API key")
            if e.response.status_code == 403:
                raise HTTPException(
                    403,
                    "Access denied for source team. Ensure your API key has Alerts permissions and your IP is allowed.",
                )
            raise HTTPException(e.response.status_code, "Source request failed. Check your API key and permissions.")
        except Exception as ex:
            raise HTTPException(500, "An unexpected error occurred. Please try again.")

        prepared = prepare_v3_for_import(response)
        alerts_list = prepared.get("alerts") or []
        skipped = prepared.get("skipped_flow") or 0

        prefix = (body.alert_names_prefix_filter or "").strip()
        if prefix:
            alerts_list = filter_alerts_by_name_prefix(alerts_list, prefix)
            prepared = {"alerts": alerts_list, "skipped_flow": skipped}

        alerts_v3_count = len(alerts_list)
        if alerts_v3_count == 0:
            msg = f"No alerts matched the prefix '{prefix}'." if prefix else "No alerts to export. Source team has no alerts."
            return {
                "success": True,
                "message": msg,
                "count": 0,
            }
    else:
        # v1/v2 workflow: fetch from v2 API, transform to v3, then import
        try:
            response = await fetch_alerts(body.source_domain, body.source_api_key)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise HTTPException(401, "Invalid or expired source API key")
            if e.response.status_code == 403:
                try:
                    data = e.response.json()
                    msg = data.get("message", "")
                    if "limit" in str(data).lower():
                        limit = data.get("limit", "N/A")
                        raise HTTPException(403, f"Alerts limit exceeded: {limit}")
                    if msg:
                        raise HTTPException(403, msg)
                except HTTPException:
                    raise
                except Exception:
                    pass
                raise HTTPException(
                    403,
                    "Access denied for source team. Ensure your API key has Alerts permissions (Data Flow > API Keys > Alerts preset) and your IP is allowed (Account Settings > IP Access Control).",
                )
            raise HTTPException(e.response.status_code, "Source request failed. Check your API key and permissions.")
        except Exception as ex:
            raise HTTPException(500, "An unexpected error occurred. Please try again.")

        alerts = response.get("alerts") or response.get("message") or []
        count = len(alerts)

        if count == 0:
            return {
                "success": True,
                "message": "No alerts to export. Source team has no alerts.",
                "count": 0,
            }

        try:
            alerts_v3 = transform_payload_for_import(response)
        except Exception:
            raise
        skipped = count - len(alerts_v3)  # unsupported types
        prefix = (body.alert_names_prefix_filter or "").strip()
        if prefix:
            alerts_v3 = filter_alerts_v1v2_by_prefix(alerts_v3, prefix)

        if not alerts_v3:
            msg = f"No alerts matched the prefix '{prefix}'." if prefix else f"No alerts could be converted to v3 format. {count} alert(s) skipped (unsupported types)."
            return {
                "success": True,
                "message": msg,
                "count": 0,
            }

    total_to_import = len(alerts_list) if body.api_version == "v3" else len(alerts_v3)

    # Check if alerts appear to have already been exported (avoid duplicate operation)
    source_names = extract_source_names_for_check(
        body.api_version,
        response if body.api_version != "v3" else {},
        prepared if body.api_version == "v3" else None,
    )
    if source_names:
        try:
            dest_names = await fetch_dest_alert_names(body.dest_domain, body.dest_api_key, body.api_version)
            if source_names <= dest_names:
                matched = len(source_names)
                return {
                    "success": True,
                    "already_exported": True,
                    "message": f"Alerts appear to have already been exported. Destination has {matched} of {matched} alert(s) with matching names. Skipping to avoid duplicates.",
                    "count": 0,
                }
        except Exception:
            pass  # Proceed with import if dest check fails

    try:
        if body.api_version == "v3":
            bulk_resp = await bulk_import_alerts_v3_grpc(body.dest_domain, body.dest_api_key, prepared)
        else:
            bulk_resp = await bulk_import_alerts(body.dest_domain, body.dest_api_key, alerts_v3)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            raise HTTPException(401, "Invalid or expired destination API key")
        if e.response.status_code == 403:
            try:
                data = e.response.json()
                msg = data.get("message", "")
                if "alerts limit" in str(msg).lower():
                    limit = data.get("limit", "N/A")
                    raise HTTPException(403, f"Destination team alerts limit exceeded: {limit}")
                if msg:
                    raise HTTPException(403, msg)
            except HTTPException:
                raise
            except Exception:
                pass
            raise HTTPException(
                403,
                "Access denied for destination team. Ensure your API key has Alerts permissions (Data Flow > API Keys > Alerts preset) and your IP is allowed (Account Settings > IP Access Control).",
            )
        raise HTTPException(e.response.status_code, "Bulk import failed. Check your API key and permissions.")
    except Exception:
        raise HTTPException(500, "An unexpected error occurred. Please try again.")

    created = bulk_resp.get("created", 0)
    errs = bulk_resp.get("errors", [])
    msg = f"Created {created} alert(s) in destination team."
    if skipped:
        msg += f" {skipped} alert(s) skipped (unsupported type)."
    if errs:
        msg += f" {len(errs)} failed."
    return {"success": True, "message": msg, "count": created}
