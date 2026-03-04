# Coralogix Alerts Export

A web application that exports all alerts from a source Coralogix team and imports them into a destination team.

## Supported APIs

- **Alert v1/v2** – Export from legacy REST APIs (`GET /api/v2/external/alerts`) and import via v3
- **API v3** – Export and import using the Alerts API v3 (gRPC ListAlertDefs / CreateAlertDef)

See the [Alerts API v1/v2 docs](https://coralogix.com/docs/developer-portal/apis/data-management/alerts-api/alerts-api-v1-v2/#export-all-alerts-to-a-new-coralogix-team) and [Alerts API v3](https://coralogix.com/docs/developer-portal/apis/data-management/alerts-api/alerts-grpc-api/) for details.

## Setup

### Prerequisites

- Python 3.10+

### Installation

```bash
git clone https://github.com/ayomikun2024/CX-Alert-Export.git
cd CX-Alert-Export
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run

```bash
uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

If you get `Address already in use`, either stop the existing process or use another port:

```bash
# Use port 8001 instead
uvicorn app.main:app --reload --port 8001
```

## Usage

1. **API Version**: Choose **Alerts API v1/v2** (legacy) or **Alerts API v3**.
2. **Source Team**: Select the region/domain and enter the API key for the team you want to export alerts from.
3. **Destination Team**: Select the region/domain and enter the API key for the team you want to import alerts into.
4. Click **Export Alerts**.

**Alert v1/v2 mode:**
1. Fetches alerts from the source via `GET /api/v2/external/alerts`
2. Transforms the payload to v3 format (strip IDs and integration IDs)
3. Imports into the destination via API v3 (`POST /mgmt/openapi/latest/alerts/alerts-general/v3`)

**API v3 mode:**
1. Fetches alerts from the source via gRPC `ListAlertDefs`
2. Strips IDs and integration references
3. Imports into the destination via gRPC `CreateAlertDef`

## API Key Permissions

Create API keys in **Data Flow > API Keys** for both source and destination teams. Use the **Alerts** permission preset, which includes:

- `ALERTS:READCONFIG` (source: read alerts)
- `ALERTS:UPDATECONFIG` (destination: create alerts)
- `LOGS.ALERTS:READCONFIG` / `LOGS.ALERTS:UPDATECONFIG`
- `SPANS.ALERTS:READCONFIG` / `SPANS.ALERTS:UPDATECONFIG`
- `METRICS.ALERTS:READCONFIG` / `METRICS.ALERTS:UPDATECONFIG`
- And other alert-related permissions

If you get "Access denied" (403), verify the API key has the Alerts preset and that your IP is allowed under **Account Settings > IP Access Control**.

## Supported Regions

| Region | API Domain |
|--------|------------|
| US1 | api.us1.coralogix.com |
| US2 | api.us2.coralogix.com |
| EU1 | api.eu1.coralogix.com |
| EU2 | api.eu2.coralogix.com |
| AP1 | api.ap1.coralogix.com |
| AP2 | api.ap2.coralogix.com |
| AP3 | api.ap3.coralogix.com |

## Notes

- **Integration IDs** are stripped before import because they reference integrations in the source team. Reconfigure notification channels (Slack, email, etc.) in the destination team after import.
- **Empty source**: If the source has no alerts, the operation completes successfully with a count of 0.
- **Alerts limit**: If the destination team hits its alerts limit (typically 500), you'll see a 403 error with the limit value.
- **Security**: API keys are sent only in the request body and are not logged or persisted. Run behind HTTPS in production.
