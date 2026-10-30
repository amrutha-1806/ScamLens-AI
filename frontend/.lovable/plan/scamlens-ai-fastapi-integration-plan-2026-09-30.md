# SCAMLENS AI FastAPI Integration Plan

## Goal
Connect the existing SCAMLENS AI interface to the real Python service at `VITE_API_BASE_URL`, preserving every page and visual style. The frontend will never infer or fabricate analysis data and will treat submitted URLs as inert text.

## API foundation
- Expand the centralized client for health, message, URL, batch, history, and model-info endpoints under `/api`.
- Validate request and response payloads at runtime, normalize only documented casing into existing display types, and surface backend-provided error details safely.
- Add the local development URL through an example environment configuration without embedding it as a production fallback.
- Introduce shared query hooks/state so connectivity and fetched backend data remain consistent across pages.

## Connected experiences
- Update the global status from disconnected static-analysis wording to “ML analysis connected” only after a successful health check.
- Show real message and URL results, loading states, backend errors, indicators, guidance, probability, risk level, and model name.
- Load scan history from the backend, retaining search and filters over returned records.
- Derive dashboard and analytics summaries/charts only from real history responses; preserve honest empty and unavailable states when records cannot be loaded.
- Load AI & Models details from `/api/model-info`, displaying only values the backend returns while retaining the existing explanatory structure.
- Enable batch submission through `/api/analyze/batch` after a valid CSV is selected; show and export only returned results.

## Safety and validation
- Never place a submitted URL in a link, image, iframe, preview request, browser navigation, or frontend fetch target; send it only as JSON text to the configured API origin.
- Distinguish disconnected, loading, empty, malformed-response, and backend-error states without substituting demo values.
- Verify message analysis, URL non-navigation, disconnected behavior, history/data pages, batch readiness, desktop/mobile rendering, runtime logs, and the automated build signal.
