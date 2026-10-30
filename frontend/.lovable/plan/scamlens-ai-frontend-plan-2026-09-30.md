# SCAMLENS AI Frontend Plan

## Goal
Build the complete professional frontend structure for SCAMLENS AI as a dark cybersecurity analysis application. All analysis surfaces will clearly remain disconnected or demo-only until the future Python/FastAPI service is available; no predictions, confidence values, or model performance values will be fabricated.

## Application shell and visual system
- Create a responsive desktop-first shell with a collapsible sidebar, mobile navigation, top status area, and all nine requested destinations.
- Define a charcoal/navy semantic color system with blue actions and safe, suspicious, high-risk, and critical states.
- Use compact rounded panels, restrained borders and shadows, accessible contrast, subtle motion, and data-dense spacing.
- Add reusable buttons, page headers, status badges, KPI panels, risk meters, charts, tables, loading placeholders, error notices, and empty states.

## Pages
- **Dashboard:** KPI placeholders marked as awaiting data, chart-ready risk and class panels, recent activity empty state, quick actions, and project overview.
- **Message Analyzer:** validated message input, four examples, analyze/clear controls, API-unavailable messaging, and a complete no-result analysis panel without fabricated output.
- **URL Analyzer:** validated URL entry and a static-analysis feature checklist; submitted URLs are never opened by the browser.
- **Batch CSV Scanner:** CSV validation, file metadata, local preview and record count, scan controls, result summary/table scaffolding, filters, search, and disabled download until results exist.
- **Analytics:** chart-ready scan trends, risk distribution, class comparison, and message/URL panels using honest empty states rather than invented numbers.
- **AI & Models:** UCI dataset details, feature engineering, model comparison list, Random Forest selection, evaluation explanation, confusion-matrix empty state, and prediction pipeline.
- **Scan History:** searchable/filterable table structure with all requested columns and a clear no-history state.
- **Reports:** scan selector, report preview structure, generate/download actions, and no-selection state.
- **About Project:** objective, problem statement, dataset, ML approach, technologies, limitations, and future enhancements.

## Data and integration structure
- Define shared TypeScript contracts for scan requests, results, URL indicators, history, reports, analytics, and API errors.
- Add one environment-driven API client using `VITE_API_BASE_URL`, with validated request boundaries and no fallback prediction engine.
- Keep fixture content limited to explicitly labeled input examples and UI previews; never present sample content as a completed scan.
- Keep application state client-side and non-persistent in this phase; history and analytics wait for the backend.

## Validation
- Verify every navigation destination and key interactive state on desktop and mobile.
- Verify CSV preview, input validation, clear/example actions, disabled result actions, URL non-navigation behavior, and accessible empty/loading/error states.
- Confirm all pages have unique metadata, the preview has no runtime errors, and the application compiles successfully.
