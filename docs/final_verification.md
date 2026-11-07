# Final Verification — Autonomous Cyber Defence with Digital Twin

## 1. Backend API Smoke Tests

Date: 2026-10-23

Result: PASS — 9 of 9 endpoints returned HTTP 200.

- GET /api/health
- GET /api/dashboard/summary
- GET /api/dashboard/detections?limit=5
- GET /api/dashboard/defences?limit=5
- GET /api/monitoring/summary
- GET /api/monitoring/flows?limit=5
- GET /api/investigations
- GET /api/twin/validations
- GET /api/traceback/192.168.64.2

Health endpoint confirmed:
- Status: ok
- Service: Smart Cyber Defence API
- Firewall execution: disabled_by_dry_run_design

## 2. AI Detection and Defence Integration

Three sampled dataset records were submitted to the local inference API.

| Reference label | Prediction | Defence decision | Result |
|---|---|---|---|
| DDOS | DDOS | BLOCK_IP | PASS |
| PORT_SCAN | PORT_SCAN | BLOCK_IP | PASS |
| BRUTE_FORCE | BRUTE_FORCE | BLOCK_IP | PASS |

Each sampled prediction returned confidence 1.0.
Each defence decision remained in DRY_RUN mode.
No firewall commands were executed.

These are three sample-level tests, not a measurement of full-dataset
accuracy or a demonstration of real-world blocking.

## 3. Frontend Production Build

Command: npm run build
Tool: Vite 8.3.4
Result: PASS
Build time: 176 ms
JavaScript bundle: approximately 232.14 kB (72.32 kB gzip)

## 4. Digital Twin Evidence Previously Recorded

- Mininet connectivity test: PASS, 2 of 2 pings.
- Bounded HTTP availability test: 10 of 10 requests succeeded.
- A prior normal-traffic test captured 108 TCP packets, aggregated 9 flows,
  and submitted 5 flows to the AI inference API.

The HTTP availability test was not a DDoS simulation. The normal-traffic
test did not demonstrate detection of a live attack.

## 5. Safety and Limitations

- Firewall execution remains disabled; defence actions are dry-run decisions.
- Public geolocation, ISP, and reputation lookup for private IP addresses
  cannot establish a public attacker origin.
- AIORI output must not be treated as confirmed attacker identity.
- The three sampled attack records do not establish overall model accuracy.
- Continuous live monitoring and live attack-response behaviour require
  separate end-to-end verification.
- MongoDB persistence should only be described as verified if separately
  tested against the configured database.

## 6. Final Status

Backend API smoke tests: PASS (9/9).
Sampled AI detection and defence integration: PASS (3/3).
Frontend production build: PASS.

The verified checks above passed. This document does not claim that every
planned feature or every production deployment scenario has been tested.
