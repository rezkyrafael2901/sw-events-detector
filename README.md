# 🔍 SW Events Detector

Forensic screening tool to detect real vs generated/edited `sw_events` files.

## Features

- **26 Forensic Markers** — validates against calibrated real device data ranges
- **10 Anomaly Detectors** — identifies synthetic patterns, generator fingerprints, cross-brand contamination
- **Verdict System** — REAL / SUSPICIOUS / LIKELY FAKE / DEFINITELY FAKE with confidence scoring
- **Detailed Dashboard** — device info, marker breakdown, anomaly list, top packages, event types

## Detection Methods

### Forensic Markers (26)
Validates event counts, gap distributions, package entropy, burst patterns, hour distribution, and more against calibrated ranges from real Android devices.

### Anomaly Detection (10 patterns)
1. **Midpoint Clustering** — markers suspiciously close to range midpoints
2. **MS Values = 1000** — all millisecond values used (synthetic fingerprint)
3. **Cross-Brand Contamination** — Samsung packages on a Xiaomi device
4. **Generator Weight Match** — event types match known generator weights
5. **Low Package Count** — below realistic device threshold
6. **Missing Manifest** — no metadata file
7. **Regular Timestamps** — artificially even spacing
8. **Extreme Burst Ratio** — artificial mega-burst injection
9. **Top1 Over-Dominance** — single package >50% events
10. **Known Real Device** — model matches training data

## Verdict Scoring

| Score | Verdict |
|-------|---------|
| 85-100 | ✅ Likely Authentic |
| 65-84 | ⚠️ Suspicious |
| 40-64 | 🔴 Likely Generated/Edited |
| 0-39 | 🔴 Almost Certainly Fake |

## Usage

### Web UI
Upload a `.zip` file → instant forensic analysis with visual dashboard.

### API
```
POST /api/analyze
Content-Type: multipart/form-data
Body: file (ZIP file)

Response: JSON with verdict, markers, anomalies, metrics
```

## Deploy

```bash
# Push to GitHub → connect to Vercel
vercel deploy
```

## Stack
- Python 3.11+ / FastAPI
- Tailwind CSS (CDN)
- Vercel Serverless
