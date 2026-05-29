"""
SW Events Detector — Forensic screening tool to detect real vs fake/generated sw_events files.
Analyzes 26 forensic markers + anomaly patterns to determine authenticity.
"""

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List as TList
import json, zipfile, io, math, hashlib, re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional

# ──────────────────────────────────────────────
# FORENSIC MARKER RANGES (from real device calibration)
# ──────────────────────────────────────────────
MARKERS = {
    "total_events": {"min": 22000, "max": 104000, "label": "Total Events", "weight": 3},
    "unique_packages": {"min": 100, "max": 600, "label": "Unique Packages", "weight": 4},
    "unique_classes": {"min": 50, "max": 500, "label": "Unique Classes", "weight": 3},
    "screen_pct": {"min": 0.5, "max": 10.0, "label": "SCREEN Events %", "weight": 2},
    "gap_zero_pct": {"min": 1.0, "max": 50.0, "label": "Gap=0 (Concurrent) %", "weight": 5},
    "gap_sub10ms_pct": {"min": 3.0, "max": 55.0, "label": "Gap<10ms %", "weight": 3},
    "gap_10ms_1s_pct": {"min": 25.0, "max": 55.0, "label": "Gap 10ms-1s %", "weight": 4},
    "gap_1s_10s_pct": {"min": 10.0, "max": 55.0, "label": "Gap 1s-10s %", "weight": 3},
    "gap_10s_60s_pct": {"min": 1.0, "max": 20.0, "label": "Gap 10s-60s %", "weight": 2},
    "gap_1m_10m_pct": {"min": 0.5, "max": 10.0, "label": "Gap 1-10min %", "weight": 2},
    "gap_gt10m_pct": {"min": 0.01, "max": 5.0, "label": "Gap>10min %", "weight": 2},
    "hour_entropy": {"min": 3.0, "max": 5.0, "label": "Hour Entropy", "weight": 4},
    "events_per_day_cv": {"min": 0.1, "max": 2.0, "label": "Events/Day CV", "weight": 3},
    "avg_burst_seq": {"min": 3.0, "max": 25.0, "label": "Avg Burst Sequence", "weight": 3},
    "max_burst_seq": {"min": 100, "max": 800, "label": "Max Burst Sequence", "weight": 4},
    "top5_pkg_pct": {"min": 30.0, "max": 85.0, "label": "Top5 Package %", "weight": 5},
    "top20_pkg_pct": {"min": 45.0, "max": 95.0, "label": "Top20 Package %", "weight": 3},
    "ms_unique": {"min": 900, "max": 1000, "label": "MS Unique Values", "weight": 6},
    "idle_gt1hr_pct": {"min": 0.0, "max": 1.0, "label": "Idle>1hr %", "weight": 2},
    "gap_p50": {"min": 0.005, "max": 2.0, "label": "Gap p50 (sec)", "weight": 3},
    "gap_p90": {"min": 2.0, "max": 80.0, "label": "Gap p90 (sec)", "weight": 3},
    "gap_p99": {"min": 100.0, "max": 900.0, "label": "Gap p99 (sec)", "weight": 3},
    "standby_bucket_pct": {"min": 3.0, "max": 55.0, "label": "STANDBY_BUCKET %", "weight": 5},
    "notification_pct": {"min": 5.0, "max": 30.0, "label": "NOTIFICATION %", "weight": 5},
    "activity_pct": {"min": 20.0, "max": 50.0, "label": "ACTIVITY_PAUSED+RESUMED %", "weight": 4},
    "pkg_entropy": {"min": 3.0, "max": 7.0, "label": "Package Entropy", "weight": 4},
}

# Known real device models (from training data)
REAL_DEVICES = {
    "realme RMX3263", "Realme RMX1821", "OPPO CPH2059", "TECNO TECNO LI7",
    "Xiaomi 23053RN02A", "realme RMX5388", "samsung SM-A105G",
    "Xiaomi M2010J19SG", "vivo V2322", "Xiaomi M2007J20CG",
    "samsung SM-A325F", "samsung SM-A256B", "samsung SM-A546E",
    "OPPO CPH2565", "vivo V2305", "realme RMX3771",
}

# Brand-specific system packages (to detect cross-brand contamination)
BRAND_SYSTEM = {
    "samsung": {"com.sec.android.app.launcher", "com.samsung.android.incallui", "com.samsung.android.messaging"},
    "xiaomi": {"com.miui.home", "com.miui.securitycenter", "com.miui.gallery"},
    "oppo": {"com.oppo.launcher", "com.coloros.gamespace", "com.heytap.cloud"},
    "realme": {"com.oppo.launcher", "com.coloros.gamespace", "com.heytap.cloud"},
    "vivo": {"com.vivo.launcher", "com.vivo.weather", "com.vivo.gallery"},
    "infinix": {"com.transsion.hilauncher", "com.transsion.XOS.gallery3d"},
    "tecno": {"com.transsion.hilauncher", "com.transsion.XOS.gallery3d"},
    "advan": {"com.advan.launcher", "com.advan.gallery"},
    "asus": {"com.asus.launcher", "com.asus.camera"},
    "google": {"com.google.android.apps.nexuslauncher", "com.google.android.dialer"},
    "oneplus": {"com.oneplus.launcher", "com.oneplus.camera"},
    "motorola": {"com.motorola.launcher3", "com.motorola.camera"},
    "poco": {"com.mi.launcher", "com.miui.securitycenter"},
}


def parse_zip(data: bytes) -> Tuple[List[dict], dict, str]:
    """Parse ZIP file, return (events, manifest, error)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        return [], {}, f"Invalid ZIP: {e}"

    names = zf.namelist()
    events_file = None
    manifest_file = None
    for n in names:
        if n.endswith("events.ndjson") or n.endswith("events.jsonl"):
            events_file = n
        if n.endswith("manifest.json"):
            manifest_file = n

    if not events_file:
        # Try to find any .ndjson or .jsonl file
        for n in names:
            if n.endswith(".ndjson") or n.endswith(".jsonl"):
                events_file = n
                break
    if not events_file:
        return [], {}, "No events file found in ZIP"

    # Parse events
    events = []
    try:
        content = zf.read(events_file).decode("utf-8", errors="replace")
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except Exception as e:
        return [], {}, f"Error reading events: {e}"

    # Parse manifest
    manifest = {}
    if manifest_file:
        try:
            manifest = json.loads(zf.read(manifest_file))
        except Exception:
            pass

    return events, manifest, ""


def calc_entropy(counter: Counter, total: int) -> float:
    """Shannon entropy."""
    if total == 0:
        return 0.0
    ent = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return ent


def analyze_events(events: List[dict], manifest: dict) -> Dict:
    """Run full forensic analysis on events."""
    if not events:
        return {"error": "No events to analyze"}

    n = len(events)
    result = {"event_count": n}

    # ── Basic counts ──
    packages = [e.get("package", "") for e in events]
    types = [e.get("type", "") for e in events]
    classes = [e.get("class", "") for e in events if e.get("class")]

    pkg_counter = Counter(packages)
    type_counter = Counter(types)
    class_counter = Counter(classes)

    result["unique_packages"] = len(pkg_counter)
    result["unique_classes"] = len(class_counter)

    # ── Timestamps & Gaps ──
    timestamps = []
    for e in events:
        ts = e.get("ts", 0)
        if isinstance(ts, (int, float)):
            timestamps.append(ts)
    timestamps.sort()

    if len(timestamps) > 1:
        gaps = [(timestamps[i+1] - timestamps[i]) / 1000.0 for i in range(len(timestamps)-1)]
        gaps = [g for g in gaps if g >= 0]  # filter negative

        if gaps:
            gap_zero = sum(1 for g in gaps if g == 0)
            gap_sub10ms = sum(1 for g in gaps if 0 < g < 0.01)
            gap_10ms_1s = sum(1 for g in gaps if 0.01 <= g < 1)
            gap_1s_10s = sum(1 for g in gaps if 1 <= g < 10)
            gap_10s_60s = sum(1 for g in gaps if 10 <= g < 60)
            gap_1m_10m = sum(1 for g in gaps if 60 <= g < 600)
            gap_gt10m = sum(1 for g in gaps if g >= 600)
            total_gaps = len(gaps)

            result["gap_zero_pct"] = gap_zero / total_gaps * 100
            result["gap_sub10ms_pct"] = gap_sub10ms / total_gaps * 100
            result["gap_10ms_1s_pct"] = gap_10ms_1s / total_gaps * 100
            result["gap_1s_10s_pct"] = gap_1s_10s / total_gaps * 100
            result["gap_10s_60s_pct"] = gap_10s_60s / total_gaps * 100
            result["gap_1m_10m_pct"] = gap_1m_10m / total_gaps * 100
            result["gap_gt10m_pct"] = gap_gt10m / total_gaps * 100

            # Gap percentiles
            sorted_gaps = sorted(gaps)
            result["gap_p50"] = sorted_gaps[len(sorted_gaps)//2]
            result["gap_p90"] = sorted_gaps[int(len(sorted_gaps)*0.9)]
            result["gap_p99"] = sorted_gaps[int(len(sorted_gaps)*0.99)]

            # Idle > 1hr
            result["idle_gt1hr_pct"] = sum(1 for g in gaps if g > 3600) / total_gaps * 100

    # ── Hour distribution & entropy ──
    hours = []
    for ts in timestamps:
        # Convert ms to hour (assume UTC+7 for Indonesia)
        import datetime
        dt = datetime.datetime.fromtimestamp(ts/1000, tz=datetime.timezone(datetime.timedelta(hours=7)))
        hours.append(dt.hour)

    hour_counter = Counter(hours)
    result["hour_entropy"] = calc_entropy(hour_counter, len(hours))

    # ── Events per day ──
    if timestamps:
        days = defaultdict(int)
        for ts in timestamps:
            import datetime
            dt = datetime.datetime.fromtimestamp(ts/1000, tz=datetime.timezone(datetime.timedelta(hours=7)))
            day_key = dt.strftime("%Y-%m-%d")
            days[day_key] += 1

        if len(days) > 1:
            day_counts = list(days.values())
            mean_day = sum(day_counts) / len(day_counts)
            if mean_day > 0:
                std_day = (sum((x - mean_day)**2 for x in day_counts) / len(day_counts)) ** 0.5
                result["events_per_day_cv"] = std_day / mean_day

    # ── Burst analysis ──
    if gaps:
        burst_seqs = []
        current_burst = 1
        for g in gaps:
            if g < 0.1:  # < 100ms gap = burst
                current_burst += 1
            else:
                if current_burst > 1:
                    burst_seqs.append(current_burst)
                current_burst = 1
        if current_burst > 1:
            burst_seqs.append(current_burst)

        if burst_seqs:
            result["avg_burst_seq"] = sum(burst_seqs) / len(burst_seqs)
            result["max_burst_seq"] = max(burst_seqs)
        else:
            result["avg_burst_seq"] = 0
            result["max_burst_seq"] = 0

    # ── Package concentration ──
    sorted_pkgs = pkg_counter.most_common()
    if sorted_pkgs:
        top5 = sum(c for _, c in sorted_pkgs[:5])
        top20 = sum(c for _, c in sorted_pkgs[:20])
        result["top5_pkg_pct"] = top5 / n * 100
        result["top20_pkg_pct"] = top20 / n * 100

    # ── MS unique values ──
    ms_values = set()
    for ts in timestamps:
        ms_values.add(ts % 1000)
    result["ms_unique"] = len(ms_values)

    # ── Package entropy ──
    result["pkg_entropy"] = calc_entropy(pkg_counter, n)

    # ── Screen events ──
    screen_events = sum(1 for t in types if "SCREEN" in str(t).upper())
    result["screen_pct"] = screen_events / n * 100

    # ── STANDBY_BUCKET ──
    standby_events = sum(1 for t in types if "STANDBY_BUCKET" in str(t).upper())
    result["standby_bucket_pct"] = standby_events / n * 100

    # ── NOTIFICATION ──
    notif_events = sum(1 for t in types if "NOTIFICATION" in str(t).upper())
    result["notification_pct"] = notif_events / n * 100

    # ── ACTIVITY_PAUSED + ACTIVITY_RESUMED ──
    activity_events = sum(1 for t in types if "ACTIVITY_PAUSED" in str(t).upper() or "ACTIVITY_RESUMED" in str(t).upper())
    result["activity_pct"] = activity_events / n * 100

    # ── Manifest info ──
    result["manifest"] = manifest
    result["device_model"] = manifest.get("device_model", "Unknown")
    result["android_version"] = manifest.get("android_version", "Unknown")
    result["window_start"] = manifest.get("window_start", "")
    result["window_end"] = manifest.get("window_end", "")

    # ── Top packages ──
    result["top_packages"] = pkg_counter.most_common(10)

    # ── Event type distribution ──
    result["event_types"] = type_counter.most_common(15)

    return result


def run_forensic_checks(metrics: Dict) -> List[Dict]:
    """Run 26 forensic marker checks."""
    checks = []
    for key, spec in MARKERS.items():
        val = metrics.get(key)
        if val is None:
            checks.append({
                "marker": key,
                "label": spec["label"],
                "status": "skip",
                "value": None,
                "range": f"{spec['min']}-{spec['max']}",
                "weight": spec["weight"],
                "message": "No data"
            })
            continue

        in_range = spec["min"] <= val <= spec["max"]
        checks.append({
            "marker": key,
            "label": spec["label"],
            "status": "pass" if in_range else "fail",
            "value": round(val, 3) if isinstance(val, float) else val,
            "range": f"{spec['min']}-{spec['max']}",
            "weight": spec["weight"],
            "message": "In range" if in_range else "OUT OF RANGE"
        })

    return checks


def run_anomaly_detection(metrics: Dict, events: List[dict]) -> List[Dict]:
    """Detect patterns that indicate generated/edited data."""
    anomalies = []
    n = len(events)

    # ── Anomaly 1: Too many markers exactly at midpoint (synthetic pattern) ──
    midpoint_count = 0
    for key, spec in MARKERS.items():
        val = metrics.get(key)
        if val is None:
            continue
        mid = (spec["min"] + spec["max"]) / 2
        spread = (spec["max"] - spec["min"]) * 0.15  # 15% of range
        if abs(val - mid) < spread:
            midpoint_count += 1

    if midpoint_count > 18:  # More than 70% at midpoint = suspicious
        anomalies.append({
            "id": "midpoint_cluster",
            "severity": "high",
            "label": "Markers Clustered at Midpoint",
            "detail": f"{midpoint_count}/26 markers are within 15% of their midpoint range. Real devices show more variance.",
            "score_penalty": 15
        })
    elif midpoint_count > 14:
        anomalies.append({
            "id": "midpoint_cluster",
            "severity": "medium",
            "label": "Markers Slightly Clustered",
            "detail": f"{midpoint_count}/26 markers are near midpoint. Mild synthetic signature.",
            "score_penalty": 5
        })

    # ── Anomaly 2: MS unique values exactly 1000 ──
    ms_unique = metrics.get("ms_unique", 0)
    if ms_unique == 1000:
        anomalies.append({
            "id": "ms_exact_1000",
            "severity": "high",
            "label": "Millisecond Values: Exactly 1000",
            "detail": "All 1000 possible millisecond values are used. Real devices typically miss a few (998-1000). Strong synthetic indicator.",
            "score_penalty": 20
        })
    elif ms_unique >= 999:
        anomalies.append({
            "id": "ms_near_1000",
            "severity": "low",
            "label": "Millisecond Values: Near Perfect",
            "detail": f"{ms_unique}/1000 ms values used. Acceptable but slightly suspicious.",
            "score_penalty": 3
        })

    # ── Anomaly 3: Known real device model in generated file ──
    device = metrics.get("device_model", "")
    if device in REAL_DEVICES:
        anomalies.append({
            "id": "known_real_device",
            "severity": "info",
            "label": "Known Real Device Model",
            "detail": f"Device '{device}' matches a known real device from training data. This could be genuine or a targeted fake.",
            "score_penalty": 0
        })

    # ── Anomaly 4: Cross-brand package contamination ──
    packages = set(e.get("package", "") for e in events)
    device_lower = device.lower()
    detected_brand = None
    for brand in BRAND_SYSTEM:
        if brand in device_lower:
            detected_brand = brand
            break

    if detected_brand:
        other_brands = []
        for brand, sys_pkgs in BRAND_SYSTEM.items():
            if brand == detected_brand:
                continue
            overlap = packages & sys_pkgs
            if len(overlap) >= 2:
                other_brands.append((brand, overlap))

        if other_brands:
            for brand, overlap in other_brands:
                anomalies.append({
                    "id": f"cross_brand_{brand}",
                    "severity": "high",
                    "label": f"Cross-Brand Contamination ({brand})",
                    "detail": f"Detected {len(overlap)} {brand}-specific packages on a {detected_brand} device: {', '.join(list(overlap)[:3])}",
                    "score_penalty": 25
                })

    # ── Anomaly 5: Event type weights too close to generator defaults ──
    type_counter = Counter(e.get("type", "") for e in events)
    # Known generator weights
    gen_weights = {
        "ACTIVITY_RESUMED": 14, "ACTIVITY_PAUSED": 13, "EVENT_23": 14,
        "NOTIFICATION_INTERRUPTION": 17, "STANDBY_BUCKET_CHANGED": 17,
    }
    type_match_count = 0
    for etype, expected_pct in gen_weights.items():
        actual_pct = type_counter.get(etype, 0) / n * 100 if n > 0 else 0
        if abs(actual_pct - expected_pct) < 2:  # Within 2% of generator weight
            type_match_count += 1

    if type_match_count >= 4:
        anomalies.append({
            "id": "generator_weights",
            "severity": "high",
            "label": "Event Type Weights Match Generator",
            "detail": f"{type_match_count}/5 key event types are within 2% of known generator weights. Strong synthetic indicator.",
            "score_penalty": 20
        })
    elif type_match_count >= 3:
        anomalies.append({
            "id": "generator_weights_partial",
            "severity": "medium",
            "label": "Event Type Weights Partially Match Generator",
            "detail": f"{type_match_count}/5 key event types match generator weights. Mildly suspicious.",
            "score_penalty": 8
        })

    # ── Anomaly 6: Package count too low ──
    pkg_count = metrics.get("unique_packages", 0)
    if pkg_count < 100:
        anomalies.append({
            "id": "low_pkg_count",
            "severity": "high",
            "label": "Suspiciously Low Package Count",
            "detail": f"Only {pkg_count} unique packages. Real devices typically have 200+. Likely truncated or incomplete data.",
            "score_penalty": 15
        })

    # ── Anomaly 7: No manifest ──
    manifest = metrics.get("manifest", {})
    if not manifest or not manifest.get("device_model"):
        anomalies.append({
            "id": "no_manifest",
            "severity": "medium",
            "label": "Missing or Empty Manifest",
            "detail": "No manifest.json found or device_model is empty. Real exports always have a manifest.",
            "score_penalty": 10
        })

    # ── Anomaly 8: Timestamps too regular (evenly spaced) ──
    timestamps = sorted([e.get("ts", 0) for e in events if isinstance(e.get("ts"), (int, float))])
    if len(timestamps) > 100:
        # Check for artificial patterns in first 100 gaps
        sample_gaps = [(timestamps[i+1] - timestamps[i]) for i in range(min(100, len(timestamps)-1))]
        if sample_gaps:
            gap_counter = Counter(sample_gaps)
            most_common_gap_count = gap_counter.most_common(1)[0][1]
            if most_common_gap_count > 30:  # Same gap repeated >30 times in 100 samples
                anomalies.append({
                    "id": "regular_gaps",
                    "severity": "high",
                    "label": "Artificially Regular Timestamps",
                    "detail": f"A single gap value repeats {most_common_gap_count}/100 times in sample. Real devices have more natural variance.",
                    "score_penalty": 20
                })

    # ── Anomaly 9: Burst sequence too uniform ──
    avg_burst = metrics.get("avg_burst_seq", 0)
    max_burst = metrics.get("max_burst_seq", 0)
    if avg_burst > 0 and max_burst > 0:
        ratio = max_burst / avg_burst
        if ratio > 100:  # Extreme max vs avg = artificial mega-burst injection
            anomalies.append({
                "id": "extreme_burst_ratio",
                "severity": "medium",
                "label": "Extreme Burst Ratio",
                "detail": f"Max burst ({max_burst}) is {ratio:.0f}x the average ({avg_burst:.1f}). Suggests artificial burst injection.",
                "score_penalty": 10
            })

    # ── Anomaly 10: Top1 package dominates too much ──
    top_packages = metrics.get("top_packages", [])
    if top_packages:
        top1_pct = top_packages[0][1] / n * 100 if n > 0 else 0
        if top1_pct > 50:
            anomalies.append({
                "id": "top1_dominance",
                "severity": "medium",
                "label": "Single Package Over-Dominance",
                "detail": f"Top package '{top_packages[0][0]}' has {top1_pct:.1f}% of events. Real devices rarely exceed 40%.",
                "score_penalty": 8
            })

    return anomalies


def calculate_verdict(checks: List[Dict], anomalies: List[Dict]) -> Dict:
    """Calculate final verdict based on checks and anomalies."""
    # Base score from forensic markers
    total_weight = sum(c["weight"] for c in checks if c["status"] != "skip")
    passed_weight = sum(c["weight"] for c in checks if c["status"] == "pass")
    base_score = (passed_weight / total_weight * 100) if total_weight > 0 else 0

    # Anomaly penalties
    total_penalty = sum(a["score_penalty"] for a in anomalies)
    final_score = max(0, base_score - total_penalty)

    # Verdict
    if final_score >= 85:
        verdict = "REAL"
        verdict_label = "✅ Likely Authentic"
        verdict_color = "#22c55e"
        verdict_detail = "File shows strong indicators of being a genuine device export. All major forensic markers are within expected ranges with natural variance patterns."
    elif final_score >= 65:
        verdict = "SUSPICIOUS"
        verdict_label = "⚠️ Suspicious"
        verdict_color = "#f59e0b"
        verdict_detail = "File has some anomalies that could indicate editing or generation. Not definitively fake, but warrants further investigation."
    elif final_score >= 40:
        verdict = "LIKELY_FAKE"
        verdict_label = "🔴 Likely Generated/Edited"
        verdict_color = "#ef4444"
        verdict_detail = "Multiple strong indicators of synthetic or heavily edited data. File is unlikely to be a genuine device export."
    else:
        verdict = "DEFINITELY_FAKE"
        verdict_label = "🔴 Almost Certainly Fake"
        verdict_color = "#dc2626"
        verdict_detail = "Overwhelming evidence of synthetic generation or heavy manipulation. This is NOT a genuine device export."

    # Confidence level
    high_anomalies = sum(1 for a in anomalies if a["severity"] == "high")
    if high_anomalies >= 3:
        confidence = "Very High"
    elif high_anomalies >= 2:
        confidence = "High"
    elif high_anomalies >= 1:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "score": round(final_score, 1),
        "base_score": round(base_score, 1),
        "total_penalty": total_penalty,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "verdict_color": verdict_color,
        "verdict_detail": verdict_detail,
        "confidence": confidence,
        "markers_passed": sum(1 for c in checks if c["status"] == "pass"),
        "markers_failed": sum(1 for c in checks if c["status"] == "fail"),
        "markers_total": sum(1 for c in checks if c["status"] != "skip"),
        "anomaly_count": len(anomalies),
        "high_anomalies": high_anomalies,
    }


app = FastAPI(title="SW Events Detector")


# Embedded HTML (updated via re-embed script)
INDEX_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>🔍 SW Events Detector</title>\n<script src="https://cdn.tailwindcss.com"></script>\n<style>\n  * { box-sizing: border-box; }\n  body { background: #0a0a0f; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, monospace; }\n  .glass { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); backdrop-filter: blur(12px); }\n  .glass:hover { border-color: rgba(255,255,255,0.12); }\n  .upload-zone { border: 2px dashed rgba(255,255,255,0.15); transition: all 0.3s; }\n  .upload-zone.dragover { border-color: #f97316; background: rgba(249,115,22,0.05); }\n  .upload-zone:hover { border-color: rgba(255,255,255,0.3); }\n  .verdict-badge { font-size: 1.5rem; font-weight: 800; letter-spacing: -0.02em; }\n  .marker-pass { color: #22c55e; }\n  .marker-fail { color: #ef4444; }\n  .marker-skip { color: #6b7280; }\n  .anomaly-high { border-left: 3px solid #ef4444; }\n  .anomaly-medium { border-left: 3px solid #f59e0b; }\n  .anomaly-low { border-left: 3px solid #3b82f6; }\n  .anomaly-info { border-left: 3px solid #6b7280; }\n  .score-ring { width: 160px; height: 160px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; font-weight: 800; }\n  .score-ring.real { background: conic-gradient(#22c55e var(--pct), rgba(255,255,255,0.05) 0); }\n  .score-ring.suspicious { background: conic-gradient(#f59e0b var(--pct), rgba(255,255,255,0.05) 0); }\n  .score-ring.fake { background: conic-gradient(#ef4444 var(--pct), rgba(255,255,255,0.05) 0); }\n  .score-inner { width: 130px; height: 130px; border-radius: 50%; background: #0a0a0f; display: flex; flex-direction: column; align-items: center; justify-content: center; }\n  .bar { height: 6px; border-radius: 3px; background: rgba(255,255,255,0.05); overflow: hidden; }\n  .bar-fill { height: 100%; border-radius: 3px; transition: width 0.6s ease; }\n  .bar-fill.pass { background: #22c55e; }\n  .bar-fill.fail { background: #ef4444; }\n  .fade-in { animation: fadeIn 0.5s ease; }\n  @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }\n  .spinner { width: 40px; height: 40px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #f97316; border-radius: 50%; animation: spin 0.8s linear infinite; }\n  @keyframes spin { to { transform: rotate(360deg); } }\n  .mode-btn { transition: all 0.2s; }\n  .mode-btn.active { background: #f97316; color: white; }\n  .file-pill { display: inline-flex; align-items: center; gap: 6px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); border-radius: 9999px; padding: 4px 12px; font-size: 12px; }\n  .file-pill .remove { cursor: pointer; color: #ef4444; font-weight: bold; }\n  .file-pill .remove:hover { color: #f87171; }\n  .batch-row { cursor: pointer; transition: background 0.15s; }\n  .batch-row:hover { background: rgba(255,255,255,0.04); }\n  .batch-detail { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }\n  .batch-detail.open { max-height: 2000px; }\n  .verdict-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }\n  .verdict-dot.real { background: #22c55e; }\n  .verdict-dot.suspicious { background: #f59e0b; }\n  .verdict-dot.likely_fake, .verdict-dot.definitely_fake { background: #ef4444; }\n  .summary-card { min-width: 120px; }\n  .hidden { display: none; }\n</style>\n</head>\n<body class="min-h-screen">\n\n<header class="glass mx-auto max-w-5xl mt-6 rounded-2xl p-6">\n  <div class="flex items-center gap-3 mb-2">\n    <span class="text-3xl">🔍</span>\n    <h1 class="text-2xl font-bold bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">SW Events Detector</h1>\n  </div>\n  <p class="text-gray-400 text-sm">Forensic screening — detect real vs generated/edited sw_events files. 26 markers + 10 anomaly detectors.</p>\n</header>\n\n<main class="max-w-5xl mx-auto mt-6 px-4">\n\n  <!-- Mode Switcher -->\n  <div class="flex items-center gap-2 mb-4">\n    <button id="mode-single" class="mode-btn active px-4 py-2 rounded-lg text-sm font-semibold" onclick="setMode(\'single\')">📄 Single File</button>\n    <button id="mode-batch" class="mode-btn px-4 py-2 rounded-lg text-sm font-semibold glass" onclick="setMode(\'batch\')">📁 Batch Upload</button>\n  </div>\n\n  <!-- Upload Zone -->\n  <div id="upload-zone" class="upload-zone rounded-2xl p-12 text-center cursor-pointer glass">\n    <div id="upload-icon" class="text-5xl mb-4">📁</div>\n    <p class="text-lg font-semibold mb-2" id="upload-text">Drop sw_events ZIP file here</p>\n    <p class="text-gray-500 text-sm" id="upload-sub">or click to browse — accepts .zip files</p>\n    <input type="file" id="file-input" accept=".zip" class="hidden">\n    <!-- File pills (batch mode) -->\n    <div id="file-pills" class="hidden mt-4 flex flex-wrap gap-2 justify-center"></div>\n    <!-- Batch analyze button -->\n    <button id="batch-btn" class="hidden mt-4 px-6 py-3 rounded-xl bg-orange-600 hover:bg-orange-700 text-white font-semibold transition">\n      🔍 Analyze All (<span id="batch-count">0</span> files)\n    </button>\n  </div>\n\n  <!-- Loading -->\n  <div id="loading" class="hidden text-center py-16">\n    <div class="spinner mx-auto mb-4"></div>\n    <p class="text-gray-400" id="loading-text">Analyzing forensic markers...</p>\n  </div>\n\n  <!-- ===== SINGLE RESULTS ===== -->\n  <div id="single-results" class="hidden fade-in mt-6 space-y-4">\n    <!-- Verdict Card -->\n    <div class="glass rounded-2xl p-6">\n      <div class="flex flex-col md:flex-row items-center gap-6">\n        <div id="score-ring" class="score-ring real" style="--pct: 0%">\n          <div class="score-inner">\n            <span id="score-num" class="text-3xl font-bold">0</span>\n            <span class="text-xs text-gray-400">/100</span>\n          </div>\n        </div>\n        <div class="flex-1 text-center md:text-left">\n          <div id="verdict-label" class="verdict-badge mb-2">—</div>\n          <p id="verdict-detail" class="text-gray-400 text-sm leading-relaxed"></p>\n          <div class="flex flex-wrap gap-4 mt-4 text-sm">\n            <div><span class="text-gray-500">Markers:</span> <span id="markers-passed" class="font-bold text-green-400">0</span>/<span id="markers-total">0</span></div>\n            <div><span class="text-gray-500">Anomalies:</span> <span id="anomaly-count" class="font-bold text-red-400">0</span></div>\n            <div><span class="text-gray-500">Score:</span> <span id="base-score" class="font-bold">0</span> - <span id="total-penalty" class="font-bold text-red-400">0</span></div>\n          </div>\n        </div>\n      </div>\n    </div>\n    <!-- Device Info -->\n    <div class="glass rounded-2xl p-6">\n      <h2 class="text-lg font-bold mb-4 flex items-center gap-2">📱 Device Info</h2>\n      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">\n        <div><span class="text-gray-500 block">Model</span><span id="dev-model" class="font-mono">—</span></div>\n        <div><span class="text-gray-500 block">Android</span><span id="dev-android" class="font-mono">—</span></div>\n        <div><span class="text-gray-500 block">Events</span><span id="dev-events" class="font-mono">—</span></div>\n        <div><span class="text-gray-500 block">Size</span><span id="dev-size" class="font-mono">—</span></div>\n        <div><span class="text-gray-500 block">Window</span><span id="dev-window" class="font-mono text-xs">—</span></div>\n        <div><span class="text-gray-500 block">SHA256</span><span id="dev-sha" class="font-mono text-xs break-all">—</span></div>\n      </div>\n    </div>\n    <!-- Anomalies -->\n    <div id="anomalies-section" class="glass rounded-2xl p-6 hidden">\n      <h2 class="text-lg font-bold mb-4 flex items-center gap-2">🚨 Anomalies Detected</h2>\n      <div id="anomalies-list" class="space-y-3"></div>\n    </div>\n    <!-- Forensic Markers -->\n    <div class="glass rounded-2xl p-6">\n      <div class="flex items-center justify-between mb-4">\n        <h2 class="text-lg font-bold flex items-center gap-2">🔬 Forensic Markers</h2>\n        <div class="flex gap-2">\n          <button onclick="filterMarkers(\'all\')" class="text-xs px-3 py-1 rounded-full glass hover:bg-white/10 active-filter" data-filter="all">All</button>\n          <button onclick="filterMarkers(\'pass\')" class="text-xs px-3 py-1 rounded-full glass hover:bg-white/10" data-filter="pass">✅ Pass</button>\n          <button onclick="filterMarkers(\'fail\')" class="text-xs px-3 py-1 rounded-full glass hover:bg-white/10" data-filter="fail">❌ Fail</button>\n        </div>\n      </div>\n      <div id="markers-list" class="space-y-2"></div>\n    </div>\n    <!-- Top Packages -->\n    <div class="glass rounded-2xl p-6">\n      <h2 class="text-lg font-bold mb-4 flex items-center gap-2">📦 Top 10 Packages</h2>\n      <div id="top-pkg-chart" class="space-y-2"></div>\n    </div>\n    <!-- Event Types -->\n    <div class="glass rounded-2xl p-6">\n      <h2 class="text-lg font-bold mb-4 flex items-center gap-2">📊 Event Types</h2>\n      <div id="event-types-chart" class="space-y-2"></div>\n    </div>\n    <!-- Back -->\n    <div class="text-center py-6">\n      <button onclick="resetUI()" class="px-6 py-3 rounded-xl bg-orange-600 hover:bg-orange-700 text-white font-semibold transition">🔍 Analyze Another</button>\n    </div>\n  </div>\n\n  <!-- ===== BATCH RESULTS ===== -->\n  <div id="batch-results" class="hidden fade-in mt-6 space-y-4">\n    <!-- Summary Cards -->\n    <div class="glass rounded-2xl p-6">\n      <h2 class="text-lg font-bold mb-4">📊 Batch Summary</h2>\n      <div id="summary-cards" class="flex flex-wrap gap-3"></div>\n    </div>\n    <!-- File List -->\n    <div class="glass rounded-2xl p-6">\n      <h2 class="text-lg font-bold mb-4">📋 Files (<span id="batch-total">0</span>)</h2>\n      <div id="batch-list" class="space-y-2"></div>\n    </div>\n    <!-- Back -->\n    <div class="text-center py-6">\n      <button onclick="resetUI()" class="px-6 py-3 rounded-xl bg-orange-600 hover:bg-orange-700 text-white font-semibold transition">🔍 Analyze More Files</button>\n    </div>\n  </div>\n\n</main>\n\n<footer class="text-center text-gray-600 text-xs py-8">SW Events Detector — Forensic Screening Tool</footer>\n\n<script>\nlet allChecks = [];\nlet currentMode = \'single\';\nlet selectedFiles = [];\n\nconst dropZone = document.getElementById(\'upload-zone\');\nconst fileInput = document.getElementById(\'file-input\');\nconst loading = document.getElementById(\'loading\');\nconst singleResults = document.getElementById(\'single-results\');\nconst batchResults = document.getElementById(\'batch-results\');\nconst batchBtn = document.getElementById(\'batch-btn\');\nconst filePills = document.getElementById(\'file-pills\');\n\nfunction setMode(mode) {\n  currentMode = mode;\n  document.getElementById(\'mode-single\').classList.toggle(\'active\', mode === \'single\');\n  document.getElementById(\'mode-batch\').classList.toggle(\'active\', mode === \'batch\');\n  document.getElementById(\'mode-single\').classList.toggle(\'glass\', mode !== \'single\');\n  document.getElementById(\'mode-batch\').classList.toggle(\'glass\', mode !== \'batch\');\n  fileInput.multiple = mode === \'batch\';\n  selectedFiles = [];\n  filePills.innerHTML = \'\';\n  filePills.classList.add(\'hidden\');\n  batchBtn.classList.add(\'hidden\');\n  document.getElementById(\'upload-text\').textContent = mode === \'single\' ? \'Drop sw_events ZIP file here\' : \'Drop multiple sw_events ZIP files here\';\n  document.getElementById(\'upload-sub\').textContent = mode === \'single\' ? \'or click to browse — accepts .zip files\' : \'or click to browse — select multiple .zip files\';\n  document.getElementById(\'upload-icon\').textContent = mode === \'single\' ? \'📁\' : \'📂\';\n}\n\n// Drag & Drop\ndropZone.addEventListener(\'click\', (e) => { if (e.target === dropZone || e.target.closest(\'#upload-icon\') || e.target.closest(\'#upload-text\') || e.target.closest(\'#upload-sub\')) fileInput.click(); });\ndropZone.addEventListener(\'dragover\', e => { e.preventDefault(); dropZone.classList.add(\'dragover\'); });\ndropZone.addEventListener(\'dragleave\', () => dropZone.classList.remove(\'dragover\'));\ndropZone.addEventListener(\'drop\', e => {\n  e.preventDefault();\n  dropZone.classList.remove(\'dragover\');\n  const files = [...e.dataTransfer.files].filter(f => f.name.endsWith(\'.zip\'));\n  if (files.length === 0) { alert(\'Please upload .zip files\'); return; }\n  if (currentMode === \'single\') handleFile(files[0]);\n  else handleBatchFiles(files);\n});\nfileInput.addEventListener(\'change\', () => {\n  const files = [...fileInput.files];\n  if (files.length === 0) return;\n  if (currentMode === \'single\') handleFile(files[0]);\n  else handleBatchFiles(files);\n});\n\nfunction handleFile(file) {\n  uploadSingle(file);\n}\n\nfunction handleBatchFiles(files) {\n  selectedFiles = files;\n  filePills.classList.remove(\'hidden\');\n  filePills.innerHTML = \'\';\n  files.forEach((f, i) => {\n    filePills.innerHTML += `<span class="file-pill">${f.name} <span class="remove" onclick="removeFile(${i})">✕</span></span>`;\n  });\n  batchBtn.classList.remove(\'hidden\');\n  document.getElementById(\'batch-count\').textContent = files.length;\n}\n\nfunction removeFile(idx) {\n  selectedFiles.splice(idx, 1);\n  if (selectedFiles.length === 0) {\n    filePills.classList.add(\'hidden\');\n    batchBtn.classList.add(\'hidden\');\n  } else {\n    handleBatchFiles(selectedFiles);\n  }\n}\n\nbatchBtn.addEventListener(\'click\', (e) => {\n  e.stopPropagation();\n  if (selectedFiles.length > 0) uploadBatch(selectedFiles);\n});\n\nasync function uploadSingle(file) {\n  dropZone.classList.add(\'hidden\');\n  loading.classList.remove(\'hidden\');\n  singleResults.classList.add(\'hidden\');\n  batchResults.classList.add(\'hidden\');\n\n  const form = new FormData();\n  form.append(\'file\', file);\n  try {\n    const res = await fetch(\'/api/analyze\', { method: \'POST\', body: form });\n    const data = await res.json();\n    if (data.error) { alert(\'Error: \' + data.error); resetUI(); return; }\n    renderSingleResults(data);\n  } catch (err) { alert(\'Network error: \' + err.message); resetUI(); }\n}\n\nasync function uploadBatch(files) {\n  dropZone.classList.add(\'hidden\');\n  loading.classList.remove(\'hidden\');\n  singleResults.classList.add(\'hidden\');\n  batchResults.classList.add(\'hidden\');\n  document.getElementById(\'loading-text\').textContent = `Analyzing ${files.length} files...`;\n\n  const form = new FormData();\n  files.forEach(f => form.append(\'files\', f));\n  try {\n    const res = await fetch(\'/api/batch\', { method: \'POST\', body: form });\n    const data = await res.json();\n    if (data.error) { alert(\'Error: \' + data.error); resetUI(); return; }\n    renderBatchResults(data);\n  } catch (err) { alert(\'Network error: \' + err.message); resetUI(); }\n}\n\n// ── Single Results ──\nfunction renderSingleResults(data) {\n  loading.classList.add(\'hidden\');\n  singleResults.classList.remove(\'hidden\');\n\n  const v = data.verdict;\n  const ring = document.getElementById(\'score-ring\');\n  ring.className = \'score-ring \' + (v.verdict === \'REAL\' ? \'real\' : v.verdict === \'SUSPICIOUS\' ? \'suspicious\' : \'fake\');\n  ring.style.setProperty(\'--pct\', v.score + \'%\');\n  document.getElementById(\'score-num\').textContent = Math.round(v.score);\n  document.getElementById(\'verdict-label\').textContent = v.verdict_label;\n  document.getElementById(\'verdict-label\').style.color = v.verdict_color;\n  document.getElementById(\'verdict-detail\').textContent = v.verdict_detail;\n  document.getElementById(\'markers-passed\').textContent = v.markers_passed;\n  document.getElementById(\'markers-total\').textContent = v.markers_total;\n  document.getElementById(\'anomaly-count\').textContent = v.anomaly_count;\n  document.getElementById(\'base-score\').textContent = v.base_score;\n  document.getElementById(\'total-penalty\').textContent = \'-\' + v.total_penalty;\n\n  document.getElementById(\'dev-model\').textContent = data.device.model;\n  document.getElementById(\'dev-android\').textContent = data.device.android;\n  document.getElementById(\'dev-events\').textContent = data.metrics.event_count?.toLocaleString() || \'—\';\n  document.getElementById(\'dev-size\').textContent = data.file_info.size_kb + \' KB\';\n  document.getElementById(\'dev-window\').textContent = data.device.window_start && data.device.window_end\n    ? data.device.window_start.slice(0,10) + \' → \' + data.device.window_end.slice(0,10) : \'—\';\n  document.getElementById(\'dev-sha\').textContent = data.file_info.sha256?.slice(0,16) + \'...\' || \'—\';\n\n  // Anomalies\n  const anomSection = document.getElementById(\'anomalies-section\');\n  const anomList = document.getElementById(\'anomalies-list\');\n  anomList.innerHTML = \'\';\n  if (data.anomalies.length > 0) {\n    anomSection.classList.remove(\'hidden\');\n    data.anomalies.forEach(a => {\n      const icons = { high: \'🔴\', medium: \'🟡\', low: \'🔵\', info: \'ℹ️\' };\n      anomList.innerHTML += `<div class="glass rounded-lg p-4 anomaly-${a.severity}"><div class="flex items-center gap-2 mb-1"><span>${icons[a.severity]||\'❓\'}</span><span class="font-semibold text-sm">${a.label}</span><span class="text-xs text-gray-500 ml-auto">-${a.score_penalty} pts</span></div><p class="text-gray-400 text-xs">${a.detail}</p></div>`;\n    });\n  } else { anomSection.classList.add(\'hidden\'); }\n\n  allChecks = data.checks;\n  renderMarkers(\'all\');\n\n  // Charts\n  renderBarChart(\'top-pkg-chart\', data.top_packages, data.metrics.event_count);\n  renderBarChart(\'event-types-chart\', data.event_types, data.metrics.event_count);\n}\n\nfunction renderBarChart(containerId, items, total) {\n  const el = document.getElementById(containerId);\n  el.innerHTML = \'\';\n  const maxVal = items.length > 0 ? items[0][1] : 1;\n  items.forEach(([name, count]) => {\n    const pct = (count / total * 100).toFixed(1);\n    const barW = (count / maxVal * 100).toFixed(0);\n    el.innerHTML += `<div class="flex items-center gap-3 text-xs"><span class="w-48 truncate text-gray-300 font-mono text-right">${name}</span><div class="flex-1 bar"><div class="bar-fill pass" style="width:${barW}%"></div></div><span class="w-16 text-gray-400 text-right">${pct}%</span></div>`;\n  });\n}\n\nfunction renderMarkers(filter) {\n  const list = document.getElementById(\'markers-list\');\n  list.innerHTML = \'\';\n  const checks = filter === \'all\' ? allChecks : allChecks.filter(c => c.status === filter);\n  checks.forEach(c => {\n    const icon = c.status === \'pass\' ? \'✅\' : c.status === \'fail\' ? \'❌\' : \'⏭️\';\n    const barW = c.value !== null ? Math.min(100, Math.max(5, (c.value / parseFloat(c.range.split(\'-\')[1]) * 100))) : 0;\n    list.innerHTML += `<div class="flex items-center gap-3 text-xs py-1.5"><span class="w-6 text-center">${icon}</span><span class="w-44 text-gray-300 text-right">${c.label}</span><div class="flex-1 bar"><div class="bar-fill ${c.status === \'pass\' ? \'pass\' : \'fail\'}" style="width:${barW}%"></div></div><span class="w-20 text-right font-mono marker-${c.status}">${c.value !== null ? c.value : \'—\'}</span><span class="w-28 text-gray-500 text-right text-[10px]">[${c.range}]</span></div>`;\n  });\n  document.querySelectorAll(\'[data-filter]\').forEach(btn => {\n    btn.classList.toggle(\'active-filter\', btn.dataset.filter === filter);\n    if (btn.dataset.filter === filter) btn.classList.add(\'bg-white/10\');\n    else btn.classList.remove(\'bg-white/10\');\n  });\n}\nfunction filterMarkers(f) { renderMarkers(f); }\n\n// ── Batch Results ──\nfunction renderBatchResults(data) {\n  loading.classList.add(\'hidden\');\n  batchResults.classList.remove(\'hidden\');\n\n  const s = data.summary;\n  document.getElementById(\'batch-total\').textContent = s.total;\n\n  // Summary cards\n  const cards = document.getElementById(\'summary-cards\');\n  cards.innerHTML = \'\';\n  cards.innerHTML += `<div class="summary-card glass rounded-xl p-4 text-center"><div class="text-2xl font-bold">${s.total}</div><div class="text-xs text-gray-400">Total Files</div></div>`;\n  cards.innerHTML += `<div class="summary-card glass rounded-xl p-4 text-center"><div class="text-2xl font-bold text-green-400">${s.verdicts[\'REAL\']||0}</div><div class="text-xs text-gray-400">✅ Authentic</div></div>`;\n  cards.innerHTML += `<div class="summary-card glass rounded-xl p-4 text-center"><div class="text-2xl font-bold text-yellow-400">${s.verdicts[\'SUSPICIOUS\']||0}</div><div class="text-xs text-gray-400">⚠️ Suspicious</div></div>`;\n  cards.innerHTML += `<div class="summary-card glass rounded-xl p-4 text-center"><div class="text-2xl font-bold text-red-400">${(s.verdicts[\'LIKELY_FAKE\']||0)+(s.verdicts[\'DEFINITELY_FAKE\']||0)}</div><div class="text-xs text-gray-400">🔴 Fake</div></div>`;\n  if (s.errors > 0) cards.innerHTML += `<div class="summary-card glass rounded-xl p-4 text-center"><div class="text-2xl font-bold text-gray-400">${s.errors}</div><div class="text-xs text-gray-400">❌ Errors</div></div>`;\n\n  // File list\n  const list = document.getElementById(\'batch-list\');\n  list.innerHTML = \'\';\n  data.results.forEach((r, i) => {\n    if (r.error) {\n      list.innerHTML += `<div class="glass rounded-lg p-4"><span class="text-red-400">❌</span> <span class="font-mono text-sm">${r.filename}</span> — <span class="text-gray-400 text-sm">${r.error}</span></div>`;\n      return;\n    }\n    const v = r.verdict;\n    const dotClass = v.verdict.toLowerCase();\n    list.innerHTML += `\n      <div class="batch-row glass rounded-lg" onclick="toggleBatchDetail(${i})">\n        <div class="flex items-center gap-3 p-4">\n          <span class="verdict-dot ${dotClass}"></span>\n          <span class="font-mono text-sm flex-1 truncate">${r.filename}</span>\n          <span class="text-xs text-gray-400">${r.device.model}</span>\n          <span class="text-xs text-gray-400">${r.event_count?.toLocaleString()} evt</span>\n          <span class="text-xs text-gray-400">${r.file_info.size_kb} KB</span>\n          <span class="font-bold text-sm" style="color:${v.verdict_color}">${Math.round(v.score)}/100</span>\n          <span class="text-xs font-semibold" style="color:${v.verdict_color}">${v.verdict_label}</span>\n        </div>\n        <div id="batch-detail-${i}" class="batch-detail px-4 pb-4">\n          <div class="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs mb-3">\n            <div><span class="text-gray-500">Markers:</span> <span class="text-green-400">${v.markers_passed}</span>/<span class="text-red-400">${v.markers_failed}</span>/${v.markers_total}</div>\n            <div><span class="text-gray-500">Anomalies:</span> <span class="text-red-400">${r.anomalies.length}</span></div>\n            <div><span class="text-gray-500">Base Score:</span> ${v.base_score} - ${v.total_penalty}</div>\n            <div><span class="text-gray-500">Android:</span> ${r.device.android}</div>\n            <div><span class="text-gray-500">Packages:</span> ${r.unique_packages}</div>\n            <div><span class="text-gray-500">SHA256:</span> ${r.file_info.sha256?.slice(0,12)}...</div>\n          </div>\n          ${r.anomalies.length > 0 ? \'<div class="mb-3">\' + r.anomalies.map(a => {\n            const icons = { high: \'🔴\', medium: \'🟡\', low: \'🔵\', info: \'ℹ️\' };\n            return `<div class="anomaly-${a.severity} glass rounded p-2 mb-1"><span>${icons[a.severity]||\'❓\'}</span> <span class="font-semibold">${a.label}</span> <span class="text-gray-500">(-${a.score_penalty}pts)</span><br><span class="text-gray-400 text-[11px]">${a.detail}</span></div>`;\n          }).join(\'\') + \'</div>\' : \'\'}\n          <div class="flex gap-4">\n            <div class="flex-1"><div class="text-gray-500 text-[11px] mb-1">Top Packages</div>${(r.top_packages||[]).slice(0,5).map(([p,c])=>`<div class="flex gap-2 text-[11px]"><span class="truncate w-32 font-mono">${p}</span><span class="text-gray-400">${(c/r.event_count*100).toFixed(1)}%</span></div>`).join(\'\')}</div>\n            <div class="flex-1"><div class="text-gray-500 text-[11px] mb-1">Event Types</div>${(r.event_types||[]).slice(0,5).map(([t,c])=>`<div class="flex gap-2 text-[11px]"><span class="truncate w-32 font-mono">${t}</span><span class="text-gray-400">${(c/r.event_count*100).toFixed(1)}%</span></div>`).join(\'\')}</div>\n          </div>\n          <div class="mt-3 text-[11px]">\n            <div class="text-gray-500 mb-1">Forensic Markers</div>\n            <div class="flex flex-wrap gap-1">${(r.checks||[]).map(c=>`<span class="px-1.5 py-0.5 rounded text-[10px] ${c.status===\'pass\'?\'bg-green-900/30 text-green-400\':c.status===\'fail\'?\'bg-red-900/30 text-red-400\':\'bg-gray-800 text-gray-500\'}">${c.status===\'pass\'?\'✅\':\'❌\'} ${c.label}</span>`).join(\'\')}</div>\n          </div>\n        </div>\n      </div>`;\n  });\n}\n\nfunction toggleBatchDetail(i) {\n  const el = document.getElementById(\'batch-detail-\' + i);\n  el.classList.toggle(\'open\');\n}\n\nfunction resetUI() {\n  dropZone.classList.remove(\'hidden\');\n  loading.classList.add(\'hidden\');\n  singleResults.classList.add(\'hidden\');\n  batchResults.classList.add(\'hidden\');\n  fileInput.value = \'\';\n  selectedFiles = [];\n  filePills.innerHTML = \'\';\n  filePills.classList.add(\'hidden\');\n  batchBtn.classList.add(\'hidden\');\n  document.getElementById(\'loading-text\').textContent = \'Analyzing forensic markers...\';\n}\n</script>\n</body>\n</html>\n'


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(INDEX_HTML)


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    """Analyze an uploaded sw_events ZIP file."""
    try:
        data = await file.read()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read file: {e}"}, status_code=400)

    # Parse
    events, manifest, err = parse_zip(data)
    if err:
        return JSONResponse({"error": err}, status_code=400)

    if not events:
        return JSONResponse({"error": "No valid events found in file"}, status_code=400)

    # Analyze
    metrics = analyze_events(events, manifest)

    # Run forensic checks
    checks = run_forensic_checks(metrics)

    # Run anomaly detection
    anomalies = run_anomaly_detection(metrics, events)

    # Calculate verdict
    verdict = calculate_verdict(checks, anomalies)

    # File info
    sha256 = hashlib.sha256(data).hexdigest()
    file_info = {
        "filename": file.filename,
        "size_bytes": len(data),
        "size_kb": round(len(data) / 1024, 1),
        "sha256": sha256,
    }

    return JSONResponse({
        "file_info": file_info,
        "metrics": {k: v for k, v in metrics.items() if k not in ("manifest", "top_packages", "event_types")},
        "checks": checks,
        "anomalies": anomalies,
        "verdict": verdict,
        "device": {
            "model": metrics.get("device_model", "Unknown"),
            "android": metrics.get("android_version", "Unknown"),
            "window_start": metrics.get("window_start", ""),
            "window_end": metrics.get("window_end", ""),
        },
        "top_packages": metrics.get("top_packages", []),
        "event_types": metrics.get("event_types", []),
    })


@app.post("/api/batch")
async def batch_analyze(files: TList[UploadFile] = File(...)):
    """Analyze multiple sw_events ZIP files at once."""
    results = []
    for file in files:
        try:
            data = await file.read()
        except Exception as e:
            results.append({"filename": file.filename, "error": f"Failed to read: {e}"})
            continue

        events, manifest, err = parse_zip(data)
        if err or not events:
            results.append({"filename": file.filename, "error": err or "No events found"})
            continue

        metrics = analyze_events(events, manifest)
        checks = run_forensic_checks(metrics)
        anomalies = run_anomaly_detection(metrics, events)
        verdict = calculate_verdict(checks, anomalies)

        sha256 = hashlib.sha256(data).hexdigest()
        results.append({
            "filename": file.filename,
            "file_info": {
                "size_bytes": len(data),
                "size_kb": round(len(data) / 1024, 1),
                "sha256": sha256,
            },
            "verdict": verdict,
            "device": {
                "model": metrics.get("device_model", "Unknown"),
                "android": metrics.get("android_version", "Unknown"),
            },
            "checks": checks,
            "anomalies": anomalies,
            "event_count": len(events),
            "unique_packages": metrics.get("unique_packages", 0),
            "top_packages": metrics.get("top_packages", []),
            "event_types": metrics.get("event_types", []),
            "metrics": {k: v for k, v in metrics.items() if k not in ("manifest", "top_packages", "event_types")},
        })

    # Summary stats
    valid = [r for r in results if "error" not in r]
    summary = {
        "total": len(results),
        "valid": len(valid),
        "errors": len(results) - len(valid),
        "verdicts": {},
    }
    for r in valid:
        v = r["verdict"]["verdict"]
        summary["verdicts"][v] = summary["verdicts"].get(v, 0) + 1

    return JSONResponse({"results": results, "summary": summary})
