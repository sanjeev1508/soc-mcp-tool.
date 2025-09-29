from typing import Any, List, Dict, Optional
import datetime
import asyncio
import os
import requests
from fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("socMCP")


# -------------------------
# Helper: VirusTotal (or any IP reputation) lookup wrapper
# -------------------------
async def vt_lookup_ip(ip: str, vt_api_key: Optional[str]) -> Dict[str, Any]:
    """
    Lookup IP reputation using VirusTotal API if vt_api_key is provided.
    Returns a dict with either 'error' or raw JSON from the API.
    If vt_api_key is None, returns empty dict (no external lookup).
    """
    if not vt_api_key:
        # Try environment fallback; if still None, return empty signal
        vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        return {"note": "no_api_key_provided"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": vt_api_key}

    def _req():
        return requests.get(url, headers=headers, timeout=15)

    try:
        resp = await asyncio.to_thread(_req)
    except Exception as e:
        return {"error": f"request_failed: {str(e)}"}

    if resp.status_code != 200:
        return {"error": f"status_{resp.status_code}", "details": resp.text}

    try:
        return resp.json()
    except Exception as e:
        return {"error": f"invalid_json: {e}", "raw": resp.text}


# -------------------------
# Utility: safe timestamp parse / normalization
# -------------------------
def iso_to_dt(ts: Optional[str]) -> Optional[datetime.datetime]:
    """Convert ISO-like timestamp string to timezone-aware UTC datetime if possible."""
    if not ts:
        return None
    try:
        # fromisoformat handles many ISO8601 variants (Python >=3.11 better); fallback try/except
        dt = datetime.datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            # assume input is UTC if no tz provided
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        try:
            # last resort: try parsing common fraction seconds without timezone
            dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f")
            return dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            return None


# -------------------------
# MCP Tool: detect_bruteforce
# -------------------------
@mcp.tool()
async def detect_bruteforce(
    ip: str,
    logs: Optional[List[Dict[str, Any]]] = None,
    vt_api_key: Optional[str] = None,
    window_seconds: int = 300,
    fail_threshold: int = 10,
) -> Dict[str, Any]:
    """
    Determine whether the given IP is likely performing brute-force activity.
    - ip: target IP address to evaluate (string).
    - logs: OPTIONAL list of structured events (dict). Each event should be:
        {
          "ip": "<ip string>",
          "user": "<username or None>",
          "result": "<FAIL or SUCCESS or BAN or ALERT or other>",
          "timestamp": "<ISO8601 string or None>",
          "source": "<e.g. ssh, http, app>"
        }
      The client is responsible for parsing raw logs into this structure.
    - vt_api_key: OPTIONAL VirusTotal API key to enrich decision (no hardcoded key here).
    - window_seconds: time window (seconds) to consider for rapid attempts.
    - fail_threshold: number of failed attempts within window considered suspicious.

    Returns:
      {
        "ip": <ip>,
        "verdict": "attack"|"suspicious"|"normal",
        "risk_score": int (0-100),
        "signals": { ... },
        "evidence": { ... },
        "vt_enrichment": {...} or {"note":"no_api_key_provided"},
        "timestamp": "<ISO8601 UTC>"
      }
    """
    ip = ip.strip()
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1) Optional VT enrichment
    vt_data = await vt_lookup_ip(ip, vt_api_key)

    # 2) If client supplied logs, analyze them. Client must supply structured logs (no regex here).
    evidence = {
        "total_failures": 0,
        "total_success": 0,
        "events_analyzed": 0,
        "failures_in_window": 0,
        "unique_usernames": set(),
        "sample_events": [],
    }

    if logs:
        # Filter events for this IP and normalise timestamps
        ip_events = []
        for ev in logs:
            try:
                if ev.get("ip") != ip:
                    continue
            except Exception:
                continue

            ts = iso_to_dt(ev.get("timestamp"))
            ip_events.append({"raw": ev, "ts": ts})

        # sort by timestamp (unknown timestamps will be placed at end)
        ip_events.sort(key=lambda e: e["ts"] or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))

        evidence["events_analyzed"] = len(ip_events)

        # compute aggregate counts and windowed failures
        # determine window end as latest timestamp or now
        if ip_events:
            latest_ts = next((e["ts"] for e in reversed(ip_events) if e["ts"]), now)
        else:
            latest_ts = now

        window_start = latest_ts - datetime.timedelta(seconds=window_seconds)

        failures_in_window = 0
        for e in ip_events:
            result = (e["raw"].get("result") or "").upper()
            if result == "FAIL":
                evidence["total_failures"] += 1
            elif result == "SUCCESS":
                evidence["total_success"] += 1
            if e["raw"].get("user"):
                evidence["unique_usernames"].add(e["raw"].get("user"))
            # windowed failures
            if e["ts"] and e["ts"] >= window_start and (e["raw"].get("result") or "").upper() == "FAIL":
                failures_in_window += 1
            # collect small sample
            if len(evidence["sample_events"]) < 10:
                evidence["sample_events"].append(e["raw"])

        evidence["failures_in_window"] = failures_in_window
        evidence["unique_usernames"] = list(evidence["unique_usernames"])

    # 3) Scoring: combine signals conservatively (simple, interpretable)
    risk_score = 0
    signals = {}

    # VT-based signals (if any)
    if isinstance(vt_data, dict) and vt_data.get("note") != "no_api_key_provided":
        signals["vt_enrichment_available"] = True
        # conservative: if API returned an analysis summary, reward risk
        # (client can inspect vt_data details)
        vt_flags = 0
        try:
            attrs = vt_data.get("data", {}).get("attributes", {}) if isinstance(vt_data.get("data"), dict) else {}
            last_stats = attrs.get("last_analysis_stats") or {}
            malicious_count = int(last_stats.get("malicious", 0) or 0)
            suspicious_count = int(last_stats.get("suspicious", 0) or 0)
            reputation = attrs.get("reputation")
            vt_flags += min(100, malicious_count * 10 + suspicious_count * 3)
            if isinstance(reputation, int) and reputation < 0:
                vt_flags += 20
        except Exception:
            vt_flags = 0
        signals["vt_flag_score"] = min(80, vt_flags)
        risk_score += signals["vt_flag_score"] * 0.6  # VT is significant but not sole decider
    else:
        signals["vt_enrichment_available"] = False

    # Log-derived signals
    if logs:
        signals["events_analyzed"] = evidence["events_analyzed"]
        signals["total_failures"] = evidence["total_failures"]
        signals["failures_in_window"] = evidence["failures_in_window"]
        signals["unique_usernames_tried"] = len(evidence["unique_usernames"]) if isinstance(evidence.get("unique_usernames"), list) else 0

        # failure-driven scoring
        risk_score += min(40, evidence["failures_in_window"] * 3)  # up to +40 from windowed failures
        # username enumeration adds small risk
        if len(evidence.get("unique_usernames", [])) > 3 and evidence["total_failures"] > 5:
            risk_score += 10
            signals["username_enumeration_suspected"] = True
    else:
        # if no logs, be conservative
        signals["logs_provided"] = False

    # Normalize score to 0-100
    risk_score = int(max(0, min(100, risk_score)))

    # Simple thresholding: return "attack", "suspicious", or "normal"
    if risk_score >= 70:
        verdict = "attack"
    elif risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "normal"

    return {
        "ip": ip,
        "verdict": verdict,
        "risk_score": risk_score,
        "signals": signals,
        "evidence": {
            "events_analyzed": evidence["events_analyzed"],
            "total_failures": evidence["total_failures"],
            "failures_in_window": evidence["failures_in_window"],
            "unique_usernames": evidence["unique_usernames"],
            "sample_events": evidence["sample_events"],
        },
        "vt_enrichment": vt_data,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# -------------------------
# MCP Tool: correlate_events
# -------------------------
@mcp.tool()
async def correlate_events(
    logs: List[Dict[str, Any]],
    window_seconds: int = 300,
    fail_threshold: int = 5,
) -> Dict[str, Any]:
    """
    Correlate a list of structured events (no parsing inside).
    Input:
      logs: list of dict { ip, user, result, timestamp, source }
    Output:
      {
        "summary": {...},
        "ip_stats": { ip: {events, failures, successes, first_seen, last_seen} },
        "user_stats": { user: {events, unique_ips, failures, successes} },
        "alerts": [ {type, subject, reason, metric_values} ],
        "timestamp": "<ISO8601 UTC>"
      }

    Note: The client is responsible for supplying structured events.
    """
    # defensive checks
    if not logs or not isinstance(logs, list):
        return {"error": "logs_must_be_list_of_structured_event_dicts"}

    ip_buckets: Dict[str, List[Dict[str, Any]]] = {}
    user_buckets: Dict[str, List[Dict[str, Any]]] = {}
    total_failures = 0
    total_success = 0

    # Normalize and bucket events (no regex)
    for ev in logs:
        try:
            ip = ev.get("ip") or "unknown"
            user = ev.get("user") or "unknown"
            result = (ev.get("result") or "").upper()
            ts = iso_to_dt(ev.get("timestamp"))
        except Exception:
            continue

        entry = {"ip": ip, "user": user, "result": result, "timestamp": ts, "source": ev.get("source"), "raw": ev}
        ip_buckets.setdefault(ip, []).append(entry)
        user_buckets.setdefault(user, []).append(entry)
        if result == "FAIL":
            total_failures += 1
        elif result == "SUCCESS":
            total_success += 1

    # Build per-IP stats and alerts
    ip_stats: Dict[str, Dict[str, Any]] = {}
    alerts: List[Dict[str, Any]] = []

    for ip, events in ip_buckets.items():
        events_sorted = sorted(events, key=lambda e: e["timestamp"] or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
        first_seen = next((e["timestamp"] for e in events_sorted if e["timestamp"]), None)
        last_seen = next((e["timestamp"] for e in reversed(events_sorted) if e["timestamp"]), None)

        failures = sum(1 for e in events if e["result"] == "FAIL")
        successes = sum(1 for e in events if e["result"] == "SUCCESS")
        unique_users = {e["user"] for e in events if e["user"]}
        alert_needed = False
        reason = None

        # Windowed failure detection: count failures within sliding window ending at last_seen
        failures_in_window = 0
        if last_seen:
            window_start = last_seen - datetime.timedelta(seconds=window_seconds)
            failures_in_window = sum(1 for e in events if e["timestamp"] and e["timestamp"] >= window_start and e["result"] == "FAIL")
            if failures_in_window >= fail_threshold:
                alert_needed = True
                reason = "many_failures_in_window"

        ip_stats[ip] = {
            "events": len(events),
            "failures": failures,
            "successes": successes,
            "unique_users": len(unique_users),
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "failures_in_window": failures_in_window,
        }

        if alert_needed:
            alerts.append({
                "type": "suspicious_ip",
                "ip": ip,
                "reason": reason,
                "failures_in_window": failures_in_window,
                "threshold": fail_threshold,
                "events_sample": [e["raw"] for e in events[:5]],
            })

    # Username enumeration detection
    user_stats: Dict[str, Dict[str, Any]] = {}
    for user, events in user_buckets.items():
        unique_ips = {e["ip"] for e in events if e["ip"]}
        failures = sum(1 for e in events if e["result"] == "FAIL")
        successes = sum(1 for e in events if e["result"] == "SUCCESS")
        user_stats[user] = {
            "events": len(events),
            "unique_ips": len(unique_ips),
            "failures": failures,
            "successes": successes,
        }
        # heuristic: same username tried from many IPs with many failures and no successes
        if len(unique_ips) >= 5 and failures >= 5 and successes == 0:
            alerts.append({
                "type": "username_enumeration",
                "user": user,
                "unique_ips": len(unique_ips),
                "failures": failures,
                "events_sample": [e["raw"] for e in events[:5]],
            })

    summary = {
        "total_events": sum(len(v) for v in ip_buckets.values()),
        "total_failures": total_failures,
        "total_success": total_success,
        "unique_ips": len(ip_buckets),
        "unique_users": len(user_buckets),
    }

    # Sort alerts by simple severity heuristic (username_enum first)
    alerts_sorted = sorted(alerts, key=lambda a: (0 if a["type"] == "username_enumeration" else 1, -a.get("failures", 0)))

    return {
        "summary": summary,
        "ip_stats": ip_stats,
        "user_stats": user_stats,
        "alerts": alerts_sorted,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# -------------------------
# Optional: minimal get_ip_details tool using client-supplied API key
# -------------------------
@mcp.tool()
async def get_ip_details(ip: str, vt_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Simple wrapper to retrieve IP details from VirusTotal if an API key is provided.
    No hardcoded key here.
    """
    return await vt_lookup_ip(ip, vt_api_key)


# -------------------------
# Run server (if executed directly)
# -------------------------
if __name__ == "__main__":
    # do not embed secrets here; run with environment VAR or pass vt_api_key via MCP client call
    mcp.run(transport="http", port=8000)
