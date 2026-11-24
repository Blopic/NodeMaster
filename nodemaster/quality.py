import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta
from math import isfinite
from time import monotonic
from typing import Any

import httpx

from .config import Settings
from .network_info import classify_ip
from .sources import public_address
from .store import Store

PROVIDERS = ("ipinfo", "abuseipdb")
KEY_PROVIDERS = (*PROVIDERS, "ipapi")
PUBLIC_PROVIDERS = ("ipapi", "ipwhois", "dbip")
LOCATION_PROVIDERS = ("dbip", "ipinfo", "ipapi", "ipwhois", "abuseipdb")
FLAGS = ("vpn", "proxy", "hosting", "datacenter", "tor", "relay", "mobile")
FLAG_COST = {"vpn": 15, "proxy": 15, "tor": 30, "relay": 10}


def country_code(value: Any) -> str | None:
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def normalize_quality(provider: str, raw: dict[str, Any]) -> dict[str, Any]:
    if provider == "ipinfo":
        asn = raw.get("asn") if isinstance(raw.get("asn"), dict) else {}
        geo = raw.get("geo") if isinstance(raw.get("geo"), dict) else {}
        privacy = raw.get("privacy") if isinstance(raw.get("privacy"), dict) else {}
        org = raw.get("org") if isinstance(raw.get("org"), str) else ""
        asn_id = raw.get("asn") if isinstance(raw.get("asn"), str) else asn.get("asn")
        if not asn_id and org.startswith("AS"):
            asn_id = org.split()[0]
        name = raw.get("as_name") or asn.get("name") or (org.partition(" ")[2] if asn_id and org else org)
        result = {"ip": raw.get("ip"), "country": geo.get("country_code") or raw.get("country_code") or raw.get("country"),
                  "region": geo.get("region") or raw.get("region"), "city": geo.get("city") or raw.get("city"),
                  "asn": asn_id, "isp": name, "organization": org or name,
                  "network_type": raw.get("usage_type") or asn.get("type") or raw.get("as_type")}
        for flag in FLAGS:
            result[flag] = privacy.get(flag, raw.get("is_" + flag))
        result["datacenter"] = result["datacenter"] if isinstance(result["datacenter"], bool) else raw.get("is_hosting")
    elif provider == "abuseipdb":
        payload = raw.get("data")
        if not isinstance(payload, dict):
            raise ValueError("Invalid provider response")
        score = payload.get("abuseConfidenceScore")
        risk = float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) and isfinite(score) and 0 <= score <= 100 else None
        result = {"ip": payload.get("ipAddress"), "country": payload.get("countryCode"), "isp": payload.get("isp"),
                  "network_type": payload.get("usageType"), "tor": payload.get("isTor"),
                  "abuse_risk": risk, "total_reports": payload.get("totalReports"), "last_reported": payload.get("lastReportedAt")}
    elif provider == "ipapi":
        asn = raw.get("asn")
        location = raw.get("location") if isinstance(raw.get("location"), dict) else raw
        company = raw.get("company") if isinstance(raw.get("company"), dict) else {}
        result = {"ip": raw.get("ip"), "country": location.get("country_code") or location.get("country"),
                  "region": location.get("state") or location.get("region"), "city": location.get("city"),
                  "isp": company.get("name"), "asn": asn.get("asn") if isinstance(asn, dict) else asn,
                  "network_type": company.get("type") or (asn.get("type") if isinstance(asn, dict) else None)}
        result.update({flag: raw.get("is_" + flag) for flag in FLAGS})
    elif provider == "dbip":
        result = {"ip": raw.get("ipAddress"), "country": raw.get("countryCode"),
                  "region": raw.get("stateProv"), "city": raw.get("city")}
    elif provider == "ipquery":
        isp = raw.get("isp")
        risk = raw.get("risk")
        if not isinstance(isp, dict) or not isinstance(risk, dict):
            raise ValueError("Invalid provider response")
        result = {"ip": raw.get("ip"), "asn": isp.get("asn"), "isp": isp.get("isp"), "organization": isp.get("org"),
                  "datacenter": risk.get("is_datacenter"), "mobile": risk.get("is_mobile")}
    else:
        if raw.get("success") is not True:
            raise ValueError("Invalid provider response")
        connection = raw.get("connection") if isinstance(raw.get("connection"), dict) else {}
        security = raw.get("security") if isinstance(raw.get("security"), dict) else {}
        result = {"ip": raw.get("ip"), "country": raw.get("country_code"), "region": raw.get("region"),
                  "city": raw.get("city"), "asn": connection.get("asn"), "isp": connection.get("isp"),
                  "organization": connection.get("org"), "network_type": connection.get("type"),
                  "hosting": security.get("hosting"), "mobile": security.get("mobile")}
    if isinstance(asn := result.get("asn"), (int, str)):
        number = str(asn).split()[0].upper().removeprefix("AS") if str(asn).strip() else ""
        result["asn"] = "AS" + number if number.isascii() and number.isdigit() else None
    result["country"] = country_code(result.get("country"))
    return {key: value for key, value in result.items() if (isinstance(value, bool) if key in FLAGS else value not in (None, ""))}


def quality_profile(rows: list[dict[str, Any]]) -> dict[str, Any]:
    latest: dict[str, Any] = {}
    successful: dict[str, Any] = {}
    for row in rows:
        latest.setdefault(row["provider"], row)
        if row["status"] == "passed":
            successful.setdefault(row["provider"], row)
    facts: dict[str, dict[str, Any]] = {}
    for provider, row in successful.items():
        for key, value in row["data"].items():
            facts.setdefault(key, {})[provider] = value
    differences = {key: values for key, values in facts.items() if key != "ip" and len({str(v).casefold() for v in values.values()}) > 1}
    reasons = []
    if abuse := facts.get("abuse_risk"):
        reasons.append({"metric": "abuse_risk", "values": abuse, "penalty": round(max(abuse.values()) * 0.6, 1)})
    for flag, cost in FLAG_COST.items():
        if values := {provider: value for provider, value in facts.get(flag, {}).items() if provider in PROVIDERS}:
            if any(values.values()):
                reasons.append({"metric": flag, "values": values, "penalty": cost})
    known_risk = "abuse_risk" in facts or any(set(facts.get(flag, {})).intersection(PROVIDERS) for flag in FLAG_COST)
    locations_by_provider = {}
    for row in rows:
        name = row["provider"]
        if row["status"] == "passed" and name in LOCATION_PROVIDERS and (country := country_code(row["data"].get("country"))):
            locations_by_provider.setdefault(name, {"country": country, "region": row["data"].get("region"),
                                                    "city": row["data"].get("city"), "provider": name})
    locations = [locations_by_provider[name] for name in LOCATION_PROVIDERS if name in locations_by_provider]
    location = max(locations, key=lambda row: bool(row["region"]) + bool(row["city"]), default=None)
    return {"score": round(max(0, 100 - sum(row["penalty"] for row in reasons)), 1) if known_risk else None,
            "facts": facts, "differences": differences, "reasons": reasons, "location": location,
            "ip_type": classify_ip(list(successful.values())) or "unknown",
            "asn": next((facts["asn"][p] for p in LOCATION_PROVIDERS if p in facts.get("asn", {})), None),
            "providers": {k: {"status": row["status"], "checked": row["checked"],
                              "observed": successful[k]["checked"] if k in successful else None}
                          for k, row in latest.items()}}


class QualityService:
    def __init__(self, store: Store, settings: Settings, client: httpx.AsyncClient):
        self.store, self.settings, self.client = store, settings, client
        sources = (*PROVIDERS, *PUBLIC_PROVIDERS, "ipquery")
        self.next_request = {p: 0.0 for p in sources}
        self.cooldown = {p: 0.0 for p in sources}
        self.rate_locks = {p: asyncio.Lock() for p in sources}
        self.keys = {p: store.get_setting(p + "_key", "", secret=True) for p in KEY_PROVIDERS}

    async def check(self, ip: str, *, force: bool = False, turn_type: bool = False) -> dict[str, Any]:
        if not public_address(ip):
            return {"status": "non_public_ip", "calls": 0}
        ip = ipaddress.ip_address(ip).compressed
        enabled = {name: self.keys[name] for name in PROVIDERS if self.keys[name]}
        enabled.update({name: self.keys.get(name, "") for name in PUBLIC_PROVIDERS
                        if getattr(self.settings, "quality_" + name + "_enabled")})
        settings = self.settings
        type_fallback = turn_type and settings.quality_turn_type_fallback
        if not enabled and not type_fallback:
            return {"status": "no_providers", "calls": 0}
        cutoff = datetime.now(UTC) - timedelta(hours=settings.quality_cache_hours)
        rows = self.store.quality_profile_rows(ip)
        latest = {}
        for row in rows:
            latest.setdefault(row["provider"], row)

        def fresh_location(row: dict[str, Any]) -> bool:
            return (row["status"] == "passed" and bool(country_code(row["data"].get("country")))
                    and datetime.fromisoformat(row["checked"]) >= cutoff)

        async def check_provider(name: str, key: str, *, for_location: bool = False) -> tuple[str, int]:
            previous = latest.get(name)
            if not force and previous and datetime.fromisoformat(previous["checked"]) >= cutoff:
                if previous["status"] == "passed" and (not for_location or fresh_location(previous)):
                    return "cached", 0
                if for_location and previous["status"] in {"passed", "no_location"}:
                    return "no_location", 0
            if self.cooldown[name] > monotonic():
                return "rate_limited", 0
            return await self.query(ip, name, key, settings)

        results = await asyncio.gather(*(check_provider(name, key, for_location=name in PUBLIC_PROVIDERS)
                                         for name, key in enabled.items()))
        states = {name: state for name, (state, _) in zip(enabled, results, strict=True)}
        calls = sum(count for _, count in results)
        rows = self.store.quality_profile_rows(ip) if calls else rows
        if settings.quality_dbip_enabled and settings.quality_location_fallback and "ipwhois" not in enabled and not any(map(fresh_location, rows)):
            states["ipwhois"], count = await check_provider("ipwhois", "", for_location=True)
            calls += count
            if count:
                rows = self.store.quality_profile_rows(ip)
        if type_fallback and quality_profile([row for row in rows if row["provider"] != "ipquery"])["ip_type"] == "unknown":
            states["ipquery"], count = await check_provider("ipquery", "")
            calls += count
            if count:
                rows = self.store.quality_profile_rows(ip)
        succeeded = sum(state in {"passed", "cached"} for state in states.values())
        status = "passed" if succeeded == len(states) else "partial" if succeeded else "failed"
        return {"status": status, "calls": calls, "providers": states, "profile": quality_profile(rows)}

    async def query(self, ip: str, name: str, key: str, settings: Settings) -> tuple[str, int]:
        data: dict[str, Any] = {}
        raw: dict[str, Any] = {}
        async with self.rate_locks[name]:
            if self.cooldown[name] > monotonic():
                return "rate_limited", 0
            await asyncio.sleep(max(0, self.next_request[name] - monotonic()))
            if self.cooldown[name] > monotonic():
                return "rate_limited", 0
            self.next_request[name] = monotonic() + settings.quality_interval_seconds
        try:
            spec = {}
            method = self.client.get
            if name == "ipinfo":
                url = f"https://ipinfo.io/{ip}/json"
                spec = {"headers": {"Authorization": "Bearer " + key}}
            elif name == "abuseipdb":
                url = "https://api.abuseipdb.com/api/v2/check"
                spec = {"headers": {"Key": key, "Accept": "application/json"}, "params": {"ipAddress": ip, "maxAgeInDays": 90}}
            elif name == "ipapi":
                url = "https://api.ipapi.is/"
                spec = {"params": {"q": ip}}
                if key:
                    method = self.client.post
                    spec = {"json": {"q": ip, "key": key}}
            elif name == "dbip":
                url = f"https://api.db-ip.com/v2/free/{ip}"
            elif name == "ipquery":
                url = f"https://api.ipquery.io/{ip}"
            else:
                url = f"https://ipwho.is/{ip}"
            timeout = min(5 if name == "ipquery" else 2.5, settings.request_timeout)
            async with asyncio.timeout(timeout):
                response = await method(url, **spec, follow_redirects=False)
            if response.status_code == 429:
                delay = response.headers.get("Retry-After", "")[:9]
                self.cooldown[name] = monotonic() + max(60, int(delay) if delay.isascii() and delay.isdigit() else 60)
                status = "rate_limited"
            else:
                response.raise_for_status()
                candidate = response.json()
                if not isinstance(candidate, dict):
                    raise ValueError
                data = normalize_quality(name, candidate)
                if ipaddress.ip_address(data.get("ip", "")).compressed != ip:
                    raise ValueError
                raw = candidate
                status = "no_location" if name == "dbip" and not data.get("country") else "passed"
        except httpx.HTTPStatusError as exc:
            status = "provider_auth" if exc.response.status_code in {401, 403} else "http_error"
        except (TimeoutError, httpx.TimeoutException):
            status = "timeout"
        except httpx.HTTPError:
            status = "network_error"
        except (ValueError, TypeError, OverflowError):
            status = "invalid_data"
            data = {}
        self.store.save_quality(ip, name, status, data, raw)
        return status, 1
