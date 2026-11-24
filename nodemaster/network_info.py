from typing import Any


# Common Cloudflare PoPs. Unmapped codes still appear without an inferred country.
EDGE_CITIES = {
    "HKG": ("HK", "香港"), "TPE": ("TW", "台北"), "KHH": ("TW", "高雄"),
    "NRT": ("JP", "东京"), "HND": ("JP", "东京"), "KIX": ("JP", "大阪"),
    "ICN": ("KR", "首尔"), "SIN": ("SG", "新加坡"), "BKK": ("TH", "曼谷"),
    "KUL": ("MY", "吉隆坡"), "MNL": ("PH", "马尼拉"), "CGK": ("ID", "雅加达"),
    "BOM": ("IN", "孟买"), "DEL": ("IN", "德里"), "SYD": ("AU", "悉尼"),
    "MEL": ("AU", "墨尔本"), "AKL": ("NZ", "奥克兰"), "LAX": ("US", "洛杉矶"),
    "SJC": ("US", "圣何塞"), "SFO": ("US", "旧金山"), "SEA": ("US", "西雅图"),
    "IAD": ("US", "阿什本"), "ORD": ("US", "芝加哥"), "EWR": ("US", "纽瓦克"),
    "DFW": ("US", "达拉斯"), "YYZ": ("CA", "多伦多"), "YVR": ("CA", "温哥华"),
    "LHR": ("GB", "伦敦"), "FRA": ("DE", "法兰克福"), "AMS": ("NL", "阿姆斯特丹"),
    "CDG": ("FR", "巴黎"), "MAD": ("ES", "马德里"), "ZRH": ("CH", "苏黎世"),
}

IP_TYPE_LABELS = {"residential": "家宽", "business": "商宽", "education": "教育网", "hosting": "数据中心 / CDN",
                  "mobile": "移动网络", "isp": "运营商网络", "government": "政府网络", "unknown": "未知"}
IP_TYPES = tuple(IP_TYPE_LABELS)
TYPE_ALIASES = {
    "residential": "residential", "residential isp": "residential", "fixed line isp": "residential",
    "business": "business", "commercial": "business", "company": "business", "corporate": "business",
    "education": "education", "university": "education", "university/college/school": "education",
    "hosting": "hosting", "datacenter": "hosting", "data center": "hosting", "cdn": "hosting",
    "data center/web hosting/transit": "hosting", "mobile": "mobile", "mobile isp": "mobile",
    "isp": "isp", "government": "government", "military": "government",
}


def ip_type_evidence(data: dict[str, Any]) -> str | None:
    if data.get("datacenter") is True or data.get("hosting") is True:
        return "hosting"
    if data.get("mobile") is True:
        return "mobile"
    value = data.get("network_type")
    return TYPE_ALIASES.get(value.strip().casefold()) if isinstance(value, str) else None


def classify_ip(rows: list[dict[str, Any]]) -> str | None:
    types = {kind for row in rows if row["status"] == "passed" and (kind := ip_type_evidence(row["data"]))}
    specific = types - {"isp"}
    if len(specific) == 1:
        return next(iter(specific))
    return "isp" if not specific and "isp" in types else None
