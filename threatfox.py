# threatfox.py
# RAW ThreatFox API client (abuse.ch)


import requests
from typing import Dict, Any, Optional

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


# =========================
# LOW-LEVEL CORE
# =========================

def _post(payload: dict, api_key: str, timeout: int = 20) -> Dict[str, Any]:
    if not api_key:
        return {
            "error": "no_api_key",
            "message": "ThreatFox API key not provided"
        }

    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "SOC-Helper"
    }

    try:
        r = requests.post(
            API_URL,
            json=payload,
            headers=headers,
            timeout=timeout
        )
    except Exception as e:
        return {
            "error": "request_failed",
            "message": str(e)
        }

    try:
        return r.json()
    except Exception:
        return {
            "error": "invalid_json",
            "status_code": r.status_code,
            "raw": r.text
        }


# =========================
# SEARCH / LOOKUP
# =========================

def search_ioc(
    ioc: str,
    api_key: str,
    exact_match: bool = True,
    timeout: int = 20
) -> Dict[str, Any]:

    payload = {
        "query": "search_ioc",
        "search_term": ioc,
        "exact_match": exact_match
    }
    return _post(payload, api_key, timeout)


def get_ioc_by_id(
    ioc_id: int,
    api_key: str,
    timeout: int = 20
) -> Dict[str, Any]:

    payload = {
        "query": "ioc",
        "id": int(ioc_id)
    }
    return _post(payload, api_key, timeout)


def search_hash(
    file_hash: str,
    api_key: str,
    timeout: int = 20
) -> Dict[str, Any]:

    payload = {
        "query": "search_hash",
        "hash": file_hash
    }
    return _post(payload, api_key, timeout)


# =========================
# BULK / LISTING
# =========================

def get_recent_iocs(
    api_key: str,
    days: int = 3,
    timeout: int = 20
) -> Dict[str, Any]:
    """
    Последние IOC (1–7 дней).
    """
    payload = {
        "query": "get_iocs",
        "days": int(days)
    }
    return _post(payload, api_key, timeout)


def tag_info(
    tag: str,
    api_key: str,
    limit: int = 100,
    timeout: int = 20
) -> Dict[str, Any]:
    """
    IOC по тегу.
    """
    payload = {
        "query": "taginfo",
        "tag": tag,
        "limit": int(limit)
    }
    return _post(payload, api_key, timeout)


def malware_info(
    malware: str,
    api_key: str,
    limit: int = 100,
    timeout: int = 20
) -> Dict[str, Any]:

    payload = {
        "query": "malwareinfo",
        "malware": malware,
        "limit": int(limit)
    }
    return _post(payload, api_key, timeout)


# =========================
# METADATA / DICTIONARIES
# =========================

def get_types(api_key: str, timeout: int = 20) -> Dict[str, Any]:

    payload = {
        "query": "types"
    }
    return _post(payload, api_key, timeout)


def get_tag_list(api_key: str, timeout: int = 20) -> Dict[str, Any]:

    payload = {
        "query": "tag_list"
    }
    return _post(payload, api_key, timeout)


def get_malware_list(api_key: str, timeout: int = 20) -> Dict[str, Any]:

    payload = {
        "query": "malware_list"
    }
    return _post(payload, api_key, timeout)


def get_label(
    malware: str,
    api_key: str,
    platform: Optional[str] = None,
    timeout: int = 20
) -> Dict[str, Any]:

    payload = {
        "query": "get_label",
        "malware": malware
    }

    if platform:
        payload["platform"] = platform

    return _post(payload, api_key, timeout)


# =========================
# SUBMISSION (OPTIONAL)
# =========================

def submit_ioc(
    api_key: str,
    threat_type: str,
    ioc_type: str,
    malware: str,
    iocs: list,
    confidence_level: int = 50,
    reference: Optional[str] = None,
    comment: Optional[str] = None,
    tags: Optional[list] = None,
    is_compromised: bool = False,
    anonymous: bool = False,
    timeout: int = 20
) -> Dict[str, Any]:

    payload = {
        "query": "submit_ioc",
        "threat_type": threat_type,
        "ioc_type": ioc_type,
        "malware": malware,
        "confidence_level": int(confidence_level),
        "is_compromised": bool(is_compromised),
        "anonymous": int(bool(anonymous)),
        "iocs": iocs
    }

    if reference:
        payload["reference"] = reference
    if comment:
        payload["comment"] = comment
    if tags:
        payload["tags"] = tags

    return _post(payload, api_key, timeout)


# =========================
# OPTIONAL NORMALIZER
# =========================

def normalize_ioc(resp: Dict[str, Any]) -> Dict[str, Any]:

    if not isinstance(resp, dict):
        return {"error": "invalid_response"}

    if "id" not in resp:
        return resp

    return {
        "id": resp.get("id"),
        "ioc": resp.get("ioc"),
        "ioc_type": resp.get("ioc_type"),
        "ioc_type_desc": resp.get("ioc_type_desc"),
        "threat_type": resp.get("threat_type"),
        "threat_type_desc": resp.get("threat_type_desc"),
        "malware": resp.get("malware"),
        "malware_printable": resp.get("malware_printable"),
        "malware_alias": resp.get("malware_alias"),
        "confidence_level": resp.get("confidence_level"),
        "is_compromised": resp.get("is_compromised"),
        "asn": resp.get("asn"),
        "country": resp.get("country"),
        "first_seen": resp.get("first_seen"),
        "last_seen": resp.get("last_seen"),
        "reporter": resp.get("reporter"),
        "reference": resp.get("reference"),
        "comment": resp.get("comment"),
        "tags": resp.get("tags"),
        "credits": resp.get("credits"),
        "malware_samples": resp.get("malware_samples"),
        "uuid": resp.get("uuid"),
        "raw": resp
    }
