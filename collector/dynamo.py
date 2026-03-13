"""DynamoDB client wrapper — cache reads/writes and event persistence."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import logging
import os
import time
from typing import Any, Optional

import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from collector.models import EnrichedEvent, HoneypotEvent, IPEnrichment, StatsResponse, TopCredential, TopIP

logger = logging.getLogger(__name__)

_CACHE_TABLE = "hollownet-ip-cache"
_EVENTS_TABLE = "hollownet-events"
_EVENTS_IP_GSI = "src_ip-index"
_DEFAULT_REGION = "us-east-1"
_CACHE_TTL_SECONDS = 86_400  # 24 h

_deserializer = TypeDeserializer()
_serializer = TypeSerializer()


def create_dynamo_client(
    *,
    profile: str | None = None,
    region: str | None = None,
) -> Any:
    """Create a DynamoDB low-level client with configured profile/region."""
    session = boto3.Session(
        region_name=region or os.environ.get("AWS_REGION", _DEFAULT_REGION),
        profile_name=profile or os.environ.get("AWS_PROFILE", "hollownet"),
    )
    return session.client("dynamodb")


def _make_client(profile: str | None = None) -> Any:
    """Backward-compatible client factory used by existing callers."""
    return create_dynamo_client(profile=profile)


def _deserialize_item(item: dict[str, Any]) -> dict[str, Any]:
    return {key: _deserializer.deserialize(value) for key, value in item.items()}


def _deserialize_events(items: list[dict[str, Any]]) -> list[EnrichedEvent]:
    events: list[EnrichedEvent] = []
    for item in items:
        raw = _deserialize_item(item)
        try:
            events.append(EnrichedEvent(**raw))
        except ValidationError as exc:
            logger.warning(
                json.dumps(
                    {
                        "level": "warning",
                        "msg": "Skipping invalid event from DynamoDB",
                        "context": {"event_id": raw.get("event_id"), "error": str(exc)},
                    }
                )
            )
    return events


def get_ip_cache(
    ip: str,
    *,
    client: Any | None = None,
) -> Optional[IPEnrichment]:
    """Fetch a cached IPEnrichment from DynamoDB.

    Returns None on cache miss or if the entry has expired.
    """
    ddb = client or _make_client()
    try:
        resp = ddb.get_item(
            TableName=_CACHE_TABLE,
            Key={"ip": {"S": ip}},
        )
    except (ClientError, BotoCoreError) as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "DynamoDB get_ip_cache failed",
                    "context": {"ip": ip, "error": str(exc)},
                }
            )
        )
        return None

    item = resp.get("Item")
    if not item:
        return None

    # Honour TTL even if DynamoDB hasn't expired the item yet
    ttl_val = item.get("ttl", {}).get("N")
    if ttl_val and int(ttl_val) < int(time.time()):
        return None

    raw = {k: _deserializer.deserialize(v) for k, v in item.items()}
    raw.pop("ttl", None)
    try:
        return IPEnrichment(**raw)
    except ValidationError as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "Failed to deserialize cached IPEnrichment",
                    "context": {"ip": ip, "error": str(exc)},
                }
            )
        )
        return None


def set_ip_cache(
    enrichment: IPEnrichment,
    *,
    client: Any | None = None,
) -> None:
    """Write an IPEnrichment to the cache table with a 24 h TTL."""
    ddb = client or _make_client()
    ttl = int(time.time()) + _CACHE_TTL_SECONDS

    item: dict[str, Any] = {k: v for k, v in enrichment.model_dump().items() if v is not None}
    item["ttl"] = ttl

    dynamo_item = {k: _serializer.serialize(v) for k, v in item.items()}

    try:
        ddb.put_item(TableName=_CACHE_TABLE, Item=dynamo_item)
    except (ClientError, BotoCoreError) as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "DynamoDB set_ip_cache failed",
                    "context": {"ip": enrichment.ip, "error": str(exc)},
                }
            )
        )


def put_event(
    event: HoneypotEvent,
    *,
    client: Any | None = None,
) -> None:
    """Persist a HoneypotEvent to the hollownet-events table."""
    ddb = client or _make_client()

    item: dict[str, Any] = {k: v for k, v in event.model_dump().items() if v is not None}
    dynamo_item = {k: _serializer.serialize(v) for k, v in item.items()}

    try:
        ddb.put_item(TableName=_EVENTS_TABLE, Item=dynamo_item)
    except (ClientError, BotoCoreError) as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "DynamoDB put_event failed",
                    "context": {"event_id": event.event_id, "error": str(exc)},
                }
            )
        )
        raise


def _scan_events(
    *,
    ddb: Any,
    src_ip: str | None = None,
    event_type: str | None = None,
    limit: int,
) -> list[dict[str, Any]]:
    """Scan events table with optional filters, up to *limit* items."""
    scan_kwargs: dict[str, Any] = {"TableName": _EVENTS_TABLE, "Limit": limit}
    filters: list[str] = []
    expr_values: dict[str, Any] = {}

    if src_ip:
        filters.append("src_ip = :src_ip")
        expr_values[":src_ip"] = {"S": src_ip}
    if event_type:
        filters.append("event_type = :event_type")
        expr_values[":event_type"] = {"S": event_type}

    if filters:
        scan_kwargs["FilterExpression"] = " AND ".join(filters)
        scan_kwargs["ExpressionAttributeValues"] = expr_values

    items: list[dict[str, Any]] = []
    while len(items) < limit:
        resp = ddb.scan(**scan_kwargs)
        batch = resp.get("Items", [])
        remaining = limit - len(items)
        items.extend(batch[:remaining])

        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) >= limit:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key

    return items


def get_events(
    *,
    src_ip: str | None = None,
    event_type: str | None = None,
    limit: int = 20,
    client: Any | None = None,
) -> list[EnrichedEvent]:
    """Return recent events filtered by src_ip/event_type."""
    ddb = client or _make_client()
    safe_limit = max(1, min(limit, 100))

    items: list[dict[str, Any]]
    if src_ip:
        query_kwargs: dict[str, Any] = {
            "TableName": _EVENTS_TABLE,
            "IndexName": _EVENTS_IP_GSI,
            "KeyConditionExpression": "src_ip = :src_ip",
            "ExpressionAttributeValues": {":src_ip": {"S": src_ip}},
            "Limit": safe_limit,
            "ScanIndexForward": False,
        }
        if event_type:
            query_kwargs["FilterExpression"] = "event_type = :event_type"
            query_kwargs["ExpressionAttributeValues"][":event_type"] = {"S": event_type}

        try:
            resp = ddb.query(**query_kwargs)
            items = resp.get("Items", [])
            return _deserialize_events(items[:safe_limit])
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")
            if error_code not in {"ValidationException", "ResourceNotFoundException"}:
                logger.error(
                    json.dumps(
                        {
                            "level": "error",
                            "msg": "DynamoDB query get_events failed",
                            "context": {
                                "src_ip": src_ip,
                                "event_type": event_type,
                                "limit": safe_limit,
                                "error": str(exc),
                            },
                        }
                    )
                )
                raise
            logger.warning(
                json.dumps(
                    {
                        "level": "warning",
                        "msg": "Falling back to scan for get_events",
                        "context": {"reason": error_code, "src_ip": src_ip},
                    }
                )
            )
        except BotoCoreError as exc:
            logger.error(
                json.dumps(
                    {
                        "level": "error",
                        "msg": "DynamoDB get_events failed",
                        "context": {"error": str(exc)},
                    }
                )
            )
            raise

    try:
        items = _scan_events(
            ddb=ddb,
            src_ip=src_ip,
            event_type=event_type,
            limit=safe_limit,
        )
    except (ClientError, BotoCoreError) as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "DynamoDB scan get_events failed",
                    "context": {
                        "src_ip": src_ip,
                        "event_type": event_type,
                        "limit": safe_limit,
                        "error": str(exc),
                    },
                }
            )
        )
        raise

    return _deserialize_events(items)


def _scan_all_events(*, ddb: Any) -> list[dict[str, Any]]:
    scan_kwargs: dict[str, Any] = {"TableName": _EVENTS_TABLE}
    items: list[dict[str, Any]] = []

    while True:
        resp = ddb.scan(**scan_kwargs)
        items.extend(resp.get("Items", []))

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key

    return items


def get_stats(*, client: Any | None = None) -> StatsResponse:
    """Return dashboard aggregates computed from stored events."""
    ddb = client or _make_client()
    try:
        items = _scan_all_events(ddb=ddb)
    except (ClientError, BotoCoreError) as exc:
        logger.error(
            json.dumps(
                {
                    "level": "error",
                    "msg": "DynamoDB get_stats scan failed",
                    "context": {"error": str(exc)},
                }
            )
        )
        raise

    events = _deserialize_events(items)
    total_events = len(events)
    today_utc = datetime.now(timezone.utc).date()

    events_today = 0
    events_by_type: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    ip_context: dict[str, tuple[str | None, int]] = {}
    credential_counts: Counter[tuple[str, str]] = Counter()

    for event in events:
        try:
            event_date = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00")).date()
            if event_date == today_utc:
                events_today += 1
        except ValueError:
            logger.warning(
                json.dumps(
                    {
                        "level": "warning",
                        "msg": "Invalid timestamp in event while computing stats",
                        "context": {"event_id": event.event_id, "timestamp": event.timestamp},
                    }
                )
            )

        events_by_type[event.event_type] += 1
        ip_counts[event.src_ip] += 1
        ip_context[event.src_ip] = (event.country, event.abuse_score)

        if event.username and event.password:
            credential_counts[(event.username, event.password)] += 1

    top_ips = [
        TopIP(
            ip=ip,
            count=count,
            country=ip_context.get(ip, (None, 0))[0],
            abuse_score=ip_context.get(ip, (None, 0))[1],
        )
        for ip, count in ip_counts.most_common(10)
    ]

    top_credentials = [
        TopCredential(username=username, password=password, count=count)
        for (username, password), count in credential_counts.most_common(10)
    ]

    return StatsResponse(
        total_events=total_events,
        events_today=events_today,
        top_ips=top_ips,
        top_credentials=top_credentials,
        events_by_type=dict(events_by_type),
    )
