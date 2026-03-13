"""DynamoDB client wrapper — cache reads/writes and event persistence."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from collector.models import HoneypotEvent, IPEnrichment

logger = logging.getLogger(__name__)

_CACHE_TABLE = "hollownet-ip-cache"
_EVENTS_TABLE = "hollownet-events"
_REGION = "us-east-1"
_CACHE_TTL_SECONDS = 86_400  # 24 h

_deserializer = TypeDeserializer()
_serializer = TypeSerializer()


def _make_client(profile: str | None = None) -> Any:
    """Create a DynamoDB low-level client with the configured profile."""
    session = boto3.Session(
        region_name=_REGION,
        profile_name=profile or os.environ.get("AWS_PROFILE", "hollownet"),
    )
    return session.client("dynamodb")


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
    except Exception as exc:
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
    except Exception as exc:
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
    except Exception as exc:
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
    except Exception as exc:
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
