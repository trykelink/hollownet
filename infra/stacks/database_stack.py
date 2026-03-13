"""DynamoDB tables for Hollownet — events store and IP enrichment cache."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_dynamodb as dynamodb
from constructs import Construct


class DatabaseStack(cdk.Stack):
    """Creates hollownet-events and hollownet-ip-cache DynamoDB tables."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ------------------------------------------------------------------ #
        # Table 1: hollownet-events                                           #
        # ------------------------------------------------------------------ #
        events_table = dynamodb.Table(
            self,
            "EventsTable",
            table_name="hollownet-events",
            partition_key=dynamodb.Attribute(
                name="event_id",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            time_to_live_attribute="ttl",
        )

        events_table.add_global_secondary_index(
            index_name="src_ip-index",
            partition_key=dynamodb.Attribute(
                name="src_ip",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING,
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        cdk.Tags.of(events_table).add("project", "hollownet")
        cdk.Tags.of(events_table).add("env", "prod")

        # ------------------------------------------------------------------ #
        # Table 2: hollownet-ip-cache                                         #
        # ------------------------------------------------------------------ #
        ip_cache_table = dynamodb.Table(
            self,
            "IpCacheTable",
            table_name="hollownet-ip-cache",
            partition_key=dynamodb.Attribute(
                name="ip",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            time_to_live_attribute="ttl",
        )

        cdk.Tags.of(ip_cache_table).add("project", "hollownet")
        cdk.Tags.of(ip_cache_table).add("env", "prod")

        # Expose for cross-stack references if needed later
        self.events_table = events_table
        self.ip_cache_table = ip_cache_table
