"""SNS alert infrastructure for Hollownet — Telegram notifications."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_sns as sns
from constructs import Construct


class AlertStack(cdk.Stack):
    """Creates the hollownet-alerts SNS topic for threat notifications."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        alert_topic = sns.Topic(
            self,
            "AlertTopic",
            topic_name="hollownet-alerts",
            display_name="Hollownet Threat Alerts",
        )

        cdk.Tags.of(alert_topic).add("project", "hollownet")
        cdk.Tags.of(alert_topic).add("env", "prod")

        cdk.CfnOutput(
            self,
            "AlertTopicArn",
            value=alert_topic.topic_arn,
            export_name="AlertTopicArn",
            description="ARN of the Hollownet SNS alert topic",
        )

        self.alert_topic = alert_topic
