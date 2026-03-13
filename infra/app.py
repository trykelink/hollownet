#!/usr/bin/env python3
"""CDK app entry point for Hollownet infrastructure."""

from __future__ import annotations

import os

import aws_cdk as cdk

from stacks.alert_stack import AlertStack
from stacks.database_stack import DatabaseStack
from stacks.storage_stack import StorageStack

app = cdk.App()

env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=os.environ.get("CDK_DEFAULT_REGION"),
)

DatabaseStack(app, "HollownetDatabase", env=env)
StorageStack(app, "HollownetStorage", env=env)
AlertStack(app, "HollownetAlerts", env=env)

app.synth()
