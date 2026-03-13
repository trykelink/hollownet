"""S3 buckets for Hollownet — dataset, ML models, and dashboard."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_s3 as s3
from constructs import Construct


class StorageStack(cdk.Stack):
    """Creates hollownet-dataset, hollownet-models, and hollownet-dashboard S3 buckets."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = cdk.Stack.of(self).account

        # ------------------------------------------------------------------ #
        # Bucket 1: hollownet-dataset-{account}                               #
        # Training data exports — moves to Glacier after 90 days.            #
        # ------------------------------------------------------------------ #
        dataset_bucket = s3.Bucket(
            self,
            "DatasetBucket",
            bucket_name=f"hollownet-dataset-{account}",
            versioned=False,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="archive-to-glacier",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=cdk.Duration.days(90),
                        )
                    ],
                )
            ],
        )

        cdk.Tags.of(dataset_bucket).add("project", "hollownet")
        cdk.Tags.of(dataset_bucket).add("env", "prod")

        # ------------------------------------------------------------------ #
        # Bucket 2: hollownet-models-{account}                                #
        # Versioned — each retrain uploads a new model version.              #
        # ------------------------------------------------------------------ #
        models_bucket = s3.Bucket(
            self,
            "ModelsBucket",
            bucket_name=f"hollownet-models-{account}",
            versioned=True,
            removal_policy=cdk.RemovalPolicy.RETAIN,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )

        cdk.Tags.of(models_bucket).add("project", "hollownet")
        cdk.Tags.of(models_bucket).add("env", "prod")

        # ------------------------------------------------------------------ #
        # Bucket 3: hollownet-dashboard-{account}                             #
        # Static website hosting — CloudFront will sit in front.             #
        # ------------------------------------------------------------------ #
        dashboard_bucket = s3.Bucket(
            self,
            "DashboardBucket",
            bucket_name=f"hollownet-dashboard-{account}",
            versioned=False,
            removal_policy=cdk.RemovalPolicy.DESTROY,
            # Public access allowed so CloudFront can serve the assets.
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=False,
                block_public_policy=False,
                ignore_public_acls=False,
                restrict_public_buckets=False,
            ),
            website_index_document="index.html",
            website_error_document="404.html",
        )

        cdk.Tags.of(dashboard_bucket).add("project", "hollownet")
        cdk.Tags.of(dashboard_bucket).add("env", "prod")

        # Expose for cross-stack references
        self.dataset_bucket = dataset_bucket
        self.models_bucket = models_bucket
        self.dashboard_bucket = dashboard_bucket
