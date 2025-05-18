import os
import sys
from aws_cdk import (
    Stack, CfnOutput, aws_iam as iam
)
from constructs import Construct

# === Constants ===
SAML_PROVIDER_NAME = "OKTASAML1"
SAML_AUDIENCE = "https://signin.aws.amazon.com/saml"
OKTA_METADATA_FILE = "okta_metadata.xml"

ROLE_NAMES = {
    "admin": "SE-AWSM-ADMIN",
    "pipeline_admin": "SE-AWSM-PIPELINE-ADMIN",
    "security": "SE-AWSM-Security",
    "ds_ir": "SE-AWSM-DS-Incident-Response",
    #"billing": "SE-AWSM-Billing",
    "read_only": "SE-AWSM-Read-Only",
    "dev_power": "SE-AWSM-Customer-Developer-PowerUser",
    "network_admin": "SE-AWSM-Customer-Network-Admin",
    "db_admin": "SE-AWSM-Customer-Database-Admin",
    "ds_admin": "SE-AWSM-Customer-DataScientist-Admin",
    "sysadmin": "SE-AWSM-Customer-SystemsAdministrator",
    "isso": "SE-AWSM-Customer-ISSO",
    "identity_admin": "SE-AWSM-CUSTOMER-IDENTITY-CM-ADMINS"
}

MANAGED_POLICIES = {
    "AdministratorAccess": "AdministratorAccess",
    "SecurityAudit": "SecurityAudit",
    "IAMFullAccess": "IAMFullAccess",
    "ReadOnlyAccess": "ReadOnlyAccess",
    "PowerUserAccess": "PowerUserAccess",
    "NetworkAdministrator": "AmazonVPCFullAccess",
    "AmazonRDSFullAccess": "AmazonRDSFullAccess",
    "AmazonS3FullAccess": "AmazonS3FullAccess",
    "AmazonEMRFullAccess": "AmazonElasticMapReduceFullAccess",
    "AmazonKinesisFullAccess": "AmazonKinesisFullAccess",
    "AmazonEC2FullAccess": "AmazonEC2FullAccess",
    #"Billing": "job-function/Billing",
    "AmazonAthenaFullAccess": "AmazonAthenaFullAccess",
    "AmazonQuickSightDescribeOnlyAccess": "AmazonQuickSightDescribeOnlyAccess",
    "AWSGlueConsoleFullAccess": "AWSGlueConsoleFullAccess"
}

class OktaSamlStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        metadata_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), OKTA_METADATA_FILE)
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                saml_metadata = f.read()
        except Exception as e:
            print(f"Error reading {OKTA_METADATA_FILE}: {e}")
            sys.exit(1)

        saml_provider = iam.CfnSAMLProvider(
            self, "OKTASAMLProvider",
            name=SAML_PROVIDER_NAME,
            saml_metadata_document=saml_metadata
        )
        CfnOutput(self, "OKTASAMLProviderARN", value=saml_provider.attr_arn)

        def saml_federated_principal():
            return iam.FederatedPrincipal(
                federated=saml_provider.attr_arn,
                conditions={"StringEquals": {"SAML:aud": SAML_AUDIENCE}},
                assume_role_action="sts:AssumeRoleWithSAML"
            )

        def output_role(role, name):
            CfnOutput(self, f"{name}-ARN", value=role.role_arn)

        for name, role_name in ROLE_NAMES.items():
            if name == "pipeline_admin":
                role = iam.Role(
                    self, role_name,
                    role_name=role_name,
                    assumed_by=iam.ServicePrincipal("codepipeline.amazonaws.com"),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES["AdministratorAccess"])
                    ]
                )
            elif name == "ds_admin":
                role = iam.Role(
                    self, role_name,
                    role_name=role_name,
                    assumed_by=saml_federated_principal(),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES["AmazonEMRFullAccess"]),
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES["AmazonAthenaFullAccess"]),
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES["AmazonEC2FullAccess"]),
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES["AmazonKinesisFullAccess"]),
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES["AWSGlueConsoleFullAccess"])
                    ]
                )
            elif name == "identity_admin":
                role = iam.Role(
                    self, role_name,
                    role_name=role_name,
                    assumed_by=saml_federated_principal()
                )
                identity_admin_policy = iam.Policy(self, "IdentityAdminPolicy",
                    policy_name="SE-AWSM-IdentityAdmin-Custom",
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "elasticloadbalancing:DescribeLoadBalancers",
                                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                                "iam:PassRole",
                                "iam:GetRole",
                                "iam:ListRoleTags",
                                "iam:TagRole",
                                "iam:UntagRole"
                            ],
                            resources=["*"]
                        )
                    ]
                )
                identity_admin_policy.attach_to_role(role)
            else:
                policies = {
                    "admin": ["AdministratorAccess"],
                    "security": ["ReadOnlyAccess", "SecurityAudit", "IAMFullAccess"],
                    "ds_ir": ["ReadOnlyAccess"],
                    #"billing": ["SecurityAudit", "Billing"],
                    "read_only": ["ReadOnlyAccess"],
                    "dev_power": ["PowerUserAccess", "IAMFullAccess"],
                    "network_admin": ["NetworkAdministrator"],
                    "db_admin": ["AmazonRDSFullAccess"],
                    "sysadmin": ["AmazonEC2FullAccess"],
                    "isso": ["ReadOnlyAccess", "SecurityAudit"]
                }.get(name, [])

                role = iam.Role(
                    self, role_name,
                    role_name=role_name,
                    assumed_by=saml_federated_principal(),
                    managed_policies=[
                        iam.ManagedPolicy.from_aws_managed_policy_name(MANAGED_POLICIES[p])
                        for p in policies
                    ]
                )
            output_role(role, role_name)
