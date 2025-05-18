#!/usr/bin/env python3
import aws_cdk as cdk
from okta_saml.okta_saml_stack import OktaSamlStack

app = cdk.App()
OktaSamlStack(app, "OktaSamlStack")
app.synth() 