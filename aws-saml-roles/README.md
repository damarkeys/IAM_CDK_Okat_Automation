# IAM_CDK_Okat_Automation


# Okta SAML AWS CDK Stack

This project provisions an AWS SAML Identity Provider and a set of IAM roles for Okta SAML federation using AWS CDK v2 (Python).
## Prerequisiteis

1- Install aws cli v2. Setup your account using 
```sh
aws configure
```
2- Install the cdk using npm.
```sh
npm install -g cdk
```
3- Create the python venv.
```sh
python -m venv venv
.\venv\Scripts\Activate.ps1 #windows powershell
source venv/bin/activate #linux
```
## Structure

- `app.py`: CDK app entry point
- `okta_saml/okta_saml_stack.py`: Main stack definition
- `okta_metadata.xml`: Okta SAML metadata (place your file here)
- `requirements.txt`: Python dependencies
- `cdk.json`: CDK configuration

## Usage

1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
2. Place your `okta_metadata.xml` in the project root.
3. Synthesize the stack:
   ```sh
   cdk synth
   ```
4. Deploy:
   ```sh
   cdk deploy
   ```
