# Secure Coding - Preventing Sensitive Data Exposure (Hardcoded Secrets)
# This code demonstrates how to prevent hardcoded secrets in Python applications.


# Import necessary libraries
import boto3 # Requires: pip install boto3
import botocore.exceptions
import json
import sys
import os


# Step 1:

# --- Reading Secrets from Environment Variables ---
# This is a common and recommended pattern.
# Secrets are set in the environment where the script runs,
# NOT hardcoded here.

# Example: Get an API key from an environment variable named 'MY_API_KEY'
# os.environ.get() is safer than os.environ[] as it returns None if the
# variable is not found, instead of raising a KeyError.
api_key = os.environ.get('MY_API_KEY')

# Example: Get a database password, providing a default value (use cautiously)
# Providing defaults might be okay for non-sensitive config, but generally
# avoid defaulting sensitive secrets. It's better to fail if a secret is missing.
db_password = os.environ.get('DB_PASSWORD') # No default, will be None if not set

# --- Usage Example ---

if api_key:
    print(f"Successfully retrieved API Key (length): {len(api_key)}")
    # Use the api_key for your application logic...
    # e.g., connect_to_service(api_key)
else:
    print("Error: Environment variable 'MY_API_KEY' not found.", file=sys.stderr)
    # Handle the error appropriately - maybe exit the application
    # sys.exit("Application cannot start without MY_API_KEY")


if db_password:
    print(f"Successfully retrieved DB Password (length): {len(db_password)}")
    # Use the db_password...
    # e.g., db_connect(user='admin', password=db_password)
else:
    # It's often better to raise an error or exit if a required secret is missing
    print("Error: Environment variable 'DB_PASSWORD' not found.", file=sys.stderr)
    # sys.exit("Application cannot start without DB_PASSWORD")

# --- How to Set Environment Variables (Examples) ---
# Linux/macOS (in terminal):
# export MY_API_KEY="your_actual_api_key_value"
# export DB_PASSWORD="your_actual_db_password"
# python your_script.py
#
# Windows (Command Prompt):
# set MY_API_KEY="your_actual_api_key_value"
# set DB_PASSWORD="your_actual_db_password"
# python your_script.py
#
# Windows (PowerShell):
# $env:MY_API_KEY="your_actual_api_key_value"
# $env:DB_PASSWORD="your_actual_db_password"
# python your_script.py
#
# Dockerfile:
# ENV MY_API_KEY="value_set_at_build_time_or_runtime"
# ENV DB_PASSWORD="value_set_at_build_time_or_runtime"
#
# Kubernetes (Deployment YAML):
# env:
# - name: MY_API_KEY
#   valueFrom:
#     secretKeyRef:
#       name: my-secrets # Name of the K8s Secret object
#       key: api-key     # Key within the Secret object


# Step 2  Identifying Hardcoded Secrets

# --- Reading Secrets from AWS Secrets Manager ---
# This is a robust pattern for cloud environments (AWS).
# Assumes your environment (e.g., EC2 instance, Lambda, ECS task) has
# appropriate IAM permissions to call secretsmanager:GetSecretValue.
# No AWS credentials should be hardcoded here. Boto3 will automatically
# find credentials from IAM roles, environment variables, or config files.

# Specify the name or ARN of the secret in Secrets Manager
# It's good practice to get this from an environment variable rather than hardcoding
secret_name = os.environ.get("MY_APP_SECRET_NAME", "my/application/secrets") # Example: Read name from env var
region_name = os.environ.get("AWS_REGION", "us-east-1") # Get region from standard env var or default

# Create a Secrets Manager client
# Ensure the region is correctly specified
session = boto3.session.Session()
client = session.client(
    service_name='secretsmanager',
    region_name=region_name
)

# --- Function to Retrieve Secret ---
def get_secret(secret_name, region_name):
    """Retrieves a secret value from AWS Secrets Manager."""
    try:
        print(f"Attempting to retrieve secret: {secret_name} from region: {region_name}")
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        print("Successfully called GetSecretValue API.")
    except botocore.exceptions.ClientError as e:
        print(f"Error retrieving secret '{secret_name}': {e}", file=sys.stderr)
        # Handle specific exceptions based on your needs
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            print("Decryption failure.", file=sys.stderr)
        elif error_code == 'InternalServiceErrorException':
            # An error occurred on the server side.
            print("Internal service error.", file=sys.stderr)
        elif error_code == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            print("Invalid parameter.", file=sys.stderr)
        elif error_code == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            print("Invalid request.", file=sys.stderr)
        elif error_code == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            print(f"Secret '{secret_name}' not found.", file=sys.stderr)
        else:
            # Handle other potential errors
            print(f"Unhandled ClientError: {error_code}", file=sys.stderr)
        return None # Return None on error
    except Exception as e:
        print(f"An unexpected error occurred during secret retrieval: {e}", file=sys.stderr)
        return None # Return None on unexpected error
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret_data = get_secret_value_response['SecretString']
            print("Secret retrieved as string.")
            return secret_data
        elif 'SecretBinary' in get_secret_value_response:
            # If the secret was stored as binary data
            decoded_binary_secret = get_secret_value_response['SecretBinary']
            print("Secret retrieved as binary data.")
            return decoded_binary_secret # Return the raw bytes
        else:
            print("Warning: Secret value response did not contain SecretString or SecretBinary.", file=sys.stderr)
            return None


# --- Usage Example ---

secret_value = get_secret(secret_name, region_name)

if secret_value:
    try:
        # Attempt to parse if it's a JSON string (common practice)
        secrets_dict = json.loads(secret_value)
        api_key = secrets_dict.get('MY_API_KEY') # Use .get() for safety
        db_password = secrets_dict.get('DB_PASSWORD')

        if api_key:
            print(f"Successfully parsed API Key from Secrets Manager (length): {len(api_key)}")
            # Use the api_key...
        else:
            print("API Key not found within the retrieved secret JSON.", file=sys.stderr)

        if db_password:
            print(f"Successfully parsed DB Password from Secrets Manager (length): {len(db_password)}")
            # Use the db_password...
        else:
            print("DB Password not found within the retrieved secret JSON.", file=sys.stderr)

    except json.JSONDecodeError:
        # Handle cases where the secret is not a JSON string (e.g., just a plain password)
        print("Retrieved secret is not valid JSON. Using the raw value.")
        # Use the raw secret_value directly if appropriate
        # Example: treat the whole string as the password
        # db_password = secret_value
        # print(f"Using raw secret value (length): {len(secret_value)}")

    except Exception as e:
        print(f"An error occurred processing the parsed secret: {e}", file=sys.stderr)
else:
    print(f"Could not retrieve secret '{secret_name}'. Application cannot proceed.", file=sys.stderr)
    # Handle the failure appropriately (e.g., exit)
    sys.exit(f"Failed to retrieve critical secret: {secret_name}")


# Step 3: Securely Store Secrets

# The code artifact currently open, titled "Python: Reading from AWS Secrets Manager" (id="python_aws_read_secret"), shows the Python code for securely retrieving secrets using AWS Secrets Manager.
# This corresponds directly to the third major secure pattern discussed in Section 3 of the playbook: Secrets Management Systems. It's the code you would typically use in your Python application running on AWS to avoid hardcoding secrets."

# Step 4 Prevention Strategies

# Focuses on integrating tools, establishing processes, and educating developers, rather than writing specific Python application code.

# Here's a breakdown of why there isn't a direct Python code block for this step:

# Automated Detection (Pre-Commit Hooks & CI/CD):

# This involves configuring external tools like gitleaks or TruffleHog and integrating them into your development workflow.
# Configuration is typically done using YAML files (e.g., .pre-commit-config.yaml for hooks, GitHub Actions/GitLab CI YAML files for pipelines), not Python scripts within your main application. These YAML files define when and how to run the scanning tools against your codebase.
# Developer Education & Security Culture:

# This involves training sessions, documentation, and fostering awareness – purely human and process elements.
# Policies and Standards:

# These are organizational documents defining rules and expectations.
# Secure Development Practices:

# This includes mandatory code reviews (process), using secure project templates (setup/tooling), and managing repository access (permissions).
# While you could write utility scripts in Python to help manage some of these processes (e.g., a script to check if pre-commit hooks are installed), there isn't a core Python code component for Step 4 that belongs in the application itself, unlike the code needed to securely read secrets (Step 3).

# Step 5: Remediation Guide - Responding to Found Secrets
# outlines the overall process for dealing with a discovered hardcoded secret. It involves several actions:

# Triage (Step 5.1): Analysis and investigation (no specific application code).
# Rotation (Step 5.2): Actions in the secret's source system (e.g., AWS console/API, database) and updating the secure storage (like the conceptual script python_aws_update_secret shown earlier).
# Removal from Code (Step 5.3): This is where you modify your application's Python code. You replace the hardcoded secret with code that securely retrieves it, using one of the patterns from Section 3. For example, you would use the code shown in the artifact "Python: Reading from AWS Secrets Manager" (id="python_aws_read_secret") if you were migrating the secret to AWS Secrets Manager.
# Removal from History (Step 5.4): Using external Git tools (no application code).
# Post-Mortem (Step 5.5): Analysis and process improvement (no application code).
# So, there isn't a new Python code block specifically for Step 5. Instead, Step 5.3 involves applying the relevant code from Section 3 (like the AWS Secrets Manager example already provided) to fix the hardcoded value in your application.
