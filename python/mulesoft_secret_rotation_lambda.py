"""Update Mulesoft password from Secrets Manager"""

import os
import logging
import base64
import json
import requests
import boto3
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_secret(secret_name, region_name="us-east-1"):
    """
    Create a Secrets Manager client and retrieve the secret.

    Args:
        secret_name (str): The name of the secret to retrieve.
        region_name (str): The AWS region where the secret is stored.

    Returns:
        str: The secret value as a JSON string if 'SecretString' is present,
             or a base64-decoded binary string if 'SecretBinary' is present.
    """
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        logger.error("Error retrieving secret '%s': %s", secret_name, e)
        raise e
    else:
        # Decrypts secret using the associated KMS CMK
        # Depending on whether the secret is a string or binary,
        # one of these fields will be populated
        if "SecretString" in get_secret_value_response:
            try:
                return json.loads(get_secret_value_response["SecretString"])
            except json.JSONDecodeError as e:
                logger.error("Error decoding JSON from SecretString: %s", e)
                raise e
        else:
            try:
                return base64.b64decode(
                    get_secret_value_response["SecretBinary"]
                ).decode("utf-8")
            except UnicodeDecodeError as e:
                logger.error("Error decoding SecretBinary as UTF-8: %s", e)
                raise e


def update_mulesoft_configuration(mulesoft_api_url, mulesoft_api_key, new_password):
    """
    Update the MuleSoft password using the provided API URL, API key, and new password.

    Args:
        mulesoft_api_url (str): The URL of the MuleSoft API endpoint.
                                Expected format: 'https://<domain>/api/<endpoint>'.
        mulesoft_api_key (str): The API key for authenticating with the MuleSoft API.
                                Expected format: A valid alphanumeric string.
        new_password (str): The new password to be set in the MuleSoft configuration.
                            Expected format: A non-empty string.

    Raises:
        requests.exceptions.RequestException: If the API request fails.
    """
    headers = {"X-ANYPNT-KEY": mulesoft_api_key, "Content-Type": "application/json"}

    # Validate the format of the MuleSoft API URL
    if not mulesoft_api_url.startswith("https://") or "/api/" not in mulesoft_api_url:
        error_message = f"Invalid MuleSoft API URL format: {mulesoft_api_url}. The URL must start with 'https://' and contain '/api/'."
        logger.error(error_message)
        raise ValueError(error_message)

    try:
        timeout = int(os.environ.get("REQUEST_TIMEOUT", 10))
    except ValueError:
        logger.warning(
            "Invalid REQUEST_TIMEOUT value. Falling back to default timeout of 10 seconds."
        )
        timeout = 10

    data = {"password": new_password}

    try:
        timeout = int(os.environ.get("REQUEST_TIMEOUT", 10))
        response = requests.put(
            mulesoft_api_url, headers=headers, json=data, timeout=timeout
        )
        response.raise_for_status()
        logger.info("Updated MuleSoft configuration successfully.")

    except requests.exceptions.RequestException as e:
        logger.error("Error updating MuleSoft configuration: %s", e)
        raise e


def lambda_handler(event, context):
    """Retrieve and validate required environment variables"""
    secret_name = os.environ.get("SECRET_NAME")
    if not secret_name:
        logger.error("Environment variable 'SECRET_NAME' is required but not set.")
        raise ValueError("Environment variable 'SECRET_NAME' is required but not set.")

    mulesoft_api_url = os.environ.get("MULESOFT_API_URL")
    if (
        not mulesoft_api_url
        or not mulesoft_api_url.startswith("https://")
        or "/api/" not in mulesoft_api_url
    ):
        logger.error("Invalid or missing environment variable: MULESOFT_API_URL")
        raise ValueError(
            "The environment variable 'MULESOFT_API_URL' must be set, start with 'https://', and contain '/api/'."
        )

    mulesoft_api_key = os.environ.get("MULESOFT_API_KEY")
    if not mulesoft_api_key:
        logger.error("Environment variable 'MULESOFT_API_KEY' is required but not set.")
        raise ValueError(
            "Environment variable 'MULESOFT_API_KEY' is required but not set."
        )

    region_name = os.environ.get("REGION_NAME", "us-east-1")

    # Retrieve the password from AWS Secrets Manager
    new_password = get_secret(secret_name, region_name)

    # Update MuleSoft configuration
    try:
        update_mulesoft_configuration(mulesoft_api_url, mulesoft_api_key, new_password)
    except Exception as e:
        logger.error("Failed to update MuleSoft configuration: %s", e)
        raise e
    update_mulesoft_configuration(mulesoft_api_url, mulesoft_api_key, new_password)
