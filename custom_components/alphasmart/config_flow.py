"""Config flow for Alpha Smart integration."""
from __future__ import annotations

import logging
from typing import Any

from boto3 import client
from pycognito.aws_srp import AWSSRP
from requests_aws4auth import AWS4Auth
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import httpx_client

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)
STEP_USER_DATA_SCHEMA = vol.Schema(
    {vol.Required(CONF_USERNAME): str, vol.Required(CONF_PASSWORD): str}
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """

    # If your PyPI package is not built with async, pass your methods
    # to the executor:
    # await hass.async_add_executor_job(
    #     your_validate_func, data[CONF_USERNAME], data[CONF_PASSWORD]
    # )
    httpx_session = httpx_client.get_async_client(hass)

    cloud_info = await httpx_session.get(
        "https://iot-prod-config.s3.eu-central-1.amazonaws.com/v1.json",
    )
    _LOGGER.debug(cloud_info)
    cloud_info_json = cloud_info.json()
    api_endpoint = cloud_info_json["endpoint"]
    user_pool_id = cloud_info_json["cognito"]["alphaSmart"]["userPoolId"]
    user_pool_region = cloud_info_json["region"]
    client_id = cloud_info_json["cognito"]["alphaSmart"]["webClientId"]
    identity_pool_id = cloud_info_json["cognito"]["alphaSmart"]["identityPoolId"]
    mqtt_broker_endpoint = cloud_info_json["mqttBrokerEndpoint"]

    def get_idp_client():
        return client("cognito-idp", region_name=user_pool_region)

    idp_client = await hass.async_add_executor_job(get_idp_client)
    aws_srp = AWSSRP(
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
        user_pool_id,
        client_id,
        client=idp_client,
    )
    tokens = await hass.async_add_executor_job(aws_srp.authenticate_user)
    if not tokens["AuthenticationResult"]:
        raise InvalidAuth

    def get_identity_client():
        return client("cognito-identity", region_name=user_pool_region)

    identity_client = await hass.async_add_executor_job(get_identity_client)

    def get_identity_id():
        return identity_client.get_id(
            IdentityPoolId=identity_pool_id,
            Logins={
                f"cognito-idp.{user_pool_region}.amazonaws.com/{user_pool_id}": tokens[
                    "AuthenticationResult"
                ]["IdToken"]
            },
        )

    identity_id = await hass.async_add_executor_job(get_identity_id)
    _LOGGER.info(identity_id)

    def temp_credentials():
        return identity_client.get_credentials_for_identity(
            IdentityId=identity_id["IdentityId"],
            Logins={
                f"cognito-idp.{user_pool_region}.amazonaws.com/{user_pool_id}": tokens[
                    "AuthenticationResult"
                ]["IdToken"]
            },
        )

    credentials = await hass.async_add_executor_job(temp_credentials)
    if not credentials["Credentials"]:
        raise InvalidAuth
    _LOGGER.debug(credentials)
    auth = AWS4Auth(
        credentials["Credentials"]["AccessKeyId"],
        credentials["Credentials"]["SecretKey"],
        user_pool_region,
        "execute-api",
        session_token=credentials["Credentials"]["SessionToken"],
    )
    httpx_session.auth = auth
    devices = await httpx_session.get(
        api_endpoint + "/v1/devices",
    )
    devices_json = devices.json()
    _LOGGER.debug(devices_json)
    return {
        "title": "Alpha Smart",
        "tokens": tokens["AuthenticationResult"],
        "credentials": credentials["Credentials"],
        "devices": devices_json,
        "cloud_info": {
            "api_endpoint": api_endpoint,
            "user_pool_id": user_pool_id,
            "user_pool_region": user_pool_region,
            "client_id": client_id,
            "mqtt_broker_endpoint": mqtt_broker_endpoint,
        },
        "identity_id": identity_id["IdentityId"],
    }


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Alpha Smart."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=info)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
