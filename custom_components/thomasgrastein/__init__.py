"""The Alpha Smart integration."""
from __future__ import annotations

from asyncio import wrap_future
from datetime import timedelta
import json
import logging
from typing import Any

from awscrt import auth
from awsiot import mqtt, mqtt_connection_builder
from boto3 import client
from pycognito import Cognito
from requests_aws4auth import AWS4Auth

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import httpx_client
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.CLIMATE]

UPDATE_INTERVAL = timedelta(hours=12)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Alpha Smart from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    coordinator = AlphaSmartCoordinator(hass)

    hass.data[DOMAIN][entry.entry_id] = coordinator
    hass.data[DOMAIN]["data"] = entry.data

    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _LOGGER.info("Starting websocket task")

    mqtt_connection = await coordinator.async_websocket_connect()

    def on_message_received(topic, payload, dup, qos, retain, **kwargs):
        # _LOGGER.info("Received message from topic %s: %s", topic, payload)
        # topic userinfo/eu-central-1:6af4f4fc-fc76-4916-babe-47c9f93b3d29/devices/c3c45f32-ca01-4498-bd88-318323af1517/reported: b'{"10":100,"31":21.08,"33":36}'
        device_id = topic.split("/")[3]
        _LOGGER.info("device id: %s", device_id)
        payload_json = payload.decode("utf-8")
        _LOGGER.info("payload: %s", payload_json)
        # self.data[device_id]["30"] = target_temperature
        # map payload to self.data[device_id]
        for key, value in json.loads(payload_json).items():
            coordinator.data[device_id][key] = value
        coordinator.async_update_listeners()

    subscribe_future, _ = mqtt_connection.subscribe(
        topic="userinfo/eu-central-1:6af4f4fc-fc76-4916-babe-47c9f93b3d29/#",
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_message_received,
    )
    res = await wrap_future(subscribe_future)
    _LOGGER.info("res: %s", res)

    hass.data[DOMAIN]["mqtt_connection"] = mqtt_connection

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


class AlphaSmartCoordinator(DataUpdateCoordinator):
    """Class to manage fetching Alpha Smart data."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Alpha Smart."""
        try:
            devices = []
            for device in self.hass.data[DOMAIN]["data"]["devices"]:
                if device["oem"] == "Moehlenhoff":
                    devices.append(device)
            if not devices or len(devices) == 0:
                raise UpdateFailed("No device found")
            httpx_session = httpx_client.get_async_client(self.hass)
            tokens = await self.async_get_auth()
            auth = AWS4Auth(
                tokens["AccessKeyId"],
                tokens["SecretKey"],
                self.hass.data[DOMAIN]["data"]["cloud_info"]["user_pool_region"],
                "execute-api",
                session_token=tokens["SessionToken"],
            )
            httpx_session.auth = auth
            api_endpoint = self.hass.data[DOMAIN]["data"]["cloud_info"]["api_endpoint"]
            obj = {}
            for device in devices:
                url = api_endpoint + "/v1/devices/" + device["deviceId"] + "/values"
                device_values = await httpx_session.get(url)
                device_values_json = device_values.json()
                _LOGGER.debug("device values: %s", device_values_json)
                _LOGGER.info(
                    "last heartbeat for device %s: %s",
                    device_values_json["name"],
                    device_values_json["lastHeartbeatAt"],
                )
                obj[device["deviceId"]] = device_values_json
            return obj
        except ConnectionError as err:
            raise UpdateFailed(f"Error communicating with API: {err}") from err

    async def async_set_target_temperature(
        self, device_id: str, target_temperature: float
    ) -> None:
        """Set the target temperature of the given heat area."""
        _LOGGER.debug(
            "Setting target temperature of device id %s to %0.1f",
            device_id,
            target_temperature,
        )
        httpx_session = httpx_client.get_async_client(self.hass)
        tokens = await self.async_get_auth()
        auth = AWS4Auth(
            tokens["AccessKeyId"],
            tokens["SecretKey"],
            self.hass.data[DOMAIN]["data"]["cloud_info"]["user_pool_region"],
            "execute-api",
            session_token=tokens["SessionToken"],
        )
        httpx_session.auth = auth
        cloud_info = self.hass.data[DOMAIN]["data"]["cloud_info"]
        api_endpoint = cloud_info["api_endpoint"]
        url = api_endpoint + "/v1/devices/" + device_id + "/values"
        payload = {"30": target_temperature}
        await httpx_session.put(url, json=payload)
        self.data[device_id]["30"] = target_temperature
        self.async_update_listeners()

    async def async_websocket_connect(self) -> None:
        """Connect to the websocket."""
        _LOGGER.info("Connecting to websocket")
        tokens = await self.async_get_auth()
        cred_provider = auth.AwsCredentialsProvider.new_static(
            access_key_id=tokens["AccessKeyId"],
            secret_access_key=tokens["SecretKey"],
            session_token=tokens["SessionToken"],
        )

        def on_connection_failure(connection, callback_data):
            assert isinstance(callback_data, mqtt.OnConnectionFailureData)
            _LOGGER.error("Connection failed with error %s", callback_data.error)

        def on_connection_interrupted(connection, error, **kwargs):
            _LOGGER.error("Connection interrupted with error %s", error)

        mqtt_connection = mqtt_connection_builder.websockets_with_default_aws_signing(
            region=self.hass.data[DOMAIN]["data"]["cloud_info"]["user_pool_region"],
            credentials_provider=cred_provider,
            endpoint=self.hass.data[DOMAIN]["data"]["cloud_info"][
                "mqtt_broker_endpoint"
            ],
            client_id="eu-central-1:6af4f4fc-fc76-4916-babe-47c9f93b3d29/dPMS2NjaQAS2jPjZwnu3Tv",
            on_connection_interrupted=on_connection_interrupted,
            on_connection_failure=on_connection_failure,
        )
        connect_future = mqtt_connection.connect()
        res = await wrap_future(connect_future)
        _LOGGER.info("Connected to websocket")
        _LOGGER.info("res: %s", res)

        return mqtt_connection

    async def async_get_auth(self):
        """Renews the auth token if necessary and returns the new credentials."""
        cloud_info = self.hass.data[DOMAIN]["data"]["cloud_info"]
        user_pool_id = cloud_info["user_pool_id"]
        user_pool_region = cloud_info["user_pool_region"]
        client_id = cloud_info["client_id"]
        tokens = self.hass.data[DOMAIN]["data"]["tokens"]

        def get_cognito_client():
            return Cognito(
                user_pool_id,
                client_id,
                id_token=tokens["IdToken"],
                refresh_token=tokens["RefreshToken"],
                access_token=tokens["AccessToken"],
            )

        u = await self.hass.async_add_executor_job(get_cognito_client)
        try:
            await self.hass.async_add_executor_job(u.verify_tokens)
        except Exception:
            _LOGGER.info("Refreshing tokens")
            _LOGGER.info("old id token: %s", tokens["IdToken"])
            await self.hass.async_add_executor_job(u.check_token)
            mergedTokens = self.hass.data[DOMAIN]["data"]["tokens"]
            mergedTokens.update({"IdToken": u.id_token, "AccessToken": u.access_token})
            self.hass.data[DOMAIN]["data"]["tokens"].update(mergedTokens)
            _LOGGER.info(
                "new id token: %s",
                self.hass.data[DOMAIN]["data"]["tokens"]["IdToken"],
            )
        await self.hass.async_add_executor_job(u.verify_tokens)

        def get_identity_client():
            return client("cognito-identity", region_name=user_pool_region)

        identity_client = await self.hass.async_add_executor_job(get_identity_client)

        def temp_credentials():
            return identity_client.get_credentials_for_identity(
                IdentityId=self.hass.data[DOMAIN]["data"]["identity_id"],
                Logins={
                    f"cognito-idp.{user_pool_region}.amazonaws.com/{user_pool_id}": self.hass.data[
                        DOMAIN
                    ]["data"]["tokens"]["IdToken"]
                },
            )

        credentials = await self.hass.async_add_executor_job(temp_credentials)
        _LOGGER.info("credentials: %s", credentials)
        return {
            "AccessKeyId": credentials["Credentials"]["AccessKeyId"],
            "SecretKey": credentials["Credentials"]["SecretKey"],
            "SessionToken": credentials["Credentials"]["SessionToken"],
        }
