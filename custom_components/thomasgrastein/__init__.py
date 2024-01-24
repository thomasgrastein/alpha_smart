"""The Alpha Smart integration."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

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

UPDATE_INTERVAL = timedelta(seconds=300)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Alpha Smart from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    coordinator = AlphaSmartCoordinator(hass)

    hass.data[DOMAIN][entry.entry_id] = coordinator
    hass.data[DOMAIN]["data"] = entry.data

    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

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
            # find the first device with oem "Moehnlenhoff"
            # devices = next(
            #     device
            #     for device in self.hass.data[DOMAIN]["data"]["devices"]
            #     if device["oem"] == "Moehlenhoff"
            # )
            # if not device:
            #     raise UpdateFailed("No device found")
            # get moehlenhoff devices
            devices = []
            for device in self.hass.data[DOMAIN]["data"]["devices"]:
                if device["oem"] == "Moehlenhoff":
                    devices.append(device)
            if not devices or len(devices) == 0:
                raise UpdateFailed("No device found")

            cloud_info = self.hass.data[DOMAIN]["data"]["cloud_info"]
            user_pool_id = cloud_info["user_pool_id"]
            user_pool_region = cloud_info["user_pool_region"]
            client_id = cloud_info["client_id"]
            api_endpoint = cloud_info["api_endpoint"]
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
            except Exception as e:
                _LOGGER.error(e)
                await self.hass.async_add_executor_job(u.check_token)
                self.hass.data[DOMAIN]["data"]["tokens"]["IdToken"] = u.id_token
                self.hass.data[DOMAIN]["data"]["tokens"]["AccessToken"] = u.access_token
            await self.hass.async_add_executor_job(u.verify_tokens)

            def get_identity_client():
                return client("cognito-identity", region_name=user_pool_region)

            identity_client = await self.hass.async_add_executor_job(
                get_identity_client
            )

            def temp_credentials():
                return identity_client.get_credentials_for_identity(
                    IdentityId=self.hass.data[DOMAIN]["data"][
                        "identity_id"
                    ],  # Still need to figure out where this is from
                    Logins={
                        f"cognito-idp.{user_pool_region}.amazonaws.com/{user_pool_id}": self.hass.data[
                            DOMAIN
                        ]["data"]["tokens"]["IdToken"]
                    },
                )

            credentials = await self.hass.async_add_executor_job(temp_credentials)
            # _LOGGER.info(credentials)
            auth = AWS4Auth(
                credentials["Credentials"]["AccessKeyId"],
                credentials["Credentials"]["SecretKey"],
                user_pool_region,
                "execute-api",
                session_token=credentials["Credentials"]["SessionToken"],
            )
            httpx_session = httpx_client.get_async_client(self.hass)
            httpx_session.auth = auth
            # url = api_endpoint + "/v1/devices/" + device["deviceId"] + "/values"
            # device_values = await httpx_session.get(url)
            # device_values_json = device_values.json()
            # fetch for each device
            obj = {}
            for device in devices:
                url = api_endpoint + "/v1/devices/" + device["deviceId"] + "/values"
                device_values = await httpx_session.get(url)
                device_values_json = device_values.json()
                obj[device["deviceId"]] = device_values_json
            return obj
        except ConnectionError as err:
            raise UpdateFailed(f"Error communicating with API: {err}") from err
