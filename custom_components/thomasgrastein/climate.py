import logging

from homeassistant.components.climate import ClimateEntity, ClimateEntityFeature
from homeassistant.components.climate.const import HVACMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import AlphaSmartCoordinator
from .const import DOMAIN, PRESET_AUTO, PRESET_MANUAL

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add AlphaSmartClimate entities from a config_entry."""
    coordinator: AlphaSmartCoordinator = hass.data[DOMAIN][config_entry.entry_id]
    collect = []
    for device in hass.data[DOMAIN]["data"]["devices"]:
        if device["oem"] == "Moehlenhoff" and device["deviceId"] not in [
            "5f5ad901-e014-4c55-94c9-fd8d4e96bf0d",
            "c32401c5-a65c-4be8-8099-187a5bfea52a",
        ]:
            collect.append(AlphaSmartClimate(coordinator, device["deviceId"]))
    async_add_entities(collect)


class AlphaSmartClimate(CoordinatorEntity[AlphaSmartCoordinator], ClimateEntity):
    """Alpha Smart ClimateEntity."""

    target_temperature_step = 0.1

    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE | ClimateEntityFeature.PRESET_MODE
    )
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_preset_modes = [PRESET_AUTO, PRESET_MANUAL]
    _attr_hvac_modes = [HVACMode.HEAT]

    def __init__(self, coordinator: AlphaSmartCoordinator, device_id: str) -> None:
        """Initialize Alpha Smart ClimateEntity."""
        super().__init__(coordinator)
        self._attr_unique_id = device_id
        self._attr_name = coordinator.data[self.unique_id]["name"]

    @property
    def min_temp(self) -> float:
        """Return the minimum temperature."""
        return float(0)

    @property
    def max_temp(self) -> float:
        """Return the maximum temperature."""
        return float(40)

    @property
    def current_temperature(self) -> float:
        """Return the current temperature."""
        return self.coordinator.data[self.unique_id]["31"]

    @property
    def target_temperature(self) -> float:
        """Return the temperature we try to reach."""
        return self.coordinator.data[self.unique_id]["30"]

    @property
    def preset_mode(self) -> str:
        """Return the current preset mode."""
        return PRESET_MANUAL

    @property
    def hvac_mode(self) -> HVACMode:
        """Return current hvac mode."""
        return HVACMode.HEAT

    @property
    def current_humidity(self) -> float:
        """Return the current humidity."""
        return self.coordinator.data[self.unique_id]["33"]

    async def async_set_temperature(self, **kwargs) -> None:
        """Set new target temperature."""
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            return
        await self.coordinator.async_set_target_temperature(self.unique_id, temperature)
