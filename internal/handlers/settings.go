package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ghostsecurity/reaper/internal/database/models"
)

// GetSettings retrieves the global settings
func (h *Handler) GetSettings(c *fiber.Ctx) error {
	settings, err := h.db.GetSettings()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return c.JSON(settings)
}

// UpdateSettings updates the global settings
func (h *Handler) UpdateSettings(c *fiber.Ctx) error {
	var settings models.Settings
	if err := c.BodyParser(&settings); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.db.UpdateSettings(&settings); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(settings)
}
