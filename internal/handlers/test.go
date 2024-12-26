package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/ghostsecurity/reaper/internal/tools/testing"
)

// CreateTestWorkflow creates a new test workflow
func (h *Handler) CreateTestWorkflow(c *fiber.Ctx) error {
	var workflow testing.TestWorkflow
	if err := c.BodyParser(&workflow); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	manager := testing.NewWorkflowManager(h.db)
	if err := manager.CreateWorkflow(&workflow); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(workflow)
}

// ExecuteTestWorkflow starts execution of a test workflow
func (h *Handler) ExecuteTestWorkflow(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid workflow ID",
		})
	}

	manager := testing.NewWorkflowManager(h.db)
	if err := manager.ExecuteWorkflow(uint(id)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.SendStatus(fiber.StatusOK)
}

// GetTestWorkflow retrieves a test workflow by ID
func (h *Handler) GetTestWorkflow(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid workflow ID",
		})
	}

	manager := testing.NewWorkflowManager(h.db)
	workflow, err := manager.GetWorkflow(uint(id))
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Workflow not found",
		})
	}

	return c.JSON(workflow)
}

// GetTestFindings retrieves findings for a test workflow
func (h *Handler) GetTestFindings(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid workflow ID",
		})
	}

	manager := testing.NewWorkflowManager(h.db)
	findings, err := manager.GetFindings(uint(id))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(findings)
}
