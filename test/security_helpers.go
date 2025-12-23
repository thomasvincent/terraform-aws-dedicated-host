package test

import (
	"fmt"
	"strings"
	"time"
)

// SecurityConstants defines security-related constants
const (
	MinMaintenanceWindowDuration = 1  // hours
	MaxMaintenanceWindowDuration = 24 // hours
	MinEvaluationPeriods         = 2
	DefaultMetricPeriod          = 60 // seconds
)

// Required tag sets for different compliance levels
var (
	BaseRequiredTags = []string{
		"Environment",
		"Project",
		"ManagedBy",
		"CostCenter",
	}

	ComplianceRequiredTags = []string{
		"Confidentiality",
		"Compliance",
		"SecurityContact",
		"DataClassification",
	}

	ValidConfidentialityLevels = []string{
		"public",
		"internal",
		"confidential",
		"restricted",
	}

	ValidComplianceFrameworks = []string{
		"pci-dss",
		"hipaa",
		"sox",
		"gdpr",
		"iso27001",
	}

	ValidDataClassifications = []string{
		"public",
		"internal",
		"confidential",
		"restricted",
	}
)

// SecurityValidationHelper provides utility functions for security validation
type SecurityValidationHelper struct {
	RequiredTags           []string
	ComplianceTags         []string
	ValidInstanceFamilies  []string
	ValidInstanceTypes     map[string][]string
	MaintenanceWindows     MaintenanceWindowConfig
}

type MaintenanceWindowConfig struct {
	MinDuration      time.Duration
	MaxDuration      time.Duration
	MinAdvanceNotice time.Duration
}

// NewSecurityValidationHelper creates a new SecurityValidationHelper
func NewSecurityValidationHelper() *SecurityValidationHelper {
	return &SecurityValidationHelper{
		RequiredTags: append([]string{}, BaseRequiredTags...),
		ComplianceTags: append([]string{}, ComplianceRequiredTags...),
		ValidInstanceFamilies: []string{
			"a1", "c5", "c6g", "d2", "f1", "g4", "i3", "i4i", "inf1",
			"m5", "m6g", "p3", "r5", "r6g", "t3", "t4g", "x1", "x2", "z1d",
		},
		MaintenanceWindows: MaintenanceWindowConfig{
			MinDuration:      time.Duration(MinMaintenanceWindowDuration) * time.Hour,
			MaxDuration:      time.Duration(MaxMaintenanceWindowDuration) * time.Hour,
			MinAdvanceNotice: 24 * time.Hour,
		},
	}
}

// ValidateSecurityTags checks if all required security tags are present and valid
func (h *SecurityValidationHelper) ValidateSecurityTags(tags map[string]string) []error {
	var errors []error

	// Check required tags
	for _, required := range h.RequiredTags {
		if _, exists := tags[required]; !exists {
			errors = append(errors, fmt.Errorf("missing required tag: %s", required))
		}
	}

	// Validate tag values
	if confidentiality, exists := tags["Confidentiality"]; exists {
		if !contains(ValidConfidentialityLevels, strings.ToLower(confidentiality)) {
			errors = append(errors, fmt.Errorf("invalid confidentiality level: %s", confidentiality))
		}
	}

	if compliance, exists := tags["Compliance"]; exists {
		frameworks := strings.Split(compliance, ",")
		for _, framework := range frameworks {
			if !contains(ValidComplianceFrameworks, strings.ToLower(strings.TrimSpace(framework))) {
				errors = append(errors, fmt.Errorf("invalid compliance framework: %s", framework))
			}
		}
	}

	if classification, exists := tags["DataClassification"]; exists {
		if !contains(ValidDataClassifications, strings.ToLower(classification)) {
			errors = append(errors, fmt.Errorf("invalid data classification: %s", classification))
		}
	}

	return errors
}

// ValidateMaintenanceWindow checks if maintenance window configuration is secure
func (h *SecurityValidationHelper) ValidateMaintenanceWindow(start, end time.Time) []error {
	var errors []error

	duration := end.Sub(start)
	now := time.Now()

	if start.Before(now.Add(h.MaintenanceWindows.MinAdvanceNotice)) {
		errors = append(errors, fmt.Errorf("maintenance window must be scheduled at least %v in advance", 
			h.MaintenanceWindows.MinAdvanceNotice))
	}

	if duration < h.MaintenanceWindows.MinDuration {
		errors = append(errors, fmt.Errorf("maintenance window duration must be at least %v", 
			h.MaintenanceWindows.MinDuration))
	}

	if duration > h.MaintenanceWindows.MaxDuration {
		errors = append(errors, fmt.Errorf("maintenance window duration must not exceed %v", 
			h.MaintenanceWindows.MaxDuration))
	}

	return errors
}

// ValidateInstanceType checks if instance type is valid and secure
func (h *SecurityValidationHelper) ValidateInstanceType(instanceType string) error {
	parts := strings.Split(instanceType, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid instance type format: %s", instanceType)
	}

	family := parts[0]
	if !contains(h.ValidInstanceFamilies, family) {
		return fmt.Errorf("invalid or unsupported instance family: %s", family)
	}

	return nil
}

// ValidateComplianceRequirements checks compliance-specific requirements
func (h *SecurityValidationHelper) ValidateComplianceRequirements(compliance string, config map[string]interface{}) []error {
	var errors []error
	
	// Convert compliance string to lowercase for comparison
	complianceLC := strings.ToLower(compliance)
	
	// Common security requirements for all compliance frameworks
	if val, ok := config["host_recovery"]; !ok || val != "on" {
		errors = append(errors, fmt.Errorf("%s compliance requires host_recovery to be 'on'", compliance))
	}
	
	if val, ok := config["auto_placement"]; !ok || val != "off" {
		errors = append(errors, fmt.Errorf("%s compliance requires auto_placement to be 'off'", compliance))
	}
	
	if val, ok := config["enable_monitoring"]; !ok || val != true {
		errors = append(errors, fmt.Errorf("%s compliance requires monitoring to be enabled", compliance))
	}
	
	// Framework-specific requirements
	switch complianceLC {
	case "pci-dss":
		// PCI DSS specific requirements
		if tags, ok := config["tags"].(map[string]string); ok {
			if classification, ok := tags["DataClassification"]; !ok || strings.ToLower(classification) != "restricted" {
				errors = append(errors, fmt.Errorf("PCI DSS compliance requires DataClassification tag to be 'restricted'"))
			}
		}
		
	case "hipaa":
		// HIPAA specific requirements
		if tags, ok := config["tags"].(map[string]string); ok {
			if _, ok := tags["SecurityContact"]; !ok {
				errors = append(errors, fmt.Errorf("HIPAA compliance requires SecurityContact tag"))
			}
		}
		
		if val, ok := config["enable_maintenance_window"]; !ok || val != true {
			errors = append(errors, fmt.Errorf("HIPAA compliance requires maintenance window to be enabled"))
		}
		
	case "sox":
		// SOX specific requirements
		if tags, ok := config["tags"].(map[string]string); ok {
			if _, ok := tags["Owner"]; !ok {
				errors = append(errors, fmt.Errorf("SOX compliance requires Owner tag"))
			}
		}
		
	case "gdpr":
		// GDPR specific requirements
		if tags, ok := config["tags"].(map[string]string); ok {
			if _, ok := tags["DataRegion"]; !ok {
				errors = append(errors, fmt.Errorf("GDPR compliance requires DataRegion tag"))
			}
		}
	}
	
	return errors
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

