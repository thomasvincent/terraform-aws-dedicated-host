package test

import (
	"fmt"
	"testing"
	"time"
	"strings"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComplianceValidation(t *testing.T) {
	t.Parallel()

	helper := NewSecurityValidationHelper()
	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	complianceTestCases := []struct {
		name           string
		configuration  map[string]interface{}
		expectedErrors []string
	}{
		{
			name: "pci_dss_compliant",
			configuration: map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:security-alerts"},
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(52 * time.Hour).Format(time.RFC3339),
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "pci-compliance",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Confidentiality":    "restricted",
					"Compliance":         "pci-dss",
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
				},
			},
			expectedErrors: []string{},
		},
		{
			name: "hipaa_compliant",
			configuration: map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "r5.2xlarge",
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:security-alerts"},
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(72 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(74 * time.Hour).Format(time.RFC3339),
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "hipaa-compliance",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Confidentiality":    "restricted",
					"Compliance":         "hipaa",
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
				},
			},
			expectedErrors: []string{},
		},
		{
			name: "multi_compliance_frameworks",
			configuration: map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "m5.xlarge",
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:security-alerts"},
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(52 * time.Hour).Format(time.RFC3339),
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "compliance",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Confidentiality":    "restricted",
					"Compliance":         "pci-dss,hipaa",
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
					"Owner":              "compliance-team",
					"DataRegion":         "us-west",
				},
			},
			expectedErrors: []string{},
		},
		{
			name: "invalid_compliance_framework",
			configuration: map[string]interface{}{
				"tags": map[string]string{
					"Compliance": "invalid-framework",
				},
			},
			expectedErrors: []string{
				"invalid compliance framework",
			},
		},
		{
			name: "invalid_confidentiality_level",
			configuration: map[string]interface{}{
				"tags": map[string]string{
					"Confidentiality": "top-secret",
				},
			},
			expectedErrors: []string{
				"invalid confidentiality level",
			},
		},
		{
			name: "insufficient_maintenance_window",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			},
			expectedErrors: []string{
				"maintenance window must be scheduled at least",
			},
		},
		{
			name: "pci_dss_missing_required_tags",
			configuration: map[string]interface{}{
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "pci-compliance",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Compliance":         "pci-dss",
					// Missing DataClassification and SecurityContact
				},
			},
			expectedErrors: []string{
				"missing required tag",
			},
		},
		{
			name: "hipaa_disabled_host_recovery",
			configuration: map[string]interface{}{
				"host_recovery":     "off",  // Should be on for HIPAA
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "hipaa-compliance",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Confidentiality":    "restricted",
					"Compliance":         "hipaa",
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
				},
			},
			expectedErrors: []string{
				"host_recovery to be 'on'",
			},
		},
	}

	for _, tc := range complianceTestCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Merge with default configuration
			defaultVars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", random.UniqueId()),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
			}
			
			vars := make(map[string]interface{})
			for k, v := range defaultVars {
				vars[k] = v
			}
			
			for k, v := range tc.configuration {
				vars[k] = v
			}

			terraformOptions := &terraform.Options{
				TerraformDir: workingDir,
				Vars:         vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if len(tc.expectedErrors) > 0 {
				// Validate expected errors using helper functions directly
				var foundErrors bool
				
				// Check tag validations
				if tags, ok := tc.configuration["tags"].(map[string]string); ok {
					tagErrors := helper.ValidateSecurityTags(tags)
					for _, expectedError := range tc.expectedErrors {
						for _, tagError := range tagErrors {
							if strings.Contains(tagError.Error(), expectedError) {
								foundErrors = true
								break
							}
						}
					}
				}
				
				// Check maintenance window validations
				if tc.configuration["enable_maintenance_window"] == true {
					startTimeStr, startOk := tc.configuration["maintenance_window_start_time"].(string)
					endTimeStr, endOk := tc.configuration["maintenance_window_end_time"].(string)
					
					if startOk && endOk {
						startTime, _ := time.Parse(time.RFC3339, startTimeStr)
						endTime, _ := time.Parse(time.RFC3339, endTimeStr)
						
						windowErrors := helper.ValidateMaintenanceWindow(startTime, endTime)
						for _, expectedError := range tc.expectedErrors {
							for _, windowError := range windowErrors {
								if strings.Contains(windowError.Error(), expectedError) {
									foundErrors = true
									break
								}
							}
						}
					}
				}
				
				// If no validation errors were found, expect terraform validation to fail
				if !foundErrors {
					_, err := terraform.InitAndPlanE(t, terraformOptions)
					assert.Error(t, err)
					for _, expectedError := range tc.expectedErrors {
						assert.Contains(t, err.Error(), expectedError)
					}
				}
			} else {
				// For valid cases, apply and validate
				test_structure.RunTestStage(t, "setup", func() {
					terraform.InitAndApply(t, terraformOptions)
				})

				test_structure.RunTestStage(t, "validate", func() {
					validateComplianceConfiguration(t, terraformOptions, awsRegion, helper)
				})

				test_structure.RunTestStage(t, "teardown", func() {
					terraform.Destroy(t, terraformOptions)
				})
			}
		})
	}
}

func validateComplianceConfiguration(t *testing.T, terraformOptions *terraform.Options, awsRegion string, helper *SecurityValidationHelper) {
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Get tags for validation
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	
	// Validate basic security tags
	tagErrors := helper.ValidateSecurityTags(tags)
	assert.Empty(t, tagErrors, "Security tag validation errors: %v", tagErrors)

	// Validate maintenance window if enabled
	if maintenanceWindowID := terraform.Output(t, terraformOptions, "maintenance_window_id"); maintenanceWindowID != "" {
		startTime := terraform.Output(t, terraformOptions, "maintenance_window_start_time")
		endTime := terraform.Output(t, terraformOptions, "maintenance_window_end_time")

		start, err := time.Parse(time.RFC3339, startTime)
		require.NoError(t, err)
		end, err := time.Parse(time.RFC3339, endTime)
		require.NoError(t, err)

		windowErrors := helper.ValidateMaintenanceWindow(start, end)
		assert.Empty(t, windowErrors, "Maintenance window validation errors: %v", windowErrors)
	}

	// Validate instance type
	instanceType := terraform.Output(t, terraformOptions, "instance_type")
	err := helper.ValidateInstanceType(instanceType)
	assert.NoError(t, err, "Instance type validation error: %v", err)

	// Validate compliance-specific requirements
	if complianceTag, exists := tags["Compliance"]; exists {
		frameworks := strings.Split(complianceTag, ",")
		for _, framework := range frameworks {
			framework = strings.TrimSpace(framework)
			
			// Create a configuration map from terraformOptions outputs
			config := map[string]interface{}{
				"host_recovery":     terraform.Output(t, terraformOptions, "host_recovery"),
				"auto_placement":    terraform.Output(t, terraformOptions, "auto_placement"),
				"enable_monitoring": terraform.Output(t, terraformOptions, "enable_monitoring") == "true",
				"tags":              tags,
			}
			
			// Check for maintenance window
			if maintenanceWindowID := terraform.Output(t, terraformOptions, "maintenance_window_id"); maintenanceWindowID != "" {
				config["enable_maintenance_window"] = true
			}
			
			complianceErrors := helper.ValidateComplianceRequirements(framework, config)
			assert.Empty(t, complianceErrors, "Compliance validation errors for %s: %v", framework, complianceErrors)
		}
	}
}

