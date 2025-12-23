package test

import (
	"fmt"
	"testing"
	"time"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityEdgeCases tests edge cases and boundary conditions for security features
func TestSecurityEdgeCases(t *testing.T) {
	t.Parallel()

	helper := NewSecurityValidationHelper()
	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	edgeCases := []struct {
		name           string
		configuration  map[string]interface{}
		expectedError  bool
		expectedErrorMessage string
		validation     func(*testing.T, *terraform.Options, string, *SecurityValidationHelper)
	}{
		{
			name: "minimum_maintenance_window",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(25 * time.Hour).Format(time.RFC3339),
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":     "production",
					"Project":         "edge-testing",
					"ManagedBy":       "terraform",
					"CostCenter":      "security",
				},
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateMinimumMaintenanceWindow(t, opts, region, helper)
			},
		},
		{
			name: "maximum_maintenance_window",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(48 * time.Hour).Format(time.RFC3339),
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":     "production",
					"Project":         "edge-testing",
					"ManagedBy":       "terraform",
					"CostCenter":      "security",
				},
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateMaximumMaintenanceWindow(t, opts, region, helper)
			},
		},
		{
			name: "maximum_tag_count",
			configuration: map[string]interface{}{
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "edge-testing",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Department":         "infrastructure",
					"Team":               "platform",
					"Owner":              "security-team",
					"SecurityContact":    "security@example.com",
					"Confidentiality":    "restricted",
					"Compliance":         "pci-dss",
					"DataClassification": "restricted",
					"Application":        "dedicated-hosts",
					"Version":            "1.0.0",
					"BusinessUnit":       "cloud-platform",
					"ChargeCode":         "cc-12345",
					"Criticality":        "high",
					"MaintenanceWindow":  "weekend",
					"BackupPolicy":       "daily",
					"AutoRemediation":    "enabled",
					"MonitoringLevel":    "detailed",
				},
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateMaximumTagCount(t, opts, region)
			},
		},
		{
			name: "excessive_tag_count",
			configuration: map[string]interface{}{
				"tags": generateExcessiveTags(51), // AWS limit is 50 tags
			},
			expectedError: true,
			expectedErrorMessage: "AWS allows a maximum of 50 tags",
		},
		{
			name: "extremely_long_tag_value",
			configuration: map[string]interface{}{
				"tags": map[string]string{
					"Description": strings.Repeat("a", 256), // AWS tag value limit is 255 characters
				},
			},
			expectedError: true,
			expectedErrorMessage: "cannot exceed 255 characters",
		},
		{
			name: "mixed_case_compliance_framework",
			configuration: map[string]interface{}{
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "edge-testing",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Confidentiality":    "restricted",
					"Compliance":         "PCI-dss", // Mixed case should be accepted
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
				},
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateMixedCaseCompliance(t, opts, region, helper)
			},
		},
		{
			name: "unusual_instance_type",
			configuration: map[string]interface{}{
				"instance_type":     "z1d.metal", // Less common instance type
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateUnusualInstanceType(t, opts, region)
			},
		},
		{
			name: "too_short_maintenance_window",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(25 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(25*time.Hour + 30*time.Minute).Format(time.RFC3339), // 30 min window is too short
			},
			expectedError: true,
			expectedErrorMessage: "maintenance window duration must be at least",
		},
		{
			name: "too_long_maintenance_window",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(25 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(25*time.Hour + 25*time.Hour).Format(time.RFC3339), // 25 hour window is too long
			},
			expectedError: true,
			expectedErrorMessage: "maintenance window duration must not exceed",
		},
		{
			name: "minimum_advance_notice",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(24*time.Hour + 2*time.Hour).Format(time.RFC3339),
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateMinimumAdvanceNotice(t, opts, helper)
			},
		},
		{
			name: "insufficient_advance_notice",
			configuration: map[string]interface{}{
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(23 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(23*time.Hour + 2*time.Hour).Format(time.RFC3339),
			},
			expectedError: true,
			expectedErrorMessage: "maintenance window must be scheduled at least",
		},
		{
			name: "multiple_compliance_frameworks",
			configuration: map[string]interface{}{
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "edge-testing",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Confidentiality":    "restricted",
					"Compliance":         "pci-dss,hipaa,gdpr,sox", // Multiple frameworks
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
					"Owner":              "security-team",
					"DataRegion":         "us-west", 
				},
			},
			expectedError: false,
			validation: func(t *testing.T, opts *terraform.Options, region string, helper *SecurityValidationHelper) {
				validateMultipleComplianceFrameworks(t, opts, region, helper)
			},
		},
	}

	for _, tc := range edgeCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Set up default variables
			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			// Override with test case configuration
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

			if tc.expectedError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err)
				if tc.expectedErrorMessage != "" {
					assert.Contains(t, err.Error(), tc.expectedErrorMessage)
				}
			} else {
				test_structure.RunTestStage(t, "setup", func() {
					terraform.InitAndApply(t, terraformOptions)
				})

				if tc.validation != nil {
					test_structure.RunTestStage(t, "validate", func() {
						tc.validation(t, terraformOptions, awsRegion, helper)
					})
				}

				test_structure.RunTestStage(t, "teardown", func() {
					terraform.Destroy(t, terraformOptions)
				})
			}
		})
	}
}

// Helper function to generate a map with excessive tags
func generateExcessiveTags(count int) map[string]string {
	tags := make(map[string]string)
	for i := 0; i < count; i++ {
		tags[fmt.Sprintf("Tag%d", i)] = fmt.Sprintf("Value%d", i)
	}
	return tags
}

// Validation functions for edge cases

func validateMinimumMaintenanceWindow(t *testing.T, terraformOptions *terraform.Options, awsRegion string, helper *SecurityValidationHelper) {
	// Validate that the minimum maintenance window duration is accepted
	startTime := terraform.Output(t, terraformOptions, "maintenance_window_start_time")
	endTime := terraform.Output(t, terraformOptions, "maintenance_window_end_time")
	
	start, err := time.Parse(time.RFC3339, startTime)
	require.NoError(t, err)
	end, err := time.Parse(time.RFC3339, endTime)
	require.NoError(t, err)
	
	duration := end.Sub(start)
	// Check it's at least the minimum duration
	assert.GreaterOrEqual(t, duration.Hours(), float64(MinMaintenanceWindowDuration))
	// Check it's close to the minimum (not more than 2 hours)
	assert.LessOrEqual(t, duration.Hours(), float64(MinMaintenanceWindowDuration+1))
}

func validateMaximumMaintenanceWindow(t *testing.T, terraformOptions *terraform.Options, awsRegion string, helper *SecurityValidationHelper) {
	// Validate that the maximum maintenance window duration is accepted
	startTime := terraform.Output(t, terraformOptions, "maintenance_window_start_time")
	endTime := terraform.Output(t, terraformOptions, "maintenance_window_end_time")
	
	start, err := time.Parse(time.RFC3339, startTime)
	require.NoError(t, err)
	end, err := time.Parse(time.RFC3339, endTime)
	require.NoError(t, err)
	
	duration := end.Sub(start)
	// Check it's not exceeding the maximum
	assert.LessOrEqual(t, duration.Hours(), float64(MaxMaintenanceWindowDuration))
	// Check it's close to the maximum (at least 20 hours)
	assert.GreaterOrEqual(t, duration.Hours(), float64(MaxMaintenanceWindowDuration-4))
}

func validateMaximumTagCount(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	// Check that a large number of tags (but within AWS limits) is handled correctly
	assert.GreaterOrEqual(t, len(tags), 20)
	
	// Verify some specific tags are present
	assert.Contains(t, tags, "Environment")
	assert.Contains(t, tags, "Project")
	assert.Contains(t, tags, "SecurityContact")
	assert.Contains(t, tags, "Compliance")
}

func validateMixedCaseCompliance(t *testing.T, terraformOptions *terraform.Options, awsRegion string, helper *SecurityValidationHelper) {
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	
	// The case insensitive compliance tag should be accepted
	complianceFramework := tags["Compliance"]
	assert.Equal(t, "PCI-dss", complianceFramework)
	
	// Create a config map for validation
	config := map[string]interface{}{
		"host_recovery":     terraform.Output(t, terraformOptions, "host_recovery"),
		"auto_placement":    terraform.Output(t, terraformOptions, "auto_placement"),
		"enable_monitoring": terraform.Output(t, terraformOptions, "enable_monitoring") == "true",
		"tags":              tags,
	}
	
	// Should validate correctly despite the mixed case
	errors := helper.ValidateComplianceRequirements("PCI-dss", config)
	assert.Empty(t, errors)
}

func validateUnusualInstanceType(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	instanceType := terraform.Output(t, terraformOptions, "instance_type")
	assert.Equal(t, "z1d.metal", instanceType)
	
	// Validate the host has been created with the unusual instance type
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Create EC2 client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	ec2Client := ec2.New(sess)
	
	// Describe the host
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{awssdk.String(hostID)},
	}
	
	result, err := ec2Client.DescribeHosts(input)
	require.NoError(t, err)
	require.Len(t, result.Hosts, 1)
	
	host := result.Hosts[0]
	// Verify the unusual instance type is correctly set
	assert.Equal(t, "z1d.metal", *host.InstanceType)
}

func validateMinimumAdvanceNotice(t *testing.T, terraformOptions *terraform.Options, helper *SecurityValidationHelper) {
	startTime := terraform.Output(t, terraformOptions, "maintenance_window_start_time")
	
	start, err := time.Parse(time.RFC3339, startTime)
	require.NoError(t, err)
	
	now := time.Now()
	advanceNotice := start.Sub(now)
	
	// Should be at least 24 hours
	assert.GreaterOrEqual(t, advanceNotice.Hours(), 24.0)
	// But not much more than that (testing the boundary)
	assert.Less(t, advanceNotice.Hours(), 25.0)
}

func validateMultipleComplianceFrameworks(t *testing.T, terraformOptions *terraform.Options, awsRegion string, helper *SecurityValidationHelper) {
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	
	complianceFrameworks := tags["Compliance"]
	assert.Contains(t, complianceFrameworks, "pci-dss")
	assert.Contains(t, complianceFrameworks, "hipaa")
	assert.Contains(t, complianceFrameworks, "gdpr")
	assert.Contains(t, complianceFrameworks, "sox")
	
	// Verify all required tags for multiple frameworks are present
	assert.Contains(t, tags, "SecurityContact") // Required for hipaa
	assert.Contains(t, tags, "Owner") // Required for sox
	assert.Contains(t, tags, "DataRegion") // Required for gdpr
	assert.Contains(t, tags, "DataClassification") // Required for pci-dss
	
	// Create a config map for validation
	config := map[string]interface{}{
		"host_recovery":     terraform.Output(t, terraformOptions, "host_recovery"),
		"auto_placement":    terraform.Output(t, terraformOptions, "auto_placement"),
		"enable_monitoring": terraform.Output(t, terraformOptions, "enable_monitoring") == "true",
		"tags":              tags,
		"enable_maintenance_window": true,
	}
	
	// Each framework should validate individually
	frameworks := []string{"pci-dss", "hipaa", "gdpr", "sox"}
	for _, framework := range frameworks {
		errors := helper.ValidateComplianceRequirements(framework, config)
		assert.Empty(t, errors, "Validation errors for %s framework: %v", framework, errors)
	}
}

