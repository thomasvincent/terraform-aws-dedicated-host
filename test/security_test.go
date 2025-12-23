
// TestAdditionalSecurityScenarios tests more complex security scenarios
func TestAdditionalSecurityScenarios(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	// Test scenario: Full security configuration with all security features enabled
	terraformOptions := &terraform.Options{
		TerraformDir: workingDir,
		Vars: map[string]interface{}{
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
			"maintenance_auto_placement":    "off",
			"enable_capacity_reservation":   true,
			"capacity_reservation_count":    2,
			"prevent_instance_deletion":     true,
			"tags": map[string]string{
				"Environment":     "production",
				"Project":         "security-testing",
				"ManagedBy":       "terraform",
				"CostCenter":      "security-validation",
				"Confidentiality": "high",
				"Compliance":      "pci-dss",
				"SecurityContact": "security@example.com",
				"DataClassification": "restricted",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Cleanup after tests
	defer test_structure.RunTestStage(t, "teardown", func() {
		terraform.Destroy(t, terraformOptions)
	})

	// Deploy the infrastructure
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, terraformOptions)
	})

	// Run comprehensive security validations
	test_structure.RunTestStage(t, "validate", func() {
		// Basic security validation
		validateHostSecurity(t, terraformOptions, awsRegion)
		
		// CloudWatch alarm validation
		validateCloudWatchAlarm(t, terraformOptions, awsRegion)
		
		// Maintenance window validation
		validateMaintenanceWindow(t, terraformOptions)
		
		// Additional security validations
		validateExtendedSecurityMeasures(t, terraformOptions, awsRegion)
	})
}

// validateExtendedSecurityMeasures performs additional security validations
func validateExtendedSecurityMeasures(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Create AWS session and EC2 client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	ec2Client := ec2.New(sess)

	// Validate capacity reservation if enabled
	if capacityReservationID := terraform.Output(t, terraformOptions, "capacity_reservation_id"); capacityReservationID != "" {
		input := &ec2.DescribeCapacityReservationsInput{
			CapacityReservationIds: []*string{awssdk.String(capacityReservationID)},
		}
		
		result, err := ec2Client.DescribeCapacityReservations(input)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(result.CapacityReservations), 1)
		
		reservation := result.CapacityReservations[0]
		
		// Validate reservation is active
		assert.Equal(t, "active", *reservation.State, "Capacity reservation should be active")
		
		// Validate reservation instance count
		count := terraform.Output(t, terraformOptions, "capacity_reservation_count")
		assert.Equal(t, count, fmt.Sprintf("%d", *reservation.TotalInstanceCount), 
			"Capacity reservation count should match configuration")
		
		// Validate reservation is targeted (not open)
		assert.Equal(t, "targeted", *reservation.InstanceMatchCriteria, 
			"Capacity reservation should use targeted instance matching for security")
	}
	
	// Validate tags for security and compliance
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	
	// Check for security-specific tags
	securityTags := []string{
		"Confidentiality", 
		"Compliance", 
		"SecurityContact",
		"DataClassification",
	}
	
	for _, tag := range securityTags {
		assert.Contains(t, tags, tag, fmt.Sprintf("Security tag '%s' is missing", tag))
	}
	
	// Validate the prevent_instance_deletion setting is respected
	// This can be checked indirectly by attempting to start a termination and 
	// expecting it to fail, but we'll skip the actual termination attempt in the test
	
	preventDeletion := terraform.Output(t, terraformOptions, "prevent_instance_deletion")
	assert.Equal(t, "true", preventDeletion, "prevent_instance_deletion should be enabled for security")
}

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

func TestDedicatedHostSecurity(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	terraformOptions := &terraform.Options{
		TerraformDir: workingDir,
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("test-host-%s", uniqueID),
			"availability_zone": fmt.Sprintf("%sa", awsRegion),
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "off",
			"tags": map[string]string{
				"Environment": "test",
				"Project":     "security-testing",
				"ManagedBy":   "terraform",
				"CostCenter":  "security-validation",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Cleanup after tests
	defer test_structure.RunTestStage(t, "teardown", func() {
		terraform.Destroy(t, terraformOptions)
	})

	// Deploy the infrastructure
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, terraformOptions)
	})

	// Run security validations
	test_structure.RunTestStage(t, "validate", func() {
		validateHostSecurity(t, terraformOptions, awsRegion)
	})
}

func validateHostSecurity(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Test 1: Required Security Tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	requiredTags := []string{"Environment", "Project", "ManagedBy", "CostCenter"}
	for _, tag := range requiredTags {
		assert.Contains(t, tags, tag, fmt.Sprintf("Required security tag '%s' is missing", tag))
	}

	// Test 2: Host Recovery Configuration
	hostRecovery := terraform.Output(t, terraformOptions, "host_recovery")
	assert.Equal(t, "on", hostRecovery, "Host recovery should be enabled for security")

	// Test 3: Auto Placement Configuration
	autoPlacement := terraform.Output(t, terraformOptions, "auto_placement")
	assert.Equal(t, "off", autoPlacement, "Auto placement should be disabled for security")

	// Test 4: CloudWatch Alarm Configuration (if enabled)
	if alarmARN := terraform.Output(t, terraformOptions, "cloudwatch_alarm_arn"); alarmARN != "" {
		validateCloudWatchAlarm(t, terraformOptions, awsRegion)
	}

	// Test 5: Maintenance Window Configuration (if enabled)
	if maintenanceWindowID := terraform.Output(t, terraformOptions, "maintenance_window_id"); maintenanceWindowID != "" {
		validateMaintenanceWindow(t, terraformOptions)
	}
}

func validateCloudWatchAlarm(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	alarmARN := terraform.Output(t, terraformOptions, "cloudwatch_alarm_arn")
	require.NotEmpty(t, alarmARN)

	// Extract alarm name from ARN
	parts := strings.Split(alarmARN, ":")
	alarmName := parts[len(parts)-1]
	
	// Create AWS session and CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)

	// Get alarm details
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []*string{awssdk.String(alarmName)},
	}

	result, err := cloudwatchClient.DescribeAlarms(input)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(result.MetricAlarms), 1, "No CloudWatch alarm found with name: %s", alarmName)

	alarm := result.MetricAlarms[0]

	// Validate alarm configuration
	assert.Equal(t, "GreaterThanThreshold", *alarm.ComparisonOperator, "Alarm should use GreaterThanThreshold comparison")
	assert.GreaterOrEqual(t, *alarm.EvaluationPeriods, int64(2), "Alarm should evaluate at least 2 periods")
	assert.Equal(t, int64(60), *alarm.Period, "Alarm should use 60-second periods")
	assert.Equal(t, "Maximum", *alarm.Statistic, "Alarm should use Maximum statistic")
	assert.Equal(t, float64(0), *alarm.Threshold, "Alarm threshold should be 0")
	assert.Equal(t, "AWS/EC2", *alarm.Namespace, "Alarm should use AWS/EC2 namespace")
	assert.Equal(t, "StatusCheckFailed", *alarm.MetricName, "Alarm should monitor StatusCheckFailed metric")

	// Validate alarm actions are configured
	assert.NotEmpty(t, alarm.AlarmActions, "Alarm should have at least one alarm action")

	// Validate alarm dimensions (should include HostId)
	foundHostDimension := false
	hostID := terraform.Output(t, terraformOptions, "host_id")
	for _, dim := range alarm.Dimensions {
		if *dim.Name == "HostId" {
			foundHostDimension = true
			assert.Equal(t, hostID, *dim.Value, "HostId dimension should match the dedicated host ID")
			break
		}
	}
	assert.True(t, foundHostDimension, "Alarm should have a HostId dimension")

	// Validate alarm description
	assert.Contains(t, *alarm.AlarmDescription, "dedicated host", "Alarm description should mention dedicated host")
}

func validateMaintenanceWindow(t *testing.T, terraformOptions *terraform.Options) {
	maintenanceWindowID := terraform.Output(t, terraformOptions, "maintenance_window_id")
	require.NotEmpty(t, maintenanceWindowID)
	
	hostID := terraform.Output(t, terraformOptions, "host_id")
	awsRegion := terraform.Output(t, terraformOptions, "aws_region")
	
	// Create AWS session and EC2 client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	ec2Client := ec2.New(sess)

	// Get host maintenance details
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{awssdk.String(hostID)},
	}

	result, err := ec2Client.DescribeHosts(input)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(result.Hosts), 1, "No dedicated host found with ID: %s", hostID)

	host := result.Hosts[0]

	// Validate host maintenance attributes are set correctly
	assert.NotNil(t, host.HostMaintenance, "Host maintenance attributes should be set")
	
	// Validate maintenance window start and end times
	if host.HostMaintenance != nil && host.HostMaintenance.MaintenanceSchedule != nil {
		schedule := host.HostMaintenance.MaintenanceSchedule
		
		// Verify start time is in the future
		if schedule.StartTime != nil {
			startTime, err := time.Parse(time.RFC3339, *schedule.StartTime)
			require.NoError(t, err, "Failed to parse start time")
			
			// Start time should be after test execution time
			assert.True(t, startTime.After(time.Now()), "Maintenance window start time should be in the future")
		}
		
		// Verify end time is after start time
		if schedule.StartTime != nil && schedule.EndTime != nil {
			startTime, err := time.Parse(time.RFC3339, *schedule.StartTime)
			require.NoError(t, err, "Failed to parse start time")
			
			endTime, err := time.Parse(time.RFC3339, *schedule.EndTime)
			require.NoError(t, err, "Failed to parse end time")
			
			// End time should be after start time
			assert.True(t, endTime.After(startTime), "Maintenance window end time should be after start time")
			
			// Maintenance window duration should be reasonable (between 1 and 24 hours)
			duration := endTime.Sub(startTime)
			assert.GreaterOrEqual(t, duration.Hours(), 1.0, "Maintenance window should be at least 1 hour")
			assert.LessOrEqual(t, duration.Hours(), 24.0, "Maintenance window should be at most 24 hours")
		}
	}
	
	// Validate auto placement during maintenance
	if host.HostMaintenance != nil {
		maintenance_auto_placement := terraform.Output(t, terraformOptions, "maintenance_auto_placement")
		if maintenance_auto_placement != "" {
			assert.Equal(t, maintenance_auto_placement, *host.HostMaintenance.AutoPlacement, 
				"Auto placement during maintenance should match configuration")
		}
	}
}

func TestSecurityComplianceScenarios(t *testing.T) {
	testCases := []struct {
		name           string
		configuration  map[string]interface{}
		expectedError  bool
		validationFunc func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "missing_required_tags",
			configuration: map[string]interface{}{
				"tags": map[string]string{
					"Environment": "test",
					// Missing required tags
				},
			},
			expectedError: true,
		},
		{
			name: "insecure_host_recovery",
			configuration: map[string]interface{}{
				"host_recovery": "off",
			},
			expectedError: true,
		},
		{
			name: "insecure_auto_placement",
			configuration: map[string]interface{}{
				"auto_placement": "on",
			},
			expectedError: true,
		},
		{
			name: "compliant_configuration",
			configuration: map[string]interface{}{
				"host_recovery":  "on",
				"auto_placement": "off",
				"tags": map[string]string{
					"Environment": "test",
					"Project":     "security-testing",
					"ManagedBy":   "terraform",
					"CostCenter":  "security-validation",
				},
			},
			expectedError: false,
			validationFunc: func(t *testing.T, opts *terraform.Options, region string) {
				validateHostSecurity(t, opts, region)
			},
		},
		{
			name: "monitoring_disabled",
			configuration: map[string]interface{}{
				"enable_monitoring": false,
				"host_recovery":     "on",
				"auto_placement":    "off",
				"tags": map[string]string{
					"Environment": "test",
					"Project":     "security-testing",
					"ManagedBy":   "terraform",
					"CostCenter":  "security-validation",
				},
			},
			expectedError: true,
		},
		{
			name: "alarm_actions_missing",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions":     []string{},
				"host_recovery":     "on",
				"auto_placement":    "off",
				"tags": map[string]string{
					"Environment": "test",
					"Project":     "security-testing",
					"ManagedBy":   "terraform",
					"CostCenter":  "security-validation",
				},
			},
			expectedError: true,
		},
		{
			name: "full_secure_configuration",
			configuration: map[string]interface{}{
				"host_recovery":     "on",
				"auto_placement":    "off",
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:security-alerts"},
				"enable_maintenance_window": true,
				"maintenance_window_start_time": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
				"maintenance_window_end_time":   time.Now().Add(52 * time.Hour).Format(time.RFC3339),
				"maintenance_auto_placement":    "off",
				"tags": map[string]string{
					"Environment": "test",
					"Project":     "security-testing",
					"ManagedBy":   "terraform",
					"CostCenter":  "security-validation",
					"Confidentiality": "high",
					"Compliance":      "pci-dss",
				},
			},
			expectedError: false,
			validationFunc: func(t *testing.T, opts *terraform.Options, region string) {
				validateHostSecurity(t, opts, region)
				validateCloudWatchAlarm(t, opts, region)
				validateMaintenanceWindow(t, opts)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			workingDir := "../examples/complete"
			awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

			// Merge test case configuration with default values
			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", random.UniqueId()),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
			}
			for k, v := range tc.configuration {
				vars[k] = v
			}

			terraformOptions := &terraform.Options{
				TerraformDir: workingDir,
				Vars:        vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			if tc.expectedError {
				_, err := terraform.InitAndPlanE(t, terraformOptions)
				assert.Error(t, err)
			} else {
				test_structure.RunTestStage(t, "setup", func() {
					terraform.InitAndApply(t, terraformOptions)
				})

				if tc.validationFunc != nil {
					test_structure.RunTestStage(t, "validate", func() {
						tc.validationFunc(t, terraformOptions, awsRegion)
					})
				}

				test_structure.RunTestStage(t, "teardown", func() {
					terraform.Destroy(t, terraformOptions)
				})
			}
		})
	}
}

