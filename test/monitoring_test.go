package test

import (
	"fmt"
	"testing"
	"time"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMonitoringConfigurations tests various CloudWatch alarm configurations and monitoring scenarios
func TestMonitoringConfigurations(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	monitoringTestCases := []struct {
		name           string
		configuration  map[string]interface{}
		expectedError  bool
		errorMessage   string
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "basic_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:host-alarms"},
			},
			validation: validateBasicMonitoring,
		},
		{
			name: "comprehensive_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:host-alarms"},
				"ok_actions":        []string{"arn:aws:sns:us-west-2:123456789012:recovery-notifications"},
				"insufficient_data_actions": []string{"arn:aws:sns:us-west-2:123456789012:monitoring-alerts"},
				"evaluation_periods": 3,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           80,
						"evaluation_periods":  2,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
					},
					"memory_utilization": {
						"metric_name":         "MemoryUtilization",
						"threshold":           90,
						"evaluation_periods":  3,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
					},
				},
			},
			validation: validateComprehensiveMonitoring,
		},
		{
			name: "compliance_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:host-alarms", "arn:aws:sns:us-west-2:123456789012:security-team"},
				"ok_actions":        []string{"arn:aws:sns:us-west-2:123456789012:recovery-notifications"},
				"evaluation_periods": 2,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching",
				"tags": map[string]string{
					"Environment":     "production",
					"Project":         "monitoring-tests",
					"ManagedBy":       "terraform",
					"CostCenter":      "security",
					"Compliance":      "pci-dss",
					"SecurityContact": "security@example.com",
				},
			},
			validation: validateComplianceMonitoring,
		},
		{
			name: "aggressive_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring":  true,
				"alarm_actions":      []string{"arn:aws:sns:us-west-2:123456789012:urgent-alerts"},
				"evaluation_periods": 1,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanOrEqualToThreshold",
				"threshold":           1,
				"period":              60,
				"statistic":           "Maximum",
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           60,  // Lower threshold for earlier alerting
						"evaluation_periods":  1,   // Alert on first occurrence
						"comparison_operator": "GreaterThanThreshold",
						"period":              60,  // Check every minute
						"statistic":           "Maximum",
					},
				},
			},
			validation: validateAggressiveMonitoring,
		},
		{
			name: "disabled_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": false,
			},
			validation: validateDisabledMonitoring,
		},
		{
			name: "invalid_period",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"period":            15,  // Must be multiple of 60
			},
			expectedError: true,
			errorMessage:  "period must be",
		},
		{
			name: "invalid_evaluation_periods",
			configuration: map[string]interface{}{
				"enable_monitoring":  true,
				"evaluation_periods": 0,  // Must be positive
			},
			expectedError: true,
			errorMessage:  "evaluation_periods must be greater than 0",
		},
		{
			name: "no_alarm_actions",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions":     []string{},
			},
			expectedError: true,
			errorMessage:  "alarm_actions cannot be empty",
		},
		{
			name: "composite_alarm",
			configuration: map[string]interface{}{
				"enable_monitoring":  true,
				"alarm_actions":      []string{"arn:aws:sns:us-west-2:123456789012:host-alarms"},
				"evaluation_periods": 2,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           80,
						"evaluation_periods":  2,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
					},
				},
				"composite_alarms": map[string]map[string]interface{}{
					"critical_condition": {
						"alarm_rule": "ALARM(StatusCheckFailed) OR ALARM(CPUUtilization)",
						"actions":    []string{"arn:aws:sns:us-west-2:123456789012:critical-alerts"},
					},
				},
			},
			validation: validateCompositeAlarm,
		},
	}

	for _, tc := range monitoringTestCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Default variables
			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			// Merge with test case configuration
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
				if tc.errorMessage != "" {
					assert.Contains(t, err.Error(), tc.errorMessage)
				}
			} else {
				test_structure.RunTestStage(t, "setup", func() {
					terraform.InitAndApply(t, terraformOptions)
				})

				if tc.validation != nil {
					test_structure.RunTestStage(t, "validate", func() {
						tc.validation(t, terraformOptions, awsRegion)
					})
				}

				test_structure.RunTestStage(t, "teardown", func() {
					terraform.Destroy(t, terraformOptions)
				})
			}
		})
	}
}

// Helper functions for validation

func validateBasicMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)

	// Get host ID and alarm ARN from outputs
	hostID := terraform.Output(t, terraformOptions, "host_id")
	alarmARN := terraform.Output(t, terraformOptions, "cloudwatch_alarm_arn")
	
	require.NotEmpty(t, hostID)
	require.NotEmpty(t, alarmARN)

	// Extract alarm name from ARN
	alarmName := extractResourceNameFromARN(alarmARN)
	
	// Describe the alarm
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []*string{awssdk.String(alarmName)},
	}
	
	result, err := cloudwatchClient.DescribeAlarms(input)
	require.NoError(t, err)
	require.Len(t, result.MetricAlarms, 1, "Expected exactly one alarm")
	
	alarm := result.MetricAlarms[0]
	
	// Validate basic alarm configuration
	assert.Equal(t, "StatusCheckFailed", *alarm.MetricName)
	assert.Equal(t, "AWS/EC2", *alarm.Namespace)
	assert.Equal(t, "GreaterThanThreshold", *alarm.ComparisonOperator)
	assert.Equal(t, float64(0), *alarm.Threshold)
	assert.Equal(t, int64(60), *alarm.Period)
	assert.Equal(t, "Maximum", *alarm.Statistic)
	
	// Validate dimensions
	foundHostDimension := false
	for _, dim := range alarm.Dimensions {
		if *dim.Name == "HostId" {
			foundHostDimension = true
			assert.Equal(t, hostID, *dim.Value)
		}
	}
	assert.True(t, foundHostDimension, "Alarm should have HostId dimension")
	
	// Validate actions
	assert.Len(t, alarm.AlarmActions, 1, "Should have 1 alarm action")
}

func validateComprehensiveMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID and primary alarm ARN
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Describe all alarms for this host
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("host-%s", hostID)),
	}
	
	result, err := cloudwatchClient.DescribeAlarms(input)
	require.NoError(t, err)
	
	// We should have at least 3 alarms (status check, CPU, memory)
	assert.GreaterOrEqual(t, len(result.MetricAlarms), 3, "Should have at least 3 alarms")
	
	// Validate individual alarms
	statusCheckAlarm := findAlarmByMetricName(result.MetricAlarms, "StatusCheckFailed")
	require.NotNil(t, statusCheckAlarm, "Status check alarm not found")
	assert.Equal(t, int64(3), *statusCheckAlarm.EvaluationPeriods)
	assert.Equal(t, int64(60), *statusCheckAlarm.Period)
	
	cpuAlarm := findAlarmByMetricName(result.MetricAlarms, "CPUUtilization")
	require.NotNil(t, cpuAlarm, "CPU utilization alarm not found")
	assert.Equal(t, float64(80), *cpuAlarm.Threshold)
	assert.Equal(t, int64(2), *cpuAlarm.EvaluationPeriods)
	assert.Equal(t, int64(300), *cpuAlarm.Period)
	assert.Equal(t, "Average", *cpuAlarm.Statistic)
	
	memoryAlarm := findAlarmByMetricName(result.MetricAlarms, "MemoryUtilization")
	require.NotNil(t, memoryAlarm, "Memory utilization alarm not found")
	assert.Equal(t, float64(90), *memoryAlarm.Threshold)
	assert.Equal(t, int64(3), *memoryAlarm.EvaluationPeriods)
	
	// Validate actions for all alarms
	for _, alarm := range result.MetricAlarms {
		assert.NotEmpty(t, alarm.AlarmActions, "Alarm actions should not be empty")
		if *alarm.MetricName == "StatusCheckFailed" {
			assert.NotEmpty(t, alarm.OKActions, "OK actions should not be empty for status check alarm")
			assert.NotEmpty(t, alarm.InsufficientDataActions, "Insufficient data actions should not be empty")
		}
	}
}

func validateComplianceMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID and alarm ARN
	hostID := terraform.Output(t, terraformOptions, "host_id")
	alarmARN := terraform.Output(t, terraformOptions, "cloudwatch_alarm_arn")
	
	require.NotEmpty(t, hostID)
	require.NotEmpty(t, alarmARN)
	
	// Extract alarm name from ARN
	alarmName := extractResourceNameFromARN(alarmARN)
	
	// Describe the alarm
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []*string{awssdk.String(alarmName)},
	}
	
	result, err := cloudwatchClient.DescribeAlarms(input)
	require.NoError(t, err)
	require.Len(t, result.MetricAlarms, 1)
	
	alarm := result.MetricAlarms[0]
	
	// Validate compliance-specific settings
	assert.Equal(t, "breaching", *alarm.TreatMissingData, "For compliance, missing data should be treated as breaching")
	assert.Len(t, alarm.AlarmActions, 2, "Should have 2 alarm actions for compliance (regular + security team)")
	assert.NotEmpty(t, alarm.OKActions, "Should have OK actions for compliance monitoring")
	
	// Validate tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	assert.Contains(t, tags, "SecurityContact")
	assert.Equal(t, "pci-dss", tags["Compliance"])
}

func validateAggressiveMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Describe all alarms
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("host-%s", hostID)),
	}
	
	result, err := cloudwatchClient.DescribeAlarms(input)
	require.NoError(t, err)
	
	// We should have at least 2 alarms (status check and CPU)
	assert.GreaterOrEqual(t, len(result.MetricAlarms), 2)
	
	// Validate status check alarm settings
	statusCheckAlarm := findAlarmByMetricName(result.MetricAlarms, "StatusCheckFailed")
	require.NotNil(t, statusCheckAlarm)
	assert.Equal(t, int64(1), *statusCheckAlarm.EvaluationPeriods, "Aggressive monitoring should use 1 evaluation period")
	assert.Equal(t, float64(1), *statusCheckAlarm.Threshold)
	assert.Equal(t, "GreaterThanOrEqualToThreshold", *statusCheckAlarm.ComparisonOperator)
	
	// Validate CPU alarm settings
	cpuAlarm := findAlarmByMetricName(result.MetricAlarms, "CPUUtilization")
	require.NotNil(t, cpuAlarm)
	assert.Equal(t, float64(60), *cpuAlarm.Threshold, "Aggressive monitoring should use lower CPU threshold")
	assert.Equal(t, int64(1), *cpuAlarm.EvaluationPeriods)
	assert.Equal(t, int64(60), *cpuAlarm.Period, "Should check every minute")
	
	// Validate alarm actions
	for _, alarm := range result.MetricAlarms {
		assert.NotEmpty(t, alarm.AlarmActions)
		assert.Contains(t, *alarm.AlarmActions[0], "urgent-alerts")
	}
}

func validateDisabledMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Verify that no alarm was created
	alarmARN := terraform.Output(t, terraformOptions, "cloudwatch_alarm_arn")
	assert.Empty(t, alarmARN, "No alarm should be created when monitoring is disabled")
}

func validateCompositeAlarm(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Describe all alarms
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("host-%s", hostID)),
	}
	
	result, err := cloudwatchClient.DescribeAlarms(input)
	require.NoError(t, err)
	
	// We should have metric alarms and composite alarms
	assert.GreaterOrEqual(t, len(result.MetricAlarms), 2, "Should have at least 2 metric alarms")
	assert.GreaterOrEqual(t, len(result.CompositeAlarms), 1, "Should have at least 1 composite alarm")
	
	// Validate composite alarm
	compositeAlarm := result.CompositeAlarms[0]
	assert.Contains(t, *compositeAlarm.AlarmName, "critical_condition")
	assert.Contains(t, *compositeAlarm.AlarmRule, "ALARM(StatusCheckFailed)")
	assert.Contains(t, *compositeAlarm.AlarmRule, "ALARM(CPUUtilization)")
	assert.NotEmpty(t, compositeAlarm.AlarmActions)
	assert.Contains(t, *compositeAlarm.AlarmActions[0], "critical-alerts")
}

// Helper functions

func extractResourceNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func findAlarmByMetricName(alarms []*cloudwatch.MetricAlarm, metricName string) *cloudwatch.MetricAlarm {
	for _, alarm := range alarms {
		if alarm.MetricName != nil && *alarm.MetricName == metricName {
			return alarm
		}
	}
	return nil
}

