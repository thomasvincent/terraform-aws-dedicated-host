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

// TestSecurityAlertPatterns tests various security-focused alert patterns
func TestSecurityAlertPatterns(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	alertTestCases := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "security_breach_detection",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
					"arn:aws:sns:us-west-2:123456789012:incident-response",
				},
				"security_alerts": map[string]interface{}{
					"high_cpu_utilization": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           90,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
					},
					"network_traffic_spike": map[string]interface{}{
						"metric_name":         "NetworkIn",
						"threshold":           1000000000, // 1GB/s
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
					},
					"system_status_failure": map[string]interface{}{
						"metric_name":         "StatusCheckFailed_System",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
					},
				},
				"composite_alarms": map[string]interface{}{
					"potential_security_breach": map[string]interface{}{
						"alarm_rule": "ALARM(CPUUtilization) AND ALARM(NetworkIn)",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-critical",
							"arn:aws:sns:us-west-2:123456789012:soc-team",
						},
					},
				},
				"tags": map[string]string{
					"Environment":      "production",
					"Project":          "security-monitoring",
					"ManagedBy":        "terraform",
					"CostCenter":       "security",
					"SecurityMonitoring": "enhanced",
				},
			},
			validation: validateSecurityBreachDetection,
		},
		{
			name: "compliance_violation_detection",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:compliance-alerts",
				},
				"compliance_alerts": map[string]interface{}{
					"configuration_change": map[string]interface{}{
						"metric_name":         "ConfigurationChanges",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              300,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
					},
					"unauthorized_access": map[string]interface{}{
						"metric_name":         "UnauthorizedAPIAttempts",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              300,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
					},
					"root_account_usage": map[string]interface{}{
						"metric_name":         "RootAccountUsage",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "compliance-monitoring",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Compliance":         "pci-dss,hipaa",
					"ComplianceMonitoring": "enabled",
				},
			},
			validation: validateComplianceViolationDetection,
		},
		{
			name: "anomaly_detection_alerts",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:anomaly-alerts",
				},
				"anomaly_detection_alerts": map[string]interface{}{
					"cpu_anomaly": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"anomaly_threshold":   2.0, // Standard deviations
						"evaluation_periods":  3,
						"period":              300,
						"treat_missing_data":  "ignore",
					},
					"network_anomaly": map[string]interface{}{
						"metric_name":         "NetworkIn",
						"anomaly_threshold":   3.0, // Standard deviations
						"evaluation_periods":  3,
						"period":              300,
						"treat_missing_data":  "ignore",
					},
					"memory_anomaly": map[string]interface{}{
						"metric_name":         "MemoryUtilization",
						"anomaly_threshold":   2.0, // Standard deviations
						"evaluation_periods":  3,
						"period":              300,
						"treat_missing_data":  "ignore",
					},
				},
				"tags": map[string]string{
					"Environment":      "production",
					"Project":          "security-monitoring",
					"ManagedBy":        "terraform",
					"CostCenter":       "security",
					"AnomalyDetection": "enabled",
				},
			},
			validation: validateAnomalyDetectionAlerts,
		},
		{
			name: "escalating_alert_pattern",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"escalating_alerts": map[string]interface{}{
					"cpu_warning": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           70,
						"evaluation_periods":  3,
						"period":              300,
						"statistic":           "Average",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "missing",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:warning-alerts",
						},
					},
					"cpu_critical": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           85,
						"evaluation_periods":  2,
						"period":              300,
						"statistic":           "Average",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:critical-alerts",
							"arn:aws:sns:us-west-2:123456789012:operations-team",
						},
					},
					"cpu_emergency": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           95,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:emergency-alerts",
							"arn:aws:sns:us-west-2:123456789012:incident-response",
							"arn:aws:sns:us-west-2:123456789012:executive-team",
						},
					},
				},
				"tags": map[string]string{
					"Environment":      "production",
					"Project":          "security-monitoring",
					"ManagedBy":        "terraform",
					"CostCenter":       "security",
					"EscalationAlerts": "enabled",
				},
			},
			validation: validateEscalatingAlertPattern,
		},
	}

	for _, tc := range alertTestCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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

			test_structure.RunTestStage(t, "setup", func() {
				terraform.InitAndApply(t, terraformOptions)
			})

			test_structure.RunTestStage(t, "validate", func() {
				tc.validation(t, terraformOptions, awsRegion)
			})

			test_structure.RunTestStage(t, "teardown", func() {
				terraform.Destroy(t, terraformOptions)
			})
		})
	}
}

// Validation functions

func validateSecurityBreachDetection(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get all alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Verify security breach detection alarms
	
	// 1. CPU utilization alarm
	cpuAlarm := findAlarmByMetricName(alarms, "CPUUtilization")
	require.NotNil(t, cpuAlarm, "CPU utilization alarm not found")
	assert.Equal(t, float64(90), *cpuAlarm.Threshold, "CPU threshold should be 90%")
	assert.Equal(t, int64(1), *cpuAlarm.EvaluationPeriods, "Evaluation periods should be 1 for quick breach detection")
	assert.Equal(t, int64(60), *cpuAlarm.Period, "Period should be 60 seconds for quick breach detection")
	assert.Equal(t, "breaching", *cpuAlarm.TreatMissingData, "Missing data should be treated as breaching")
	
	// 2. Network traffic alarm
	networkAlarm := findAlarmByMetricName(alarms, "NetworkIn")
	require.NotNil(t, networkAlarm, "Network traffic alarm not found")
	assert.Equal(t, float64(1000000000), *networkAlarm.Threshold, "Network threshold should be 1GB/s")
	
	// 3. System status alarm
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed_System")
	require.NotNil(t, statusAlarm, "System status alarm not found")
	
	// 4. Composite alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	assert.NotEmpty(t, compositeAlarms, "Composite alarm should exist")
	
	// Verify at least one composite alarm contains the expected rule
	hasExpectedRule := false
	for _, alarm := range compositeAlarms {
		if strings.Contains(*alarm.AlarmName, "potential_security_breach") {
			assert.Contains(t, *alarm.AlarmRule, "ALARM(CPUUtilization)", "Composite alarm should include CPU utilization")
			assert.Contains(t, *alarm.AlarmRule, "ALARM(NetworkIn)", "Composite alarm should include network traffic")
			assert.Len(t, alarm.AlarmActions, 2, "Composite alarm should have 2 actions")
			hasExpectedRule = true
		}
	}
	assert.True(t, hasExpectedRule, "Composite alarm with expected rule not found")
	
	// 5. Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enhanced", tags["SecurityMonitoring"], "SecurityMonitoring tag should be 'enhanced'")
}

func validateComplianceViolationDetection(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get all alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Verify compliance violation detection alarms
	
	// 1. Configuration change alarm
	configAlarm := findAlarmByMetricName(alarms, "ConfigurationChanges")
	require.NotNil(t, configAlarm, "Configuration change alarm not found")
	assert.Equal(t, float64(0), *configAlarm.Threshold, "Configuration change threshold should be 0")
	assert.Equal(t, "Sum", *configAlarm.Statistic, "Statistic should be Sum")
	
	// 2. Unauthorized access alarm
	accessAlarm := findAlarmByMetricName(alarms, "UnauthorizedAPIAttempts")
	require.NotNil(t, accessAlarm, "Unauthorized access alarm not found")
	
	// 3. Root account usage alarm
	rootAlarm := findAlarmByMetricName(alarms, "RootAccountUsage")
	require.NotNil(t, rootAlarm, "Root account usage alarm not found")
	assert.Equal(t, int64(60), *rootAlarm.Period, "Period should be 60 seconds for root account monitoring")
	
	// 4. Verify alarm actions for compliance alerts
	for _, alarm := range []*cloudwatch.MetricAlarm{configAlarm, accessAlarm, rootAlarm} {
		assert.NotEmpty(t, alarm.AlarmActions, "Alarm actions should not be empty")
		assert.Contains(t, *alarm.AlarmActions[0], "compliance-alerts", "Alarm action should be compliance-alerts")
	}
	
	// 5. Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enabled", tags["ComplianceMonitoring"], "ComplianceMonitoring tag should be 'enabled'")
	assert.Contains(t, tags["Compliance"], "pci-dss", "Compliance tag should include 'pci-dss'")
	assert.Contains(t, tags["Compliance"], "hipaa", "Compliance tag should include 'hipaa'")
}

func validateAnomalyDetectionAlerts(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get all alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Verify anomaly detection alarms
	
	// 1. CPU anomaly alarm
	cpuAnomalyAlarm := findAnomalyAlarmByMetricName(alarms, "CPUUtilization")
	require.NotNil(t, cpuAnomalyAlarm, "CPU anomaly alarm not found")
	assert.Equal(t, int64(3), *cpuAnomalyAlarm.EvaluationPeriods, "Evaluation periods should be 3")
	assert.Equal(t, int64(300), *cpuAnomalyAlarm.Period, "Period should be 300 seconds")
	assert.Equal(t, "ignore", *cpuAnomalyAlarm.TreatMissingData, "Missing data should be ignored for anomaly detection")
	
	// 2. Network anomaly alarm
	networkAnomalyAlarm := findAnomalyAlarmByMetricName(alarms, "NetworkIn")
	require.NotNil(t, networkAnomalyAlarm, "Network anomaly alarm not found")
	
	// 3. Memory anomaly alarm
	memoryAnomalyAlarm := findAnomalyAlarmByMetricName(alarms, "MemoryUtilization")
	require.NotNil(t, memoryAnomalyAlarm, "Memory anomaly alarm not found")
	
	// 4. Verify alarm actions for anomaly alerts
	for _, alarm := range []*cloudwatch.MetricAlarm{cpuAnomalyAlarm, networkAnomalyAlarm, memoryAnomalyAlarm} {
		assert.NotEmpty(t, alarm.AlarmActions, "Alarm actions should not be empty")
		assert.Contains(t, *alarm.AlarmActions[0], "anomaly-alerts", "Alarm action should be anomaly-alerts")
	}
	
	// 5. Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enabled", tags["AnomalyDetection"], "AnomalyDetection tag should be 'enabled'")
}

func validateEscalatingAlertPattern(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get all alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Group CPU alarms by threshold for escalation validation
	cpuAlarms := make(map[float64]*cloudwatch.MetricAlarm)
	for _, alarm := range alarms {
		if alarm.MetricName != nil && *alarm.MetricName == "CPUUtilization" {
			cpuAlarms[*alarm.Threshold] = alarm
		}
	}
	
	// Verify escalating alert pattern
	
	// 1. Warning level (70%)
	warningAlarm, ok := cpuAlarms[70]
	require.True(t, ok, "Warning level alarm (70%) not found")
	assert.Equal(t, int64(3), *warningAlarm.EvaluationPeriods, "Warning level should have 3 evaluation periods")
	assert.Equal(t, int64(300), *warningAlarm.Period, "Warning level should have 300 second period")
	assert.Equal(t, "Average", *warningAlarm.Statistic, "Warning level should use Average statistic")
	assert.Len(t, warningAlarm.AlarmActions, 1, "Warning level should have 1 action")
	
	// 2. Critical level (85%)
	criticalAlarm, ok := cpuAlarms[85]
	require.True(t, ok, "Critical level alarm (85%) not found")
	assert.Equal(t, int64(2), *criticalAlarm.EvaluationPeriods, "Critical level should have 2 evaluation periods")
	assert.Equal(t, "breaching", *criticalAlarm.TreatMissingData, "Critical level should treat missing data as breaching")
	assert.Len(t, criticalAlarm.AlarmActions, 2, "Critical level should have 2 actions")
	
	// 3. Emergency level (95%)
	emergencyAlarm, ok := cpuAlarms[95]
	require.True(t, ok, "Emergency level alarm (95%) not found")
	assert.Equal(t, int64(1), *emergencyAlarm.EvaluationPeriods, "Emergency level should have 1 evaluation period")
	assert.Equal(t, int64(60), *emergencyAlarm.Period, "Emergency level should have 60 second period")
	assert.Equal(t, "Maximum", *emergencyAlarm.Statistic, "Emergency level should use Maximum statistic")
	assert.Len(t, emergencyAlarm.AlarmActions, 3, "Emergency level should have 3 actions")
	
	// Verify alert action escalation
	assert.Contains(t, *emergencyAlarm.AlarmActions[0], "emergency-alerts", "Emergency level should notify emergency-alerts")
	assert.Contains(t, *emergencyAlarm.AlarmActions[1], "incident-response", "Emergency level should notify incident-response")
	assert.Contains(t, *emergencyAlarm.AlarmActions[2], "executive-team", "Emergency level should notify executive-team")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enabled", tags["EscalationAlerts"], "EscalationAlerts tag should be 'enabled'")
}

// Helper functions for alarm retrieval and finding

func getAlarmsForHost(client *cloudwatch.CloudWatch, hostId string) ([]*cloudwatch.MetricAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("host-%s", hostId)),
	}
	
	result, err := client.DescribeAlarms(input)
	if err != nil {
		return nil, err
	}
	
	return result.MetricAlarms, nil
}

func getCompositeAlarmsForHost(client *cloudwatch.CloudWatch, hostId string) ([]*cloudwatch.CompositeAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("host-%s", hostId)),
	}
	
	result, err := client.DescribeAlarms(input)
	if err != nil {
		return nil, err
	}
	
	return result.CompositeAlarms, nil
}

func findAlarmByMetricName(alarms []*cloudwatch.MetricAlarm, metricName string) *cloudwatch.MetricAlarm {
	for _, alarm := range alarms {
		if alarm.MetricName != nil && *alarm.MetricName == metricName {
			return alarm
		}
	}
	return nil
}

func findAnomalyAlarmByMetricName(alarms []*cloudwatch.MetricAlarm, metricName string) *cloudwatch.MetricAlarm {
	for _, alarm := range alarms {
		if alarm.MetricName != nil && 
		   *alarm.MetricName == metricName && 
		   alarm.ThresholdMetricId != nil {
			return alarm
		}
	}
	return nil
}

