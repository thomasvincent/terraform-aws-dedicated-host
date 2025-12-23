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

// TestAlertIntegrationScenarios tests interactions between different alert types in security scenarios
func TestAlertIntegrationScenarios(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	scenarios := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "breach_detection_with_anomaly",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alert_patterns": map[string]interface{}{
					// Standard threshold-based CPU alert
					"cpu_breach": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           90,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
					},
					// Anomaly detection alert for CPU
					"cpu_anomaly": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"anomaly_threshold":   2.0, // Standard deviations
						"evaluation_periods":  2,
						"period":              300,
						"treat_missing_data":  "ignore",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
					},
				},
				// Composite alert that combines both threshold breach and anomaly detection
				"composite_alerts": map[string]interface{}{
					"combined_cpu_alert": map[string]interface{}{
						"alarm_rule": "ALARM(cpu_breach) AND ALARM(cpu_anomaly)",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-critical",
							"arn:aws:sns:us-west-2:123456789012:incident-response",
						},
					},
				},
				"tags": map[string]string{
					"Environment":          "production",
					"Project":              "security-monitoring",
					"ManagedBy":            "terraform",
					"CostCenter":           "security",
					"IntegratedMonitoring": "enabled",
				},
			},
			validation: validateBreachWithAnomaly,
		},
		{
			name: "compliance_violation_chain",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alert_patterns": map[string]interface{}{
					// Configuration change detection
					"config_change": map[string]interface{}{
						"metric_name":         "ConfigurationChanges",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              300,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:config-team",
						},
					},
					// Unauthorized access detection
					"unauthorized_access": map[string]interface{}{
						"metric_name":         "UnauthorizedAPIAttempts",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              300,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
					},
					// API call volume detection
					"api_call_volume": map[string]interface{}{
						"metric_name":         "APICallCount",
						"threshold":           100,
						"evaluation_periods":  2,
						"period":              300,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:operations-team",
						},
					},
				},
				// Composite alert that chains compliance violations
				"composite_alerts": map[string]interface{}{
					"compliance_chain": map[string]interface{}{
						"alarm_rule": "ALARM(config_change) AND (ALARM(unauthorized_access) OR ALARM(api_call_volume))",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:compliance-critical",
							"arn:aws:sns:us-west-2:123456789012:security-incident",
							"arn:aws:sns:us-west-2:123456789012:audit-team",
						},
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "compliance-monitoring",
					"ManagedBy":          "terraform",
					"CostCenter":         "compliance",
					"Compliance":         "pci-dss,hipaa",
					"ComplianceMonitoring": "enhanced",
				},
			},
			validation: validateComplianceViolationChain,
		},
		{
			name: "multi_level_escalation_with_anomaly",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alert_patterns": map[string]interface{}{
					// Warning level (70% CPU)
					"cpu_warning": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           70,
						"evaluation_periods":  3,
						"period":              300,
						"statistic":           "Average",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "missing",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:monitoring-team",
						},
					},
					// Critical level (85% CPU)
					"cpu_critical": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           85,
						"evaluation_periods":  2,
						"period":              300,
						"statistic":           "Average",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:operations-team",
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
					},
					// Emergency level (95% CPU)
					"cpu_emergency": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"threshold":           95,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:incident-response",
							"arn:aws:sns:us-west-2:123456789012:executive-team",
						},
					},
					// CPU anomaly detection
					"cpu_anomaly": map[string]interface{}{
						"metric_name":         "CPUUtilization",
						"anomaly_threshold":   2.0, // Standard deviations
						"evaluation_periods":  2,
						"period":              300,
						"treat_missing_data":  "ignore",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:monitoring-team",
						},
					},
				},
				// Composite alerts that combine escalation levels with anomaly detection
				"composite_alerts": map[string]interface{}{
					"anomaly_critical": map[string]interface{}{
						"alarm_rule": "ALARM(cpu_critical) AND ALARM(cpu_anomaly)",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-escalation",
						},
					},
					"anomaly_emergency": map[string]interface{}{
						"alarm_rule": "ALARM(cpu_emergency) AND ALARM(cpu_anomaly)",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:ceo-direct",
							"arn:aws:sns:us-west-2:123456789012:incident-war-room",
						},
					},
				},
				"tags": map[string]string{
					"Environment":      "production",
					"Project":          "security-monitoring",
					"ManagedBy":        "terraform",
					"CostCenter":       "security",
					"EscalationAlerts": "multi-level",
					"AnomalyDetection": "enabled",
				},
			},
			validation: validateMultiLevelEscalationWithAnomaly,
		},
		{
			name: "security_incident_detection",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alert_patterns": map[string]interface{}{
					// Network traffic spike
					"network_spike": map[string]interface{}{
						"metric_name":         "NetworkIn",
						"threshold":           1000000000, // 1GB/s
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:network-team",
						},
					},
					// Unusual API activity
					"api_activity": map[string]interface{}{
						"metric_name":         "APICallCount",
						"threshold":           200,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Sum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "notBreaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:operations-team",
						},
					},
					// Host status check
					"host_status": map[string]interface{}{
						"metric_name":         "StatusCheckFailed",
						"threshold":           0,
						"evaluation_periods":  1,
						"period":              60,
						"statistic":           "Maximum",
						"comparison_operator": "GreaterThanThreshold",
						"treat_missing_data":  "breaching",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:operations-team",
						},
					},
				},
				// Composite alerts for incident detection
				"composite_alerts": map[string]interface{}{
					"potential_attack": map[string]interface{}{
						"alarm_rule": "ALARM(network_spike) AND ALARM(api_activity)",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:security-incident",
							"arn:aws:sns:us-west-2:123456789012:soc-team",
						},
					},
					"host_compromise": map[string]interface{}{
						"alarm_rule": "(ALARM(network_spike) OR ALARM(api_activity)) AND ALARM(host_status)",
						"actions": []string{
							"arn:aws:sns:us-west-2:123456789012:incident-response",
							"arn:aws:sns:us-west-2:123456789012:security-critical",
							"arn:aws:sns:us-west-2:123456789012:executive-team",
						},
					},
				},
				"tags": map[string]string{
					"Environment":      "production",
					"Project":          "security-monitoring",
					"ManagedBy":        "terraform",
					"CostCenter":       "security",
					"SecurityIncidentDetection": "enhanced",
				},
			},
			validation: validateSecurityIncidentDetection,
		},
	}

	for _, scenario := range scenarios {
		scenario := scenario // capture range variable
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			// Merge with test case configuration
			for k, v := range scenario.configuration {
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
				scenario.validation(t, terraformOptions, awsRegion)
			})

			test_structure.RunTestStage(t, "teardown", func() {
				terraform.Destroy(t, terraformOptions)
			})
		})
	}
}

// Validation functions for integration scenarios

func validateBreachWithAnomaly(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
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
	
	// Verify standard CPU breach alarm
	cpuBreachAlarm := findAlarmByName(alarms, "cpu_breach")
	require.NotNil(t, cpuBreachAlarm, "Standard CPU breach alarm not found")
	assert.Equal(t, float64(90), *cpuBreachAlarm.Threshold, "CPU breach threshold should be 90%")
	assert.Equal(t, int64(1), *cpuBreachAlarm.EvaluationPeriods, "Breach alarm should have 1 evaluation period")
	assert.Equal(t, int64(60), *cpuBreachAlarm.Period, "Breach alarm should have 60 second period")
	
	// Verify CPU anomaly detection alarm
	cpuAnomalyAlarm := findAlarmByName(alarms, "cpu_anomaly")
	require.NotNil(t, cpuAnomalyAlarm, "CPU anomaly detection alarm not found")
	assert.Equal(t, int64(2), *cpuAnomalyAlarm.EvaluationPeriods, "Anomaly alarm should have 2 evaluation periods")
	assert.Equal(t, int64(300), *cpuAnomalyAlarm.Period, "Anomaly alarm should have 300 second period")
	
	// Verify composite alarm that combines breach and anomaly
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	assert.NotEmpty(t, compositeAlarms, "Composite alarms should exist")
	
	combinedAlarm := findCompositeAlarmByName(compositeAlarms, "combined_cpu_alert")
	require.NotNil(t, combinedAlarm, "Combined CPU alert not found")
	
	// Verify composite alarm rule
	assert.Contains(t, *combinedAlarm.AlarmRule, "ALARM(cpu_breach)", "Composite alarm should reference CPU breach")
	assert.Contains(t, *combinedAlarm.AlarmRule, "ALARM(cpu_anomaly)", "Composite alarm should reference CPU anomaly")
	assert.Contains(t, *combinedAlarm.AlarmRule, "AND", "Composite alarm should use AND operator")
	
	// Verify composite alarm actions
	assert.Len(t, combinedAlarm.AlarmActions, 2, "Combined alarm should have 2 actions")
	assert.Contains(t, *combinedAlarm.AlarmActions[0], "security-critical", "Should notify security-critical")
	assert.Contains(t, *combinedAlarm.AlarmActions[1], "incident-response", "Should notify incident-response")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enabled", tags["IntegratedMonitoring"], "IntegratedMonitoring tag should be 'enabled'")
}

func validateComplianceViolationChain(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
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
	
	// Verify individual compliance alarms
	configChangeAlarm := findAlarmByName(alarms, "config_change")
	require.NotNil(t, configChangeAlarm, "Configuration change alarm not found")
	assert.Equal(t, "Sum", *configChangeAlarm.Statistic, "Config change alarm should use Sum statistic")
	
	unauthorizedAccessAlarm := findAlarmByName(alarms, "unauthorized_access")
	require.NotNil(t, unauthorizedAccessAlarm, "Unauthorized access alarm not found")
	
	apiCallVolumeAlarm := findAlarmByName(alarms, "api_call_volume")
	require.NotNil(t, apiCallVolumeAlarm, "API call volume alarm not found")
	assert.Equal(t, float64(100), *apiCallVolumeAlarm.Threshold, "API call volume threshold should be 100")
	
	// Verify composite alarm that chains compliance violations
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	assert.NotEmpty(t, compositeAlarms, "Composite alarms should exist")
	
	complianceChainAlarm := findCompositeAlarmByName(compositeAlarms, "compliance_chain")
	require.NotNil(t, complianceChainAlarm, "Compliance chain alarm not found")
	
	// Verify composite alarm rule structure
	assert.Contains(t, *complianceChainAlarm.AlarmRule, "ALARM(config_change)", "Should reference config change")
	assert.Contains(t, *complianceChainAlarm.AlarmRule, "ALARM(unauthorized_access)", "Should reference unauthorized access")
	assert.Contains(t, *complianceChainAlarm.AlarmRule, "ALARM(api_call_volume)", "Should reference API call volume")
	assert.Contains(t, *complianceChainAlarm.AlarmRule, "AND", "Should use AND operator")
	assert.Contains(t, *complianceChainAlarm.AlarmRule, "OR", "Should use OR operator")
	
	// Verify composite alarm actions - should have multiple notification targets
	assert.Len(t, complianceChainAlarm.AlarmActions, 3, "Should have 3 notification targets")
	assert.Contains(t, *complianceChainAlarm.AlarmActions[0], "compliance-critical", "Should notify compliance-critical")
	assert.Contains(t, *complianceChainAlarm.AlarmActions[1], "security-incident", "Should notify security-incident")
	assert.Contains(t, *complianceChainAlarm.AlarmActions[2], "audit-team", "Should notify audit-team")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enhanced", tags["ComplianceMonitoring"], "ComplianceMonitoring tag should be 'enhanced'")
	assert.Contains(t, tags["Compliance"], "pci-dss", "Compliance tag should include 'pci-dss'")
	assert.Contains(t, tags["Compliance"], "hipaa", "Compliance tag should include 'hipaa'")
}

func validateMultiLevelEscalationWithAnomaly(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
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
	
	// Verify escalation level alarms
	warningAlarm := findAlarmByName(alarms, "cpu_warning")
	require.NotNil(t, warningAlarm, "Warning level alarm not found")
	assert.Equal(t, float64(70), *warningAlarm.Threshold, "Warning threshold should be 70%")
	assert.Equal(t, int64(3), *warningAlarm.EvaluationPeriods, "Warning should have 3 evaluation periods")
	assert.Equal(t, "Average", *warningAlarm.Statistic, "Warning should use Average statistic")
	
	criticalAlarm := findAlarmByName(alarms, "cpu_critical")
	require.NotNil(t, criticalAlarm, "Critical level alarm not found")
	assert.Equal(t, float64(85), *criticalAlarm.Threshold, "Critical threshold should be 85%")
	assert.Equal(t, int64(2), *criticalAlarm.EvaluationPeriods, "Critical should have 2 evaluation periods")
	assert.Len(t, criticalAlarm.AlarmActions, 2, "Critical should have 2 notification targets")
	
	emergencyAlarm := findAlarmByName(alarms, "cpu_emergency")
	require.NotNil(t, emergencyAlarm, "Emergency level alarm not found")
	assert.Equal(t, float64(95), *emergencyAlarm.Threshold, "Emergency threshold should be 95%")
	assert.Equal(t, int64(1), *emergencyAlarm.EvaluationPeriods, "Emergency should have 1 evaluation period")
	assert.Equal(t, int64(60), *emergencyAlarm.Period, "Emergency should have 60 second period")
	assert.Equal(t, "Maximum", *emergencyAlarm.Statistic, "Emergency should use Maximum statistic")
	
	// Verify anomaly detection alarm
	anomalyAlarm := findAlarmByName(alarms, "cpu_anomaly")
	require.NotNil(t, anomalyAlarm, "CPU anomaly alarm not found")
	
	// Verify composite alarms
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	assert.NotEmpty(t, compositeAlarms, "Composite alarms should exist")
	
	// Verify critical + anomaly composite alarm
	criticalAnomalyAlarm := findCompositeAlarmByName(compositeAlarms, "anomaly_critical")
	require.NotNil(t, criticalAnomalyAlarm, "Critical anomaly alarm not found")
	assert.Contains(t, *criticalAnomalyAlarm.AlarmRule, "ALARM(cpu_critical)", "Should reference critical level")
	assert.Contains(t, *criticalAnomalyAlarm.AlarmRule, "ALARM(cpu_anomaly)", "Should reference anomaly detection")
	assert.Len(t, criticalAnomalyAlarm.AlarmActions, 1, "Should have security escalation action")
	
	// Verify emergency + anomaly composite alarm
	emergencyAnomalyAlarm := findCompositeAlarmByName(compositeAlarms, "anomaly_emergency")
	require.NotNil(t, emergencyAnomalyAlarm, "Emergency anomaly alarm not found")
	assert.Contains(t, *emergencyAnomalyAlarm.AlarmRule, "ALARM(cpu_emergency)", "Should reference emergency level")
	assert.Contains(t, *emergencyAnomalyAlarm.AlarmRule, "ALARM(cpu_anomaly)", "Should reference anomaly detection")
	assert.Len(t, emergencyAnomalyAlarm.AlarmActions, 2, "Should have two emergency actions")
	assert.Contains(t, *emergencyAnomalyAlarm.AlarmActions[0], "ceo-direct", "Should notify CEO directly")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "multi-level", tags["EscalationAlerts"], "EscalationAlerts tag should be 'multi-level'")
	assert.Equal(t, "enabled", tags["AnomalyDetection"], "AnomalyDetection tag should be 'enabled'")
}

func validateSecurityIncidentDetection(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
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
	
	// Verify individual security incident alarms
	networkSpikeAlarm := findAlarmByName(alarms, "network_spike")
	require.NotNil(t, networkSpikeAlarm, "Network spike alarm not found")
	assert.Equal(t, float64(1000000000), *networkSpikeAlarm.Threshold, "Network threshold should be 1GB/s")
	
	apiActivityAlarm := findAlarmByName(alarms, "api_activity")
	require.NotNil(t, apiActivityAlarm, "API activity alarm not found")
	assert.Equal(t, float64(200), *apiActivityAlarm.Threshold, "API threshold should be 200")
	
	hostStatusAlarm := findAlarmByName(alarms, "host_status")
	require.NotNil(t, hostStatusAlarm, "Host status alarm not found")
	
	// Verify composite alarms
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	assert.NotEmpty(t, compositeAlarms, "Composite alarms should exist")
	
	// Verify potential attack composite alarm
	potentialAttackAlarm := findCompositeAlarmByName(compositeAlarms, "potential_attack")
	require.NotNil(t, potentialAttackAlarm, "Potential attack alarm not found")
	assert.Contains(t, *potentialAttackAlarm.AlarmRule, "ALARM(network_spike)", "Should reference network spike")
	assert.Contains(t, *potentialAttackAlarm.AlarmRule, "ALARM(api_activity)", "Should reference API activity")
	assert.Contains(t, *potentialAttackAlarm.AlarmRule, "AND", "Should use AND operator")
	assert.Len(t, potentialAttackAlarm.AlarmActions, 2, "Should have 2 notification targets")
	
	// Verify host compromise composite alarm
	hostCompromiseAlarm := findCompositeAlarmByName(compositeAlarms, "host_compromise")
	require.NotNil(t, hostCompromiseAlarm, "Host compromise alarm not found")
	assert.Contains(t, *hostCompromiseAlarm.AlarmRule, "ALARM(network_spike)", "Should reference network spike")
	assert.Contains(t, *hostCompromiseAlarm.AlarmRule, "ALARM(api_activity)", "Should reference API activity")
	assert.Contains(t, *hostCompromiseAlarm.AlarmRule, "ALARM(host_status)", "Should reference host status")
	assert.Contains(t, *hostCompromiseAlarm.AlarmRule, "OR", "Should use OR operator")
	assert.Contains(t, *hostCompromiseAlarm.AlarmRule, "AND", "Should use AND operator")
	assert.Len(t, hostCompromiseAlarm.AlarmActions, 3, "Should have 3 notification targets")
	assert.Contains(t, *hostCompromiseAlarm.AlarmActions[0], "incident-response", "Should notify incident response")
	assert.Contains(t, *hostCompromiseAlarm.AlarmActions[1], "security-critical", "Should notify security critical")
	assert.Contains(t, *hostCompromiseAlarm.AlarmActions[2], "executive-team", "Should notify executive team")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enhanced", tags["SecurityIncidentDetection"], "SecurityIncidentDetection tag should be 'enhanced'")
}

// Helper functions for finding alarms by name

func findAlarmByName(alarms []*cloudwatch.MetricAlarm, alarmName string) *cloudwatch.MetricAlarm {
	for _, alarm := range alarms {
		if alarm.AlarmName != nil && strings.Contains(*alarm.AlarmName, alarmName) {
			return alarm
		}
	}
	return nil
}

func findCompositeAlarmByName(alarms []*cloudwatch.CompositeAlarm, alarmName string) *cloudwatch.CompositeAlarm {
	for _, alarm := range alarms {
		if alarm.AlarmName != nil && strings.Contains(*alarm.AlarmName, alarmName) {
			return alarm
		}
	}
	return nil
}

