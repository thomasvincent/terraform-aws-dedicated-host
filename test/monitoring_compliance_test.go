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

// TestComplianceMonitoringRequirements tests monitoring configurations for various compliance frameworks
func TestComplianceMonitoringRequirements(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	complianceTestCases := []struct {
		name           string
		compliance     string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name:       "pci_dss_monitoring",
			compliance: "pci-dss",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
					"arn:aws:sns:us-west-2:123456789012:pci-notifications",
				},
				"ok_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:operations-team",
				},
				"evaluation_periods": 2,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching", // Required for PCI compliance
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           80,
						"evaluation_periods":  2,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
					"network_in": {
						"metric_name":         "NetworkIn",
						"threshold":           5000000, // 5MB/s
						"evaluation_periods":  3,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-tests",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "pci-dss",
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
				},
			},
			validation: validatePCIDSSMonitoring,
		},
		{
			name:       "hipaa_monitoring",
			compliance: "hipaa",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
					"arn:aws:sns:us-west-2:123456789012:compliance-team",
				},
				"ok_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:operations-team",
				},
				"evaluation_periods": 2,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching", // Required for HIPAA compliance
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           90,
						"evaluation_periods":  3,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
					"memory_utilization": {
						"metric_name":         "MemoryUtilization",
						"threshold":           90,
						"evaluation_periods":  3,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-tests",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "hipaa",
					"SecurityContact":    "security@example.com",
					"DataClassification": "phi",
				},
			},
			validation: validateHIPAAMonitoring,
		},
		{
			name:       "sox_monitoring",
			compliance: "sox",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
					"arn:aws:sns:us-west-2:123456789012:audit-team",
				},
				"ok_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:operations-team",
				},
				"evaluation_periods": 2,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching", // Required for SOX compliance
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           85,
						"evaluation_periods":  2,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-tests",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "sox",
					"SecurityContact":    "security@example.com",
					"DataClassification": "confidential",
					"Owner":              "finance",
				},
			},
			validation: validateSOXMonitoring,
		},
		{
			name:       "multi_compliance_monitoring",
			compliance: "multi",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
					"arn:aws:sns:us-west-2:123456789012:compliance-team",
				},
				"ok_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:operations-team",
				},
				"evaluation_periods": 2,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanThreshold",
				"threshold":           0,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching",
				"additional_alarms": map[string]map[string]interface{}{
					"cpu_utilization": {
						"metric_name":         "CPUUtilization",
						"threshold":           80,
						"evaluation_periods":  2,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
					"network_in": {
						"metric_name":         "NetworkIn",
						"threshold":           5000000,
						"evaluation_periods":  3,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
					"memory_utilization": {
						"metric_name":         "MemoryUtilization",
						"threshold":           90,
						"evaluation_periods":  3,
						"comparison_operator": "GreaterThanThreshold",
						"period":              300,
						"statistic":           "Average",
						"treat_missing_data":  "breaching",
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-tests",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "pci-dss,hipaa,sox",
					"SecurityContact":    "security@example.com",
					"DataClassification": "restricted",
					"Owner":              "finance",
				},
			},
			validation: validateMultiComplianceMonitoring,
		},
	}

	for _, tc := range complianceTestCases {
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

// TestDisasterRecoveryMonitoring tests disaster recovery monitoring configurations
func TestDisasterRecoveryMonitoring(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	drTestCases := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "standard_dr_configuration",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"host_recovery":     "on", // Required for DR
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:dr-team",
					"arn:aws:sns:us-west-2:123456789012:incident-response",
				},
				"evaluation_periods": 1, // Quick response for DR
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanOrEqualToThreshold",
				"threshold":           1,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching",
				"tags": map[string]string{
					"Environment":   "production",
					"Project":       "monitoring-tests",
					"ManagedBy":     "terraform",
					"CostCenter":    "operations",
					"DR_Tier":       "tier1",
					"RPO":           "1h",
					"RTO":           "4h",
					"BackupEnabled": "true",
				},
			},
			validation: validateStandardDRMonitoring,
		},
		{
			name: "high_availability_dr",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"host_recovery":     "on",
				"auto_placement":    "off",
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:dr-team",
					"arn:aws:sns:us-west-2:123456789012:incident-response",
					"arn:aws:sns:us-west-2:123456789012:executive-team",
				},
				"evaluation_periods": 1,
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanOrEqualToThreshold",
				"threshold":           1,
				"period":              60,
				"statistic":           "Maximum",
				"treat_missing_data":  "breaching",
				"additional_alarms": map[string]map[string]interface{}{
					"instance_status": {
						"metric_name":         "StatusCheckFailed_Instance",
						"threshold":           1,
						"evaluation_periods":  1,
						"comparison_operator": "GreaterThanOrEqualToThreshold",
						"period":              60,
						"statistic":           "Maximum",
						"treat_missing_data":  "breaching",
					},
					"system_status": {
						"metric_name":         "StatusCheckFailed_System",
						"threshold":           1,
						"evaluation_periods":  1,
						"comparison_operator": "GreaterThanOrEqualToThreshold",
						"period":              60,
						"statistic":           "Maximum",
						"treat_missing_data":  "breaching",
					},
				},
				"tags": map[string]string{
					"Environment":       "production",
					"Project":           "monitoring-tests",
					"ManagedBy":         "terraform",
					"CostCenter":        "operations",
					"DR_Tier":           "tier0", // Highest priority
					"RPO":               "0",     // Zero data loss
					"RTO":               "15m",   // 15 minutes recovery time
					"BackupEnabled":     "true",
					"HighAvailability":  "true",
					"FailoverRegion":    "us-east-1",
				},
			},
			validation: validateHighAvailabilityDRMonitoring,
		},
		{
			name: "cost_effective_dr",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"host_recovery":     "on",
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:dr-team",
				},
				"evaluation_periods": 2, // More tolerance
				"metric_name":        "StatusCheckFailed",
				"comparison_operator": "GreaterThanOrEqualToThreshold",
				"threshold":           1,
				"period":              300, // Less frequent checks
				"statistic":           "Maximum",
				"treat_missing_data":  "missing",
				"tags": map[string]string{
					"Environment":   "production",
					"Project":       "monitoring-tests",
					"ManagedBy":     "terraform",
					"CostCenter":    "operations",
					"DR_Tier":       "tier3", // Lower priority
					"RPO":           "24h",   // Daily backups
					"RTO":           "24h",   // 24-hour recovery
					"BackupEnabled": "true",
				},
			},
			validation: validateCostEffectiveDRMonitoring,
		},
	}

	for _, tc := range drTestCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
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

// Validation functions for compliance testing

func validatePCIDSSMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate PCI DSS specific requirements
	
	// 1. Status check alarm must exist and treat missing data as breaching
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for PCI DSS compliance")
	assert.Equal(t, "breaching", *statusAlarm.TreatMissingData, "PCI DSS requires missing data to be treated as breaching")
	
	// 2. CPU utilization alarm must exist
	cpuAlarm := findAlarmByMetricName(alarms, "CPUUtilization")
	require.NotNil(t, cpuAlarm, "CPU utilization monitoring is required for PCI DSS compliance")
	
	// 3. Network monitoring must exist
	networkAlarm := findAlarmByMetricName(alarms, "NetworkIn")
	require.NotNil(t, networkAlarm, "Network monitoring is required for PCI DSS compliance")
	
	// 4. At least two alarm actions (different teams) must be configured
	for _, alarm := range alarms {
		assert.GreaterOrEqual(t, len(alarm.AlarmActions), 2, "PCI DSS requires at least two notification endpoints")
	}
	
	// 5. Required tags must be present
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	assert.Contains(t, tags, "SecurityContact")
	assert.Contains(t, tags, "DataClassification")
	assert.Equal(t, "pci-dss", tags["Compliance"])
	assert.Equal(t, "restricted", tags["DataClassification"])
}

func validateHIPAAMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate HIPAA specific requirements
	
	// 1. Status check alarm must exist and treat missing data as breaching
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for HIPAA compliance")
	assert.Equal(t, "breaching", *statusAlarm.TreatMissingData, "HIPAA requires missing data to be treated as breaching")
	
	// 2. Memory utilization alarm must exist with higher evaluation periods for HIPAA
	memoryAlarm := findAlarmByMetricName(alarms, "MemoryUtilization")
	require.NotNil(t, memoryAlarm, "Memory utilization monitoring is required for HIPAA compliance")
	assert.Equal(t, int64(3), *memoryAlarm.EvaluationPeriods, "HIPAA requires more stringent evaluation periods")
	
	// 3. At least two alarm actions (different teams) must be configured
	for _, alarm := range alarms {
		assert.GreaterOrEqual(t, len(alarm.AlarmActions), 2, "HIPAA requires at least two notification endpoints")
	}
	
	// 4. Required tags must be present
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	assert.Contains(t, tags, "SecurityContact")
	assert.Contains(t, tags, "DataClassification")
	assert.Equal(t, "hipaa", tags["Compliance"])
	assert.Equal(t, "phi", tags["DataClassification"], "HIPAA compliance requires PHI data classification")
}

func validateSOXMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate SOX specific requirements
	
	// 1. Status check alarm must exist and treat missing data as breaching
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for SOX compliance")
	assert.Equal(t, "breaching", *statusAlarm.TreatMissingData, "SOX requires missing data to be treated as breaching")
	
	// 2. CPU utilization alarm must exist
	cpuAlarm := findAlarmByMetricName(alarms, "CPUUtilization")
	require.NotNil(t, cpuAlarm, "CPU utilization monitoring is required for SOX compliance")
	
	// 3. At least two alarm actions (different teams) must be configured
	for _, alarm := range alarms {
		assert.GreaterOrEqual(t, len(alarm.AlarmActions), 2, "SOX requires at least two notification endpoints")
		assert.Contains(t, *alarm.AlarmActions[1], "audit-team", "SOX requires audit team notification")
	}
	
	// 4. Required tags must be present
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	assert.Contains(t, tags, "SecurityContact")
	assert.Contains(t, tags, "DataClassification")
	assert.Contains(t, tags, "Owner")
	assert.Equal(t, "sox", tags["Compliance"])
	assert.Equal(t, "finance", tags["Owner"], "SOX compliance requires finance ownership")
}

func validateMultiComplianceMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate multi-compliance requirements (PCI-DSS, HIPAA, SOX)
	
	// 1. Status check alarm must exist and treat missing data as breaching
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for compliance")
	assert.Equal(t, "breaching", *statusAlarm.TreatMissingData)
	
	// 2. Must have CPU, Network, and Memory alarms for combined compliance
	cpuAlarm := findAlarmByMetricName(alarms, "CPUUtilization")
	require.NotNil(t, cpuAlarm, "CPU monitoring required for multi-compliance")
	
	networkAlarm := findAlarmByMetricName(alarms, "NetworkIn")
	require.NotNil(t, networkAlarm, "Network monitoring required for PCI-DSS compliance")
	
	memoryAlarm := findAlarmByMetricName(alarms, "MemoryUtilization")
	require.NotNil(t, memoryAlarm, "Memory monitoring required for HIPAA compliance")
	
	// 3. Required tags must be present for all frameworks
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "Compliance")
	assert.Contains(t, tags, "SecurityContact")
	assert.Contains(t, tags, "DataClassification")
	assert.Contains(t, tags, "Owner")
	
	// 4. Compliance tag should contain all frameworks
	complianceTag := tags["Compliance"]
	assert.Contains(t, complianceTag, "pci-dss")
	assert.Contains(t, complianceTag, "hipaa")
	assert.Contains(t, complianceTag, "sox")
}

// Validation functions for disaster recovery testing

func validateStandardDRMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate standard DR configuration
	
	// 1. Status check alarm must exist with quick evaluation period (1)
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for DR")
	assert.Equal(t, int64(1), *statusAlarm.EvaluationPeriods, "DR requires quick response to failures")
	assert.Equal(t, int64(60), *statusAlarm.Period, "DR requires frequent checking")
	assert.Equal(t, "breaching", *statusAlarm.TreatMissingData, "DR requires treating missing data as breaching")
	
	// 2. Must have DR team notification
	hasIncidentResponseAction := false
	for _, action := range statusAlarm.AlarmActions {
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponseAction = true
			break
		}
	}
	assert.True(t, hasIncidentResponseAction, "DR monitoring requires incident response team notification")
	
	// 3. Required DR tags must be present
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "DR_Tier")
	assert.Contains(t, tags, "RPO")
	assert.Contains(t, tags, "RTO")
	assert.Contains(t, tags, "BackupEnabled")
	assert.Equal(t, "tier1", tags["DR_Tier"])
	assert.Equal(t, "1h", tags["RPO"])
	assert.Equal(t, "4h", tags["RTO"])
	assert.Equal(t, "true", tags["BackupEnabled"])
	
	// 4. Host recovery must be enabled
	hostRecovery := terraform.Output(t, terraformOptions, "host_recovery")
	assert.Equal(t, "on", hostRecovery, "DR requires host recovery to be enabled")
}

func validateHighAvailabilityDRMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate high availability DR configuration
	
	// 1. Status check alarm must exist with quick evaluation period (1)
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for high availability DR")
	assert.Equal(t, int64(1), *statusAlarm.EvaluationPeriods, "High availability requires immediate response to failures")
	
	// 2. Must have instance and system status check alarms
	instanceStatusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed_Instance")
	require.NotNil(t, instanceStatusAlarm, "Instance status check alarm is required for high availability")
	
	systemStatusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed_System")
	require.NotNil(t, systemStatusAlarm, "System status check alarm is required for high availability")
	
	// 3. Must have executive team notification for high availability
	hasExecutiveAction := false
	for _, action := range statusAlarm.AlarmActions {
		if strings.Contains(*action, "executive-team") {
			hasExecutiveAction = true
			break
		}
	}
	assert.True(t, hasExecutiveAction, "High availability requires executive notification")
	
	// 4. Required high availability tags must be present
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "DR_Tier")
	assert.Contains(t, tags, "RPO")
	assert.Contains(t, tags, "RTO")
	assert.Contains(t, tags, "BackupEnabled")
	assert.Contains(t, tags, "HighAvailability")
	assert.Contains(t, tags, "FailoverRegion")
	assert.Equal(t, "tier0", tags["DR_Tier"])
	assert.Equal(t, "0", tags["RPO"])
	assert.Equal(t, "15m", tags["RTO"])
	assert.Equal(t, "true", tags["HighAvailability"])
	
	// 5. Host recovery and auto placement must be configured correctly
	hostRecovery := terraform.Output(t, terraformOptions, "host_recovery")
	autoPlacement := terraform.Output(t, terraformOptions, "auto_placement")
	assert.Equal(t, "on", hostRecovery, "High availability requires host recovery to be enabled")
	assert.Equal(t, "off", autoPlacement, "High availability requires controlled instance placement")
}

func validateCostEffectiveDRMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create CloudWatch client
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Get alarms for this host
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)
	
	// Validate cost effective DR configuration
	
	// 1. Status check alarm must exist with less strict settings
	statusAlarm := findAlarmByMetricName(alarms, "StatusCheckFailed")
	require.NotNil(t, statusAlarm, "Status check alarm is required for DR")
	assert.Equal(t, int64(2), *statusAlarm.EvaluationPeriods, "Cost effective DR allows more evaluation periods")
	assert.Equal(t, int64(300), *statusAlarm.Period, "Cost effective DR uses less frequent checking")
	assert.Equal(t, "missing", *statusAlarm.TreatMissingData, "Cost effective DR allows missing data")
	
	// 2. Fewer notification actions are acceptable
	assert.Len(t, statusAlarm.AlarmActions, 1, "Cost effective DR uses fewer notification endpoints")
	
	// 3. Required DR tags must be present with longer RPO/RTO
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Contains(t, tags, "DR_Tier")
	assert.Contains(t, tags, "RPO")
	assert.Contains(t, tags, "RTO")
	assert.Equal(t, "tier3", tags["DR_Tier"])
	assert.Equal(t, "24h", tags["RPO"])
	assert.Equal(t, "24h", tags["RTO"])
	
	// 4. Host recovery must still be enabled
	hostRecovery := terraform.Output(t, terraformOptions, "host_recovery")
	assert.Equal(t, "on", hostRecovery, "Even cost effective DR requires host recovery to be enabled")
}

// Helper functions

func getAlarmsForHost(client *cloudwatch.CloudWatch, hostID string) ([]*cloudwatch.MetricAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("host-%s", hostID)),
	}
	
	result, err := client.DescribeAlarms(input)
	if err != nil {
		return nil, err
	}
	
	return result.MetricAlarms, nil
}

