package test

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestAlertSequencePatterns(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	sequences := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "attack_sequence_detection",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"initial_recon": map[string]interface{}{
						"metric_name": "APICallCount",
						"threshold": 50,
						"period": 300,
						"evaluation_periods": 1,
					},
					"elevated_activity": map[string]interface{}{
						"metric_name": "APICallCount",
						"threshold": 100,
						"period": 300,
						"evaluation_periods": 1,
					},
					"potential_breach": map[string]interface{}{
						"metric_name": "UnauthorizedAPIAttempts",
						"threshold": 0,
						"period": 60,
						"evaluation_periods": 1,
					},
					"sequence_window": 900, // 15 minutes
					"actions": map[string]interface{}{
						"initial": []string{
							"arn:aws:sns:us-west-2:123456789012:security-monitoring",
						},
						"elevated": []string{
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
						"breach": []string{
							"arn:aws:sns:us-west-2:123456789012:incident-response",
							"arn:aws:sns:us-west-2:123456789012:soc-team",
						},
					},
				},
			},
			validation: validateAttackSequenceDetection,
		},
		{
			name: "resource_exhaustion_sequence",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"warning_cpu": map[string]interface{}{
						"metric_name": "CPUUtilization",
						"threshold": 70,
						"period": 300,
						"evaluation_periods": 2,
					},
					"critical_cpu": map[string]interface{}{
						"metric_name": "CPUUtilization",
						"threshold": 85,
						"period": 300,
						"evaluation_periods": 2,
					},
					"memory_pressure": map[string]interface{}{
						"metric_name": "MemoryUtilization",
						"threshold": 85,
						"period": 300,
						"evaluation_periods": 2,
					},
					"disk_pressure": map[string]interface{}{
						"metric_name": "DiskUtilization",
						"threshold": 85,
						"period": 300,
						"evaluation_periods": 2,
					},
					"sequence_window": 1800, // 30 minutes
					"actions": map[string]interface{}{
						"warning": []string{
							"arn:aws:sns:us-west-2:123456789012:monitoring-team",
						},
						"critical": []string{
							"arn:aws:sns:us-west-2:123456789012:operations-team",
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
						"emergency": []string{
							"arn:aws:sns:us-west-2:123456789012:incident-response",
							"arn:aws:sns:us-west-2:123456789012:executive-team",
						},
					},
				},
			},
			validation: validateResourceExhaustionSequence,
		},
		{
			name: "compliance_violation_sequence",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"config_change": map[string]interface{}{
						"metric_name": "ConfigurationChanges",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"permission_change": map[string]interface{}{
						"metric_name": "IAMPolicyChanges",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"root_activity": map[string]interface{}{
						"metric_name": "RootAccountUsage",
						"threshold": 0,
						"period": 60,
						"evaluation_periods": 1,
					},
					"sequence_window": 3600, // 1 hour
					"actions": map[string]interface{}{
						"initial": []string{
							"arn:aws:sns:us-west-2:123456789012:compliance-monitoring",
						},
						"violation": []string{
							"arn:aws:sns:us-west-2:123456789012:compliance-team",
							"arn:aws:sns:us-west-2:123456789012:security-team",
						},
						"critical": []string{
							"arn:aws:sns:us-west-2:123456789012:audit-team",
							"arn:aws:sns:us-west-2:123456789012:executive-team",
						},
					},
				},
			},
			validation: validateComplianceViolationSequence,
		},
	}

	for _, seq := range sequences {
		seq := seq
		t.Run(seq.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			for k, v := range seq.configuration {
				vars[k] = v
			}

			terraformOptions := &terraform.Options{
				TerraformDir: workingDir,
				Vars:        vars,
				EnvVars: map[string]string{
					"AWS_DEFAULT_REGION": awsRegion,
				},
			}

			test_structure.RunTestStage(t, "setup", func() {
				terraform.InitAndApply(t, terraformOptions)
			})

			test_structure.RunTestStage(t, "validate", func() {
				seq.validation(t, terraformOptions, awsRegion)
			})

			test_structure.RunTestStage(t, "teardown", func() {
				terraform.Destroy(t, terraformOptions)
			})
		})
	}
}

func validateAttackSequenceDetection(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify sequence alarms exist with correct timing
	reconAlarm := findAlarmByName(alarms, "initial_recon")
	require.NotNil(t, reconAlarm)
	assert.Equal(t, int64(300), *reconAlarm.Period)
	assert.Equal(t, float64(50), *reconAlarm.Threshold)

	elevatedAlarm := findAlarmByName(alarms, "elevated_activity")
	require.NotNil(t, elevatedAlarm)
	assert.Equal(t, float64(100), *elevatedAlarm.Threshold)

	breachAlarm := findAlarmByName(alarms, "potential_breach")
	require.NotNil(t, breachAlarm)
	assert.Equal(t, int64(60), *breachAlarm.Period)

	// Verify sequence rules
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	sequenceAlarm := findCompositeAlarmByName(compositeAlarms, "attack_sequence")
	require.NotNil(t, sequenceAlarm)

	// Verify sequence timing in alarm rule
	rule := *sequenceAlarm.AlarmRule
	assert.Contains(t, rule, "ALARM(initial_recon)")
	assert.Contains(t, rule, "ALARM(elevated_activity)")
	assert.Contains(t, rule, "ALARM(potential_breach)")
	assert.Contains(t, rule, "within(900)") // 15 minutes
}

func validateResourceExhaustionSequence(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify resource pressure alarms
	cpuWarningAlarm := findAlarmByName(alarms, "warning_cpu")
	require.NotNil(t, cpuWarningAlarm)
	assert.Equal(t, float64(70), *cpuWarningAlarm.Threshold)

	cpuCriticalAlarm := findAlarmByName(alarms, "critical_cpu")
	require.NotNil(t, cpuCriticalAlarm)
	assert.Equal(t, float64(85), *cpuCriticalAlarm.Threshold)

	memoryAlarm := findAlarmByName(alarms, "memory_pressure")
	require.NotNil(t, memoryAlarm)
	diskAlarm := findAlarmByName(alarms, "disk_pressure")
	require.NotNil(t, diskAlarm)

	// Verify sequence composite alarms
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	exhaustionAlarm := findCompositeAlarmByName(compositeAlarms, "resource_exhaustion")
	require.NotNil(t, exhaustionAlarm)

	// Verify sequence timing and escalation
	rule := *exhaustionAlarm.AlarmRule
	assert.Contains(t, rule, "within(1800)") // 30 minutes
	assert.Contains(t, rule, "ALARM(warning_cpu)")
	assert.Contains(t, rule, "ALARM(critical_cpu)")
	assert.Contains(t, rule, "ALARM(memory_pressure)")
	assert.Contains(t, rule, "ALARM(disk_pressure)")
}

func validateComplianceViolationSequence(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify compliance violation alarms
	configAlarm := findAlarmByName(alarms, "config_change")
	require.NotNil(t, configAlarm)
	assert.Equal(t, int64(300), *configAlarm.Period)

	permissionAlarm := findAlarmByName(alarms, "permission_change")
	require.NotNil(t, permissionAlarm)

	rootAlarm := findAlarmByName(alarms, "root_activity")
	require.NotNil(t, rootAlarm)
	assert.Equal(t, int64(60), *rootAlarm.Period)

	// Verify sequence composite alarms
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	violationAlarm := findCompositeAlarmByName(compositeAlarms, "compliance_violation_sequence")
	require.NotNil(t, violationAlarm)

	// Verify sequence timing and notifications
	rule := *violationAlarm.AlarmRule
	assert.Contains(t, rule, "within(3600)") // 1 hour
	assert.Contains(t, rule, "ALARM(config_change)")
	assert.Contains(t, rule, "ALARM(permission_change)")
	assert.Contains(t, rule, "ALARM(root_activity)")

	// Verify escalation actions
	assert.Len(t, violationAlarm.AlarmActions, 3)
	hasComplianceTeam := false
	hasAuditTeam := false
	hasExecutiveTeam := false
	for _, action := range violationAlarm.AlarmActions {
		if strings.Contains(*action, "compliance-team") {
			hasComplianceTeam = true
		}
		if strings.Contains(*action, "audit-team") {
			hasAuditTeam = true
		}
		if strings.Contains(*action, "executive-team") {
			hasExecutiveTeam = true
		}
	}
	assert.True(t, hasComplianceTeam && hasAuditTeam && hasExecutiveTeam)
}

// Helper functions for finding alarms and composite alarms
func getAlarmsForHost(client *cloudwatch.CloudWatch, hostID string) ([]*cloudwatch.MetricAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(hostID),
	}
	
	result, err := client.DescribeAlarms(input)
	if err != nil {
		return nil, err
	}
	
	return result.MetricAlarms, nil
}

func getCompositeAlarmsForHost(client *cloudwatch.CloudWatch, hostID string) ([]*cloudwatch.CompositeAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(hostID),
	}
	
	result, err := client.DescribeAlarms(input)
	if err != nil {
		return nil, err
	}
	
	return result.CompositeAlarms, nil
}

func findAlarmByName(alarms []*cloudwatch.MetricAlarm, nameSuffix string) *cloudwatch.MetricAlarm {
	for _, alarm := range alarms {
		if strings.Contains(*alarm.AlarmName, nameSuffix) {
			return alarm
		}
	}
	return nil
}

func findCompositeAlarmByName(alarms []*cloudwatch.CompositeAlarm, nameSuffix string) *cloudwatch.CompositeAlarm {
	for _, alarm := range alarms {
		if strings.Contains(*alarm.AlarmName, nameSuffix) {
			return alarm
		}
	}
	return nil
}

