package test

import (
	"fmt"
	"strings"
	"testing"

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

func TestCorrelationMetricsAndThresholds(t *testing.T) {
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
			name: "temporal_correlation_metrics",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"temporal_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"short_term": map[string]interface{}{
							"metric_name": "APICallCount",
							"threshold": 100,
							"period": 60,
							"evaluation_periods": 1,
						},
						"medium_term": map[string]interface{}{
							"metric_name": "APICallCount",
							"threshold": 500,
							"period": 300,
							"evaluation_periods": 3,
						},
						"long_term": map[string]interface{}{
							"metric_name": "APICallCount",
							"threshold": 1000,
							"period": 3600,
							"evaluation_periods": 6,
						},
					},
					"correlation_rules": map[string]interface{}{
						"trend_detection": map[string]interface{}{
							"rule": "ANOMALY(SHORT_TERM, MEDIUM_TERM, LONG_TERM) WITH CONFIDENCE(95)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:trend-detection",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "temporal-correlation",
					"CorrelationLevel": "multi-period",
				},
			},
			validation: validateTemporalCorrelation,
		},
		{
			name: "severity_weighted_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"severity_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"low_severity": map[string]interface{}{
							"metric_name": "SecurityEvents",
							"severity_weight": 1,
							"threshold": 10,
							"period": 300,
						},
						"medium_severity": map[string]interface{}{
							"metric_name": "SecurityEvents",
							"severity_weight": 5,
							"threshold": 5,
							"period": 300,
						},
						"high_severity": map[string]interface{}{
							"metric_name": "SecurityEvents",
							"severity_weight": 10,
							"threshold": 1,
							"period": 300,
						},
					},
					"correlation_rules": map[string]interface{}{
						"weighted_threshold": map[string]interface{}{
							"rule": "SUM(WEIGHTED_EVENTS) > 50 within(900)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:severity-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "severity-weighted",
					"CorrelationLevel": "multi-severity",
				},
			},
			validation: validateSeverityWeightedCorrelation,
		},
		{
			name: "geographic_correlation_metrics",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"geographic_correlation": map[string]interface{}{
					"regions": []string{"us-west-2", "us-east-1", "eu-west-1"},
					"metrics": map[string]interface{}{
						"auth_failures": map[string]interface{}{
							"metric_name": "AuthFailureCount",
							"threshold": 5,
							"period": 300,
							"evaluation_periods": 1,
						},
					},
					"correlation_rules": map[string]interface{}{
						"geographic_pattern": map[string]interface{}{
							"rule": "COUNT(DISTINCT_REGIONS) >= 2 AND SUM(AuthFailureCount) > 20 within(1800)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:geo-correlation",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "geographic-correlation",
					"CorrelationLevel": "multi-region",
				},
			},
			validation: validateGeographicCorrelation,
		},
		{
			name: "adaptive_threshold_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"adaptive_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"cpu_utilization": map[string]interface{}{
							"metric_name": "CPUUtilization",
							"baseline_period": 86400, // 24 hours
							"deviation_sensitivity": "medium", // low, medium, high
							"period": 300,
							"evaluation_periods": 3,
						},
						"memory_utilization": map[string]interface{}{
							"metric_name": "MemoryUtilization",
							"baseline_period": 86400, // 24 hours
							"deviation_sensitivity": "medium",
							"period": 300,
							"evaluation_periods": 3,
						},
						"network_throughput": map[string]interface{}{
							"metric_name": "NetworkThroughput",
							"baseline_period": 86400, // 24 hours
							"deviation_sensitivity": "high",
							"period": 300,
							"evaluation_periods": 3,
						},
					},
					"correlation_rules": map[string]interface{}{
						"resource_anomaly": map[string]interface{}{
							"rule": "COUNT(ANOMALIES) >= 2 within(1800)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:resource-anomaly",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "adaptive-threshold",
					"CorrelationLevel": "multi-resource",
				},
			},
			validation: validateAdaptiveThresholdCorrelation,
		},
	}

	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			for k, v := range scenario.configuration {
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
				scenario.validation(t, terraformOptions, awsRegion)
			})

			test_structure.RunTestStage(t, "teardown", func() {
				terraform.Destroy(t, terraformOptions)
			})
		})
	}
}

func validateTemporalCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify temporal metric alarms
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Short-term metrics
	shortTermAlarm := findAlarmByName(alarms, "short_term")
	require.NotNil(t, shortTermAlarm, "Short-term alarm must exist")
	assert.Equal(t, int64(60), *shortTermAlarm.Period, "Short-term period must be 1 minute")
	assert.Equal(t, float64(100), *shortTermAlarm.Threshold, "Short-term threshold must be 100")
	assert.Equal(t, int64(1), *shortTermAlarm.EvaluationPeriods, "Short-term evaluation period must be 1")

	// Medium-term metrics
	mediumTermAlarm := findAlarmByName(alarms, "medium_term")
	require.NotNil(t, mediumTermAlarm, "Medium-term alarm must exist")
	assert.Equal(t, int64(300), *mediumTermAlarm.Period, "Medium-term period must be 5 minutes")
	assert.Equal(t, float64(500), *mediumTermAlarm.Threshold, "Medium-term threshold must be 500")
	assert.Equal(t, int64(3), *mediumTermAlarm.EvaluationPeriods, "Medium-term evaluation periods must be 3")

	// Long-term metrics
	longTermAlarm := findAlarmByName(alarms, "long_term")
	require.NotNil(t, longTermAlarm, "Long-term alarm must exist")
	assert.Equal(t, int64(3600), *longTermAlarm.Period, "Long-term period must be 1 hour")
	assert.Equal(t, float64(1000), *longTermAlarm.Threshold, "Long-term threshold must be 1000")
	assert.Equal(t, int64(6), *longTermAlarm.EvaluationPeriods, "Long-term evaluation periods must be 6")

	// Verify anomaly detection composite alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	trendAlarm := findCompositeAlarmByName(compositeAlarms, "trend_detection")
	require.NotNil(t, trendAlarm, "Trend detection alarm must exist")

	rule := *trendAlarm.AlarmRule
	assert.Contains(t, rule, "ANOMALY(SHORT_TERM, MEDIUM_TERM, LONG_TERM)", "Rule must correlate across time periods")
	assert.Contains(t, rule, "CONFIDENCE(95)", "Rule must have 95% confidence threshold")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "temporal-correlation", tags["MonitoringType"], "Host must have temporal correlation monitoring type")
	assert.Equal(t, "multi-period", tags["CorrelationLevel"], "Host must have multi-period correlation level")
}

func validateSeverityWeightedCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify severity-based alarms
	lowSeverityAlarm := findAlarmByName(alarms, "low_severity")
	require.NotNil(t, lowSeverityAlarm, "Low severity alarm must exist")
	assert.Equal(t, float64(10), *lowSeverityAlarm.Threshold, "Low severity threshold must be 10")

	mediumSeverityAlarm := findAlarmByName(alarms, "medium_severity")
	require.NotNil(t, mediumSeverityAlarm, "Medium severity alarm must exist")
	assert.Equal(t, float64(5), *mediumSeverityAlarm.Threshold, "Medium severity threshold must be 5")

	highSeverityAlarm := findAlarmByName(alarms, "high_severity")
	require.NotNil(t, highSeverityAlarm, "High severity alarm must exist")
	assert.Equal(t, float64(1), *highSeverityAlarm.Threshold, "High severity threshold must be 1")

	// Verify weighted correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	weightedAlarm := findCompositeAlarmByName(compositeAlarms, "weighted_threshold")
	require.NotNil(t, weightedAlarm, "Weighted threshold alarm must exist")

	rule := *weightedAlarm.AlarmRule
	assert.Contains(t, rule, "SUM(WEIGHTED_EVENTS)", "Rule must use weighted sum")
	assert.Contains(t, rule, "> 50", "Rule must have threshold of 50")
	assert.Contains(t, rule, "within(900)", "Rule must correlate within 15 minutes")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "severity-weighted", tags["MonitoringType"], "Host must have severity-weighted monitoring type")
	assert.Equal(t, "multi-severity", tags["CorrelationLevel"], "Host must have multi-severity correlation level")
}

func validateGeographicCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify regional alarms
	regions := []string{"us-west-2", "us-east-1", "eu-west-1"}
	for _, region := range regions {
		alarms, err := getAlarmsForHostInRegion(cloudwatchClient, hostID, region)
		require.NoError(t, err)

		authFailureAlarm := findAlarmByName(alarms, "auth_failures")
		require.NotNil(t, authFailureAlarm, fmt.Sprintf("Auth failure alarm must exist for region %s", region))
		assert.Equal(t, float64(5), *authFailureAlarm.Threshold, "Auth failure threshold must be 5")
		assert.Equal(t, int64(300), *authFailureAlarm.Period, "Period must be 5 minutes")
	}

	// Verify geographic correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	geoCorrelationAlarm := findCompositeAlarmByName(compositeAlarms, "geographic_pattern")
	require.NotNil(t, geoCorrelationAlarm, "Geographic pattern alarm must exist")

	rule := *geoCorrelationAlarm.AlarmRule
	assert.Contains(t, rule, "COUNT(DISTINCT_REGIONS) >= 2", "Rule must require at least 2 distinct regions")
	assert.Contains(t, rule, "SUM(AuthFailureCount) > 20", "Rule must have auth failure sum threshold of 20")
	assert.Contains(t, rule, "within(1800)", "Rule must correlate within 30 minutes")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "geographic-correlation", tags["MonitoringType"], "Host must have geographic correlation monitoring type")
	assert.Equal(t, "multi-region", tags["CorrelationLevel"], "Host must have multi-region correlation level")
}

func validateAdaptiveThresholdCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify adaptive threshold alarms
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// CPU utilization adaptive alarm
	cpuAlarm := findAlarmByName(alarms, "cpu_utilization")
	require.NotNil(t, cpuAlarm, "CPU utilization alarm must exist")
	assert.Equal(t, "ANOMALY_DETECTION", *cpuAlarm.ComparisonOperator, "CPU alarm must use anomaly detection")
	assert.Equal(t, int64(300), *cpuAlarm.Period, "Period must be 5 minutes")
	assert.Equal(t, int64(3), *cpuAlarm.EvaluationPeriods, "Evaluation periods must be 3")

	// Memory utilization adaptive alarm
	memoryAlarm := findAlarmByName(alarms, "memory_utilization")
	require.NotNil(t, memoryAlarm, "Memory utilization alarm must exist")
	assert.Equal(t, "ANOMALY_DETECTION", *memoryAlarm.ComparisonOperator, "Memory alarm must use anomaly detection")

	// Network throughput adaptive alarm
	networkAlarm := findAlarmByName(alarms, "network_throughput")
	require.NotNil(t, networkAlarm, "Network throughput alarm must exist")
	assert.Equal(t, "ANOMALY_DETECTION", *networkAlarm.ComparisonOperator, "Network alarm must use anomaly detection")
	
	// Verify resource anomaly correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	anomalyAlarm := findCompositeAlarmByName(compositeAlarms, "resource_anomaly")
	require.NotNil(t, anomalyAlarm, "Resource anomaly alarm must exist")

	rule := *anomalyAlarm.AlarmRule
	assert.Contains(t, rule, "COUNT(ANOMALIES) >= 2", "Rule must count at least 2 anomalies")
	assert.Contains(t, rule, "within(1800)", "Rule must correlate within 30 minutes")

	// Verify alarm has actions
	assert.Greater(t, len(anomalyAlarm.AlarmActions), 0, "Alarm must have actions")
	hasResourceAnomalyAction := false
	for _, action := range anomalyAlarm.AlarmActions {
		if strings.Contains(*action, "resource-anomaly") {
			hasResourceAnomalyAction = true
			break
		}
	}
	assert.True(t, hasResourceAnomalyAction, "Alarm must notify resource-anomaly topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "adaptive-threshold", tags["MonitoringType"], "Host must have adaptive threshold monitoring type")
	assert.Equal(t, "multi-resource", tags["CorrelationLevel"], "Host must have multi-resource correlation level")
}

// Helper function to get alarms for a host in a specific region
func getAlarmsForHostInRegion(client *cloudwatch.CloudWatch, hostID, region string) ([]*cloudwatch.MetricAlarm, error) {
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: awssdk.String(fmt.Sprintf("%s-%s", hostID, region)),
	}

	result, err := client.DescribeAlarms(input)
	if err != nil {
		return nil, err
	}

	return result.MetricAlarms, nil
}

