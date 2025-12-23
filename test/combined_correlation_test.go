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

func TestCombinedCorrelationPatterns(t *testing.T) {
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
			name: "temporal_severity_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"combined_correlation": map[string]interface{}{
					"temporal_metrics": map[string]interface{}{
						"short_term": map[string]interface{}{
							"metric_name": "SecurityEvents",
							"threshold": 10,
							"period": 60,
						},
						"long_term": map[string]interface{}{
							"metric_name": "SecurityEvents",
							"threshold": 100,
							"period": 3600,
						},
					},
					"severity_weights": map[string]interface{}{
						"low": 1,
						"medium": 5,
						"high": 10,
					},
					"correlation_rules": map[string]interface{}{
						"temporal_severity": map[string]interface{}{
							"rule": "ANOMALY(SHORT_TERM) AND WEIGHTED_SUM(SEVERITY) > 50",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:combined-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "combined-correlation",
					"CorrelationType": "temporal-severity",
				},
			},
			validation: validateTemporalSeverityCorrelation,
		},
		{
			name: "geographic_adaptive_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"combined_correlation": map[string]interface{}{
					"regions": []string{"us-west-2", "us-east-1"},
					"adaptive_metrics": map[string]interface{}{
						"baseline_period": 86400,
						"metric_name": "APICallCount",
						"sensitivity": "high",
					},
					"correlation_rules": map[string]interface{}{
						"geo_adaptive": map[string]interface{}{
							"rule": "COUNT(REGIONS_WITH_ANOMALY) >= 2 within(1800)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:geo-anomaly",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "combined-correlation",
					"CorrelationType": "geographic-adaptive",
				},
			},
			validation: validateGeographicAdaptiveCorrelation,
		},
		{
			name: "comprehensive_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"combined_correlation": map[string]interface{}{
					"temporal_metrics": map[string]interface{}{
						"short_term": map[string]interface{}{
							"metric_name": "SecurityEvents",
							"threshold": 10,
							"period": 60,
						},
					},
					"regions": []string{"us-west-2", "us-east-1"},
					"severity_weights": map[string]interface{}{
						"critical": 20,
					},
					"adaptive_metrics": map[string]interface{}{
						"baseline_period": 86400,
						"sensitivity": "high",
					},
					"correlation_rules": map[string]interface{}{
						"comprehensive": map[string]interface{}{
							"rule": "(ANOMALY(REGION) OR HIGH_SEVERITY) AND TEMPORAL_TREND",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:comprehensive-alert",
								"arn:aws:sns:us-west-2:123456789012:incident-response",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "combined-correlation",
					"CorrelationType": "comprehensive",
				},
			},
			validation: validateComprehensiveCorrelation,
		},
		{
			name: "cascading_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"combined_correlation": map[string]interface{}{
					"temporal_metrics": map[string]interface{}{
						"initial_trigger": map[string]interface{}{
							"metric_name": "DatabaseErrorRate",
							"threshold": 5,
							"period": 60,
						},
						"secondary_effect": map[string]interface{}{
							"metric_name": "APIErrorRate",
							"threshold": 10,
							"period": 300,
						},
						"final_impact": map[string]interface{}{
							"metric_name": "UserExperienceScore",
							"threshold": 80,
							"comparison_operator": "LessThanThreshold",
							"period": 300,
						},
					},
					"correlation_rules": map[string]interface{}{
						"cascading_failure": map[string]interface{}{
							"rule": "ALARM(initial_trigger) AND ALARM(secondary_effect) within(600) AND ALARM(final_impact) within(1200)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:cascading-failure",
								"arn:aws:sns:us-west-2:123456789012:service-owners",
							},
						},
					},
				},
				"tags": map[string]string{
					"MonitoringType": "combined-correlation",
					"CorrelationType": "cascading-failure",
				},
			},
			validation: validateCascadingCorrelation,
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

func validateTemporalSeverityCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify temporal alarms
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	shortTermAlarm := findAlarmByName(alarms, "short_term")
	require.NotNil(t, shortTermAlarm, "Short-term alarm must exist")
	assert.Equal(t, int64(60), *shortTermAlarm.Period, "Short-term period must be 1 minute")
	assert.Equal(t, float64(10), *shortTermAlarm.Threshold, "Short-term threshold must be 10")

	longTermAlarm := findAlarmByName(alarms, "long_term")
	require.NotNil(t, longTermAlarm, "Long-term alarm must exist")
	assert.Equal(t, int64(3600), *longTermAlarm.Period, "Long-term period must be 1 hour")
	assert.Equal(t, float64(100), *longTermAlarm.Threshold, "Long-term threshold must be 100")

	// Verify severity alarms
	lowSeverityAlarm := findAlarmByName(alarms, "low_severity")
	require.NotNil(t, lowSeverityAlarm, "Low severity alarm must exist")
	
	mediumSeverityAlarm := findAlarmByName(alarms, "medium_severity")
	require.NotNil(t, mediumSeverityAlarm, "Medium severity alarm must exist")
	
	highSeverityAlarm := findAlarmByName(alarms, "high_severity")
	require.NotNil(t, highSeverityAlarm, "High severity alarm must exist")

	// Verify combined correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	combinedAlarm := findCompositeAlarmByName(compositeAlarms, "temporal_severity")
	require.NotNil(t, combinedAlarm, "Temporal severity correlation alarm must exist")

	rule := *combinedAlarm.AlarmRule
	assert.Contains(t, rule, "ANOMALY(SHORT_TERM)", "Rule must include short-term anomaly detection")
	assert.Contains(t, rule, "WEIGHTED_SUM(SEVERITY) > 50", "Rule must include weighted severity sum")

	// Verify alarm has actions
	assert.Greater(t, len(combinedAlarm.AlarmActions), 0, "Alarm must have actions")
	hasCombinedAlert := false
	for _, action := range combinedAlarm.AlarmActions {
		if strings.Contains(*action, "combined-alert") {
			hasCombinedAlert = true
			break
		}
	}
	assert.True(t, hasCombinedAlert, "Alarm must notify combined-alert topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "combined-correlation", tags["MonitoringType"], "Host must have combined correlation monitoring type")
	assert.Equal(t, "temporal-severity", tags["CorrelationType"], "Host must have temporal-severity correlation type")
}

func validateGeographicAdaptiveCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify regional adaptive alarms
	regions := []string{"us-west-2", "us-east-1"}
	for _, region := range regions {
		alarms, err := getAlarmsForHostInRegion(cloudwatchClient, hostID, region)
		require.NoError(t, err)

		adaptiveAlarm := findAlarmByName(alarms, "api_call_count")
		require.NotNil(t, adaptiveAlarm, fmt.Sprintf("API call count alarm must exist for region %s", region))
		assert.Equal(t, "ANOMALY_DETECTION", *adaptiveAlarm.ComparisonOperator, "Alarm must use anomaly detection")
	}

	// Verify combined geographic-adaptive correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	geoAdaptiveAlarm := findCompositeAlarmByName(compositeAlarms, "geo_adaptive")
	require.NotNil(t, geoAdaptiveAlarm, "Geographic adaptive correlation alarm must exist")

	rule := *geoAdaptiveAlarm.AlarmRule
	assert.Contains(t, rule, "COUNT(REGIONS_WITH_ANOMALY) >= 2", "Rule must count regions with anomalies")
	assert.Contains(t, rule, "within(1800)", "Rule must correlate within 30 minutes")

	// Verify alarm has actions
	assert.Greater(t, len(geoAdaptiveAlarm.AlarmActions), 0, "Alarm must have actions")
	hasGeoAnomalyAlert := false
	for _, action := range geoAdaptiveAlarm.AlarmActions {
		if strings.Contains(*action, "geo-anomaly") {
			hasGeoAnomalyAlert = true
			break
		}
	}
	assert.True(t, hasGeoAnomalyAlert, "Alarm must notify geo-anomaly topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "combined-correlation", tags["MonitoringType"], "Host must have combined correlation monitoring type")
	assert.Equal(t, "geographic-adaptive", tags["CorrelationType"], "Host must have geographic-adaptive correlation type")
}

func validateComprehensiveCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify temporal alarms
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	shortTermAlarm := findAlarmByName(alarms, "short_term")
	require.NotNil(t, shortTermAlarm, "Short-term alarm must exist")

	// Verify severity alarms
	criticalSeverityAlarm := findAlarmByName(alarms, "critical")
	require.NotNil(t, criticalSeverityAlarm, "Critical severity alarm must exist")

	// Verify regional alarms
	regions := []string{"us-west-2", "us-east-1"}
	for _, region := range regions {
		regionalAlarms, err := getAlarmsForHostInRegion(cloudwatchClient, hostID, region)
		require.NoError(t, err)
		assert.NotEmpty(t, regionalAlarms, fmt.Sprintf("Alarms must exist for region %s", region))
	}

	// Verify comprehensive correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	comprehensiveAlarm := findCompositeAlarmByName(compositeAlarms, "comprehensive")
	require.NotNil(t, comprehensiveAlarm, "Comprehensive correlation alarm must exist")

	rule := *comprehensiveAlarm.AlarmRule
	assert.Contains(t, rule, "ANOMALY(REGION)", "Rule must include regional anomaly detection")
	assert.Contains(t, rule, "HIGH_SEVERITY", "Rule must include high severity condition")
	assert.Contains(t, rule, "TEMPORAL_TREND", "Rule must include temporal trend analysis")

	// Verify alarm has multiple actions
	assert.GreaterOrEqual(t, len(comprehensiveAlarm.AlarmActions), 2, "Alarm must have at least 2 actions")
	hasComprehensiveAlert := false
	hasIncidentResponse := false
	for _, action := range comprehensiveAlarm.AlarmActions {
		if strings.Contains(*action, "comprehensive-alert") {
			hasComprehensiveAlert = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
	}
	assert.True(t, hasComprehensiveAlert && hasIncidentResponse, 
		"Alarm must notify both comprehensive-alert and incident-response topics")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "combined-correlation", tags["MonitoringType"], "Host must have combined correlation monitoring type")
	assert.Equal(t, "comprehensive", tags["CorrelationType"], "Host must have comprehensive correlation type")
}

func validateCascadingCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	// Verify cascading failure alarms
	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	initialTriggerAlarm := findAlarmByName(alarms, "initial_trigger")
	require.NotNil(t, initialTriggerAlarm, "Initial trigger alarm must exist")
	assert.Equal(t, int64(60), *initialTriggerAlarm.Period, "Initial trigger period must be 1 minute")
	assert.Equal(t, float64(5), *initialTriggerAlarm.Threshold, "Initial trigger threshold must be 5")
	assert.Equal(t, "DatabaseErrorRate", *initialTriggerAlarm.MetricName, "Initial trigger must monitor database error rate")

	secondaryEffectAlarm := findAlarmByName(alarms, "secondary_effect")
	require.NotNil(t, secondaryEffectAlarm, "Secondary effect alarm must exist")
	assert.Equal(t, int64(300), *secondaryEffectAlarm.Period, "Secondary effect period must be 5 minutes")
	assert.Equal(t, float64(10), *secondaryEffectAlarm.Threshold, "Secondary effect threshold must be 10")
	assert.Equal(t, "APIErrorRate", *secondaryEffectAlarm.MetricName, "Secondary effect must monitor API error rate")

	finalImpactAlarm := findAlarmByName(alarms, "final_impact")
	require.NotNil(t, finalImpactAlarm, "Final impact alarm must exist")
	assert.Equal(t, int64(300), *finalImpactAlarm.Period, "Final impact period must be 5 minutes")
	assert.Equal(t, float64(80), *finalImpactAlarm.Threshold, "Final impact threshold must be 80")
	assert.Equal(t, "UserExperienceScore", *finalImpactAlarm.MetricName, "Final impact must monitor user experience score")
	assert.Equal(t, "LessThanThreshold", *finalImpactAlarm.ComparisonOperator, "Final impact must use less than threshold comparison")

	// Verify cascading correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	cascadingAlarm := findCompositeAlarmByName(compositeAlarms, "cascading_failure")
	require.NotNil(t, cascadingAlarm, "Cascading failure correlation alarm must exist")

	rule := *cascadingAlarm.AlarmRule
	assert.Contains(t, rule, "ALARM(initial_trigger)", "Rule must include initial trigger")
	assert.Contains(t, rule, "ALARM(secondary_effect) within(600)", "Rule must include secondary effect within 10 minutes")
	assert.Contains(t, rule, "ALARM(final_impact) within(1200)", "Rule must include final impact within 20 minutes")

	// Verify alarm has multiple actions
	assert.GreaterOrEqual(t, len(cascadingAlarm.AlarmActions), 2, "Alarm must have at least 2 actions")
	hasCascadingFailureAlert := false
	hasServiceOwnersAlert := false
	for _, action := range cascadingAlarm.AlarmActions {
		if strings.Contains(*action, "cascading-failure") {
			hasCascadingFailureAlert = true
		}
		if strings.Contains(*action, "service-owners") {
			hasServiceOwnersAlert = true
		}
	}
	assert.True(t, hasCascadingFailureAlert && hasServiceOwnersAlert, 
		"Alarm must notify both cascading-failure and service-owners topics")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "combined-correlation", tags["MonitoringType"], "Host must have combined correlation monitoring type")
	assert.Equal(t, "cascading-failure", tags["CorrelationType"], "Host must have cascading-failure correlation type")
}

