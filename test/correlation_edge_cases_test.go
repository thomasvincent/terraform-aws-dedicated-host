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

func TestCorrelationEdgeCases(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	edgeCases := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "missing_metric_data",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"edge_case_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"primary_metric": map[string]interface{}{
							"metric_name": "CustomMetric",
							"threshold": 100,
							"period": 300,
							"treat_missing_data": "breaching",
						},
						"secondary_metric": map[string]interface{}{
							"metric_name": "CustomMetric2",
							"threshold": 50,
							"period": 300,
							"treat_missing_data": "ignore",
						},
						"tertiary_metric": map[string]interface{}{
							"metric_name": "CustomMetric3",
							"threshold": 75,
							"period": 300,
							"treat_missing_data": "notBreaching",
						},
					},
					"correlation_rules": map[string]interface{}{
						"missing_data_handling": map[string]interface{}{
							"rule": "ALARM(primary_metric) AND ALARM(secondary_metric) AND NOT ALARM(tertiary_metric)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:missing-data-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"TestType": "edge-case",
					"Category": "missing-data",
				},
			},
			validation: validateMissingMetricDataHandling,
		},
		{
			name: "flapping_metrics",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"edge_case_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"unstable_metric": map[string]interface{}{
							"metric_name": "UnstableMetric",
							"threshold": 75,
							"period": 60,
							"evaluation_periods": 3,
							"datapoints_to_alarm": 2,
						},
					},
					"correlation_rules": map[string]interface{}{
						"flapping_detection": map[string]interface{}{
							"rule": "COUNT_UNIQUE_STATES(unstable_metric, 300) > 4",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:flapping-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"TestType": "edge-case",
					"Category": "flapping-metrics",
				},
			},
			validation: validateFlappingMetrics,
		},
		{
			name: "delayed_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"edge_case_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"trigger_metric": map[string]interface{}{
							"metric_name": "TriggerMetric",
							"threshold": 100,
							"period": 60,
						},
						"delayed_metric": map[string]interface{}{
							"metric_name": "DelayedMetric",
							"threshold": 50,
							"period": 300,
							"delayed_evaluation": 600,
						},
					},
					"correlation_rules": map[string]interface{}{
						"delayed_correlation": map[string]interface{}{
							"rule": "ALARM(trigger_metric) AND ALARM(delayed_metric) within(1800)",
							"minimum_time_between_alerts": 3600,
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:delayed-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"TestType": "edge-case",
					"Category": "delayed-correlation",
				},
			},
			validation: validateDelayedCorrelation,
		},
		{
			name: "boundary_conditions",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"edge_case_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"boundary_metric": map[string]interface{}{
							"metric_name": "BoundaryMetric",
							"threshold": 100,
							"period": 60,
							"anomaly_detection_band_width": 2,
						},
						"extreme_metric": map[string]interface{}{
							"metric_name": "ExtremeMetric",
							"threshold": 999999999,
							"period": 60,
							"comparison_operator": "GreaterThanThreshold",
						},
						"zero_metric": map[string]interface{}{
							"metric_name": "ZeroMetric",
							"threshold": 0,
							"period": 60,
							"comparison_operator": "LessThanOrEqualToThreshold",
						},
					},
					"correlation_rules": map[string]interface{}{
						"boundary_detection": map[string]interface{}{
							"rule": "ANOMALY(boundary_metric) WITH CONFIDENCE(99.9)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:boundary-alert",
							},
						},
						"extreme_values": map[string]interface{}{
							"rule": "ALARM(extreme_metric) OR ALARM(zero_metric)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:extreme-values-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"TestType": "edge-case",
					"Category": "boundary-conditions",
				},
			},
			validation: validateBoundaryConditions,
		},
		{
			name: "circular_dependency",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"edge_case_correlation": map[string]interface{}{
					"metrics": map[string]interface{}{
						"metric_a": map[string]interface{}{
							"metric_name": "MetricA",
							"threshold": 100,
							"period": 60,
						},
						"metric_b": map[string]interface{}{
							"metric_name": "MetricB",
							"threshold": 200,
							"period": 60,
						},
					},
					"correlation_rules": map[string]interface{}{
						"circular_dependency_a": map[string]interface{}{
							"rule": "ALARM(metric_a) OR ALARM(circular_dependency_b)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:circular-alert",
							},
						},
						"circular_dependency_b": map[string]interface{}{
							"rule": "ALARM(metric_b) OR ALARM(circular_dependency_a)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:circular-alert",
							},
						},
					},
				},
				"tags": map[string]string{
					"TestType": "edge-case",
					"Category": "circular-dependency",
				},
			},
			validation: validateCircularDependency,
		},
	}

	for _, edgeCase := range edgeCases {
		edgeCase := edgeCase
		t.Run(edgeCase.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"instance_type":     "c5.large",
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			for k, v := range edgeCase.configuration {
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
				edgeCase.validation(t, terraformOptions, awsRegion)
			})

			test_structure.RunTestStage(t, "teardown", func() {
				terraform.Destroy(t, terraformOptions)
			})
		})
	}
}

func validateMissingMetricDataHandling(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify primary metric alarm with breaching missing data
	primaryAlarm := findAlarmByName(alarms, "primary_metric")
	require.NotNil(t, primaryAlarm, "Primary metric alarm must exist")
	assert.Equal(t, "breaching", *primaryAlarm.TreatMissingData, "Primary metric must treat missing data as breaching")

	// Verify secondary metric alarm with ignored missing data
	secondaryAlarm := findAlarmByName(alarms, "secondary_metric")
	require.NotNil(t, secondaryAlarm, "Secondary metric alarm must exist")
	assert.Equal(t, "ignore", *secondaryAlarm.TreatMissingData, "Secondary metric must ignore missing data")

	// Verify tertiary metric alarm with notBreaching missing data
	tertiaryAlarm := findAlarmByName(alarms, "tertiary_metric")
	require.NotNil(t, tertiaryAlarm, "Tertiary metric alarm must exist")
	assert.Equal(t, "notBreaching", *tertiaryAlarm.TreatMissingData, "Tertiary metric must treat missing data as not breaching")

	// Verify composite alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	missingDataAlarm := findCompositeAlarmByName(compositeAlarms, "missing_data_handling")
	require.NotNil(t, missingDataAlarm, "Missing data handling alarm must exist")

	// Verify composite rule respects missing data handling
	rule := *missingDataAlarm.AlarmRule
	assert.Contains(t, rule, "ALARM(primary_metric)", "Rule must include primary metric")
	assert.Contains(t, rule, "ALARM(secondary_metric)", "Rule must include secondary metric")
	assert.Contains(t, rule, "NOT ALARM(tertiary_metric)", "Rule must include negated tertiary metric")

	// Verify actions
	assert.Greater(t, len(missingDataAlarm.AlarmActions), 0, "Alarm must have actions")
	hasMissingDataAlert := false
	for _, action := range missingDataAlarm.AlarmActions {
		if strings.Contains(*action, "missing-data-alert") {
			hasMissingDataAlert = true
			break
		}
	}
	assert.True(t, hasMissingDataAlert, "Alarm must notify missing-data-alert topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "edge-case", tags["TestType"], "Host must have edge-case test type tag")
	assert.Equal(t, "missing-data", tags["Category"], "Host must have missing-data category tag")
}

func validateFlappingMetrics(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify unstable metric alarm configuration
	unstableAlarm := findAlarmByName(alarms, "unstable_metric")
	require.NotNil(t, unstableAlarm, "Unstable metric alarm must exist")
	assert.Equal(t, int64(60), *unstableAlarm.Period, "Period must be 1 minute")
	assert.Equal(t, int64(3), *unstableAlarm.EvaluationPeriods, "Evaluation periods must be 3")
	assert.Equal(t, int64(2), *unstableAlarm.DatapointsToAlarm, "Datapoints to alarm must be 2")

	// Verify flapping detection composite alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	flappingAlarm := findCompositeAlarmByName(compositeAlarms, "flapping_detection")
	require.NotNil(t, flappingAlarm, "Flapping detection alarm must exist")

	rule := *flappingAlarm.AlarmRule
	assert.Contains(t, rule, "COUNT_UNIQUE_STATES", "Rule must use COUNT_UNIQUE_STATES function")
	assert.Contains(t, rule, "300", "Rule must check states over 5 minutes")
	assert.Contains(t, rule, "> 4", "Rule must trigger when more than 4 state changes occur")

	// Verify actions
	assert.Greater(t, len(flappingAlarm.AlarmActions), 0, "Alarm must have actions")
	hasFlappingAlert := false
	for _, action := range flappingAlarm.AlarmActions {
		if strings.Contains(*action, "flapping-alert") {
			hasFlappingAlert = true
			break
		}
	}
	assert.True(t, hasFlappingAlert, "Alarm must notify flapping-alert topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "edge-case", tags["TestType"], "Host must have edge-case test type tag")
	assert.Equal(t, "flapping-metrics", tags["Category"], "Host must have flapping-metrics category tag")
}

func validateDelayedCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify trigger metric alarm
	triggerAlarm := findAlarmByName(alarms, "trigger_metric")
	require.NotNil(t, triggerAlarm, "Trigger metric alarm must exist")
	assert.Equal(t, int64(60), *triggerAlarm.Period, "Period must be 1 minute")

	// Verify delayed metric alarm
	delayedAlarm := findAlarmByName(alarms, "delayed_metric")
	require.NotNil(t, delayedAlarm, "Delayed metric alarm must exist")
	assert.Equal(t, int64(300), *delayedAlarm.Period, "Period must be 5 minutes")

	// Verify delayed correlation composite alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	delayedCorrelationAlarm := findCompositeAlarmByName(compositeAlarms, "delayed_correlation")
	require.NotNil(t, delayedCorrelationAlarm, "Delayed correlation alarm must exist")

	rule := *delayedCorrelationAlarm.AlarmRule
	assert.Contains(t, rule, "within(1800)", "Rule must correlate within 30 minutes")

	// Verify actions
	assert.Greater(t, len(delayedCorrelationAlarm.AlarmActions), 0, "Alarm must have actions")
	hasDelayedAlert := false
	for _, action := range delayedCorrelationAlarm.AlarmActions {
		if strings.Contains(*action, "delayed-alert") {
			hasDelayedAlert = true
			break
		}
	}
	assert.True(t, hasDelayedAlert, "Alarm must notify delayed-alert topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "edge-case", tags["TestType"], "Host must have edge-case test type tag")
	assert.Equal(t, "delayed-correlation", tags["Category"], "Host must have delayed-correlation category tag")
}

func validateBoundaryConditions(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify boundary metric alarm with anomaly detection
	boundaryAlarm := findAlarmByName(alarms, "boundary_metric")
	require.NotNil(t, boundaryAlarm, "Boundary metric alarm must exist")
	assert.Equal(t, int64(60), *boundaryAlarm.Period, "Period must be 1 minute")

	// Verify extreme value metric
	extremeAlarm := findAlarmByName(alarms, "extreme_metric")
	require.NotNil(t, extremeAlarm, "Extreme metric alarm must exist")
	assert.Equal(t, float64(999999999), *extremeAlarm.Threshold, "Threshold must be extremely high")
	assert.Equal(t, "GreaterThanThreshold", *extremeAlarm.ComparisonOperator, "Must use greater than threshold comparison")

	// Verify zero metric
	zeroAlarm := findAlarmByName(alarms, "zero_metric")
	require.NotNil(t, zeroAlarm, "Zero metric alarm must exist")
	assert.Equal(t, float64(0), *zeroAlarm.Threshold, "Threshold must be zero")
	assert.Equal(t, "LessThanOrEqualToThreshold", *zeroAlarm.ComparisonOperator, "Must use less than or equal to threshold comparison")

	// Verify boundary detection composite alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	boundaryDetectionAlarm := findCompositeAlarmByName(compositeAlarms, "boundary_detection")
	require.NotNil(t, boundaryDetectionAlarm, "Boundary detection alarm must exist")

	rule := *boundaryDetectionAlarm.AlarmRule
	assert.Contains(t, rule, "ANOMALY(boundary_metric)", "Rule must include anomaly detection")
	assert.Contains(t, rule, "CONFIDENCE(99.9)", "Rule must use 99.9% confidence")

	// Verify extreme values composite alarm
	extremeValuesAlarm := findCompositeAlarmByName(compositeAlarms, "extreme_values")
	require.NotNil(t, extremeValuesAlarm, "Extreme values alarm must exist")

	extremeRule := *extremeValuesAlarm.AlarmRule
	assert.Contains(t, extremeRule, "ALARM(extreme_metric)", "Rule must include extreme metric")
	assert.Contains(t, extremeRule, "ALARM(zero_metric)", "Rule must include zero metric")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "edge-case", tags["TestType"], "Host must have edge-case test type tag")
	assert.Equal(t, "boundary-conditions", tags["Category"], "Host must have boundary-conditions category tag")
}

func validateCircularDependency(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify metric alarms
	metricAAlarm := findAlarmByName(alarms, "metric_a")
	require.NotNil(t, metricAAlarm, "Metric A alarm must exist")

	metricBAlarm := findAlarmByName(alarms, "metric_b")
	require.NotNil(t, metricBAlarm, "Metric B alarm must exist")

	// Verify circular dependency composite alarms
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	circularDependencyAAlarm := findCompositeAlarmByName(compositeAlarms, "circular_dependency_a")
	require.NotNil(t, circularDependencyAAlarm, "Circular dependency A alarm must exist")

	circularDependencyBAlarm := findCompositeAlarmByName(compositeAlarms, "circular_dependency_b")
	require.NotNil(t, circularDependencyBAlarm, "Circular dependency B alarm must exist")

	// Verify circular rules
	ruleA := *circularDependencyAAlarm.AlarmRule
	assert.Contains(t, ruleA, "ALARM(metric_a)", "Rule A must include metric A")
	assert.Contains(t, ruleA, "ALARM(circular_dependency_b)", "Rule A must reference rule B")

	ruleB := *circularDependencyBAlarm.AlarmRule
	assert.Contains(t, ruleB, "ALARM(metric_b)", "Rule B must include metric B")
	assert.Contains(t, ruleB, "ALARM(circular_dependency_a)", "Rule B must reference rule A")

	// Verify actions
	assert.Greater(t, len(circularDependencyAAlarm.AlarmActions), 0, "Alarm must have actions")
	hasCircularAlert := false
	for _, action := range circularDependencyAAlarm.AlarmActions {
		if strings.Contains(*action, "circular-alert") {
			hasCircularAlert = true
			break
		}
	}
	assert.True(t, hasCircularAlert, "Alarm must notify circular-alert topic")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "edge-case", tags["TestType"], "Host must have edge-case test type tag")
	assert.Equal(t, "circular-dependency", tags["Category"], "Host must have circular-dependency category tag")
}

