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

func TestDistributedAlertCorrelations(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	correlations := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "distributed_attack_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"host_group": map[string]interface{}{
					"primary_host": map[string]interface{}{
						"instance_type": "c5.large",
						"alerts": map[string]interface{}{
							"unusual_activity": map[string]interface{}{
								"metric_name": "UnusualActivityIndex",
								"threshold": 0.7,
								"period": 300,
							},
						},
					},
					"secondary_hosts": []map[string]interface{}{
						{
							"instance_type": "c5.large",
							"alerts": map[string]interface{}{
								"unusual_activity": map[string]interface{}{
									"metric_name": "UnusualActivityIndex",
									"threshold": 0.7,
									"period": 300,
								},
							},
						},
						{
							"instance_type": "c5.large",
							"alerts": map[string]interface{}{
								"unusual_activity": map[string]interface{}{
									"metric_name": "UnusualActivityIndex",
									"threshold": 0.7,
									"period": 300,
								},
							},
						},
					},
					"correlation_rules": map[string]interface{}{
						"distributed_attack": map[string]interface{}{
							"rule": "COUNT(ALARM(UnusualActivityIndex)) >= 2",
							"evaluation_period": 900, // 15 minutes
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:security-critical",
								"arn:aws:sns:us-west-2:123456789012:incident-response",
							},
						},
					},
				},
				"tags": map[string]string{
					"SecurityMonitoring": "distributed",
					"CorrelationEnabled": "true",
				},
			},
			validation: validateDistributedAttackCorrelation,
		},
		{
			name: "service_dependency_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"service_group": map[string]interface{}{
					"hosts": []map[string]interface{}{
						{
							"instance_type": "c5.large",
							"role": "web",
							"alerts": map[string]interface{}{
								"error_rate": map[string]interface{}{
									"metric_name": "HTTPErrorRate",
									"threshold": 5,
									"period": 300,
								},
							},
						},
						{
							"instance_type": "c5.large",
							"role": "app",
							"alerts": map[string]interface{}{
								"error_rate": map[string]interface{}{
									"metric_name": "ApplicationErrorRate",
									"threshold": 5,
									"period": 300,
								},
							},
						},
						{
							"instance_type": "c5.large",
							"role": "db",
							"alerts": map[string]interface{}{
								"error_rate": map[string]interface{}{
									"metric_name": "DatabaseErrorRate",
									"threshold": 5,
									"period": 300,
								},
							},
						},
					},
					"correlation_rules": map[string]interface{}{
						"service_failure": map[string]interface{}{
							"rule": "ALARM(HTTPErrorRate) AND ALARM(ApplicationErrorRate) AND ALARM(DatabaseErrorRate)",
							"evaluation_period": 600, // 10 minutes
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:service-critical",
								"arn:aws:sns:us-west-2:123456789012:operations-team",
							},
						},
						"cascading_failure": map[string]interface{}{
							"rule": "ALARM(DatabaseErrorRate) AND (ALARM(ApplicationErrorRate) within(300)) AND (ALARM(HTTPErrorRate) within(600))",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:cascading-failure",
								"arn:aws:sns:us-west-2:123456789012:sre-team",
							},
						},
					},
				},
				"tags": map[string]string{
					"ServiceMonitoring": "end-to-end",
					"CorrelationEnabled": "true",
				},
			},
			validation: validateServiceDependencyCorrelation,
		},
		{
			name: "security_boundary_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"security_group": map[string]interface{}{
					"boundary_hosts": []map[string]interface{}{
						{
							"instance_type": "c5.large",
							"role": "edge",
							"alerts": map[string]interface{}{
								"intrusion_attempts": map[string]interface{}{
									"metric_name": "IntrusionAttempts",
									"threshold": 10,
									"period": 300,
								},
							},
						},
						{
							"instance_type": "c5.large",
							"role": "internal",
							"alerts": map[string]interface{}{
								"unauthorized_access": map[string]interface{}{
									"metric_name": "UnauthorizedAccess",
									"threshold": 0,
									"period": 300,
								},
							},
						},
					},
					"correlation_rules": map[string]interface{}{
						"boundary_breach": map[string]interface{}{
							"rule": "ALARM(IntrusionAttempts) AND ALARM(UnauthorizedAccess) within(900)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:security-boundary",
								"arn:aws:sns:us-west-2:123456789012:incident-response",
							},
						},
					},
				},
				"tags": map[string]string{
					"SecurityBoundary": "enabled",
					"CorrelationEnabled": "true",
				},
			},
			validation: validateSecurityBoundaryCorrelation,
		},
		{
			name: "multi_region_correlation",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"multi_region": map[string]interface{}{
					"primary_region": "us-west-2",
					"secondary_regions": []string{"us-east-1", "eu-west-1"},
					"alerts": map[string]interface{}{
						"auth_failure": map[string]interface{}{
							"metric_name": "AuthFailure",
							"threshold": 5,
							"period": 300,
							"evaluation_periods": 1,
						},
					},
					"correlation_rules": map[string]interface{}{
						"coordinated_attack": map[string]interface{}{
							"rule": "COUNT(ALARM(AuthFailure)) >= 2 across regions within(1800)",
							"actions": []string{
								"arn:aws:sns:us-west-2:123456789012:global-security",
								"arn:aws:sns:us-west-2:123456789012:cirt-team",
							},
						},
					},
				},
				"tags": map[string]string{
					"GlobalMonitoring": "enabled",
					"CorrelationLevel": "multi-region",
				},
			},
			validation: validateMultiRegionCorrelation,
		},
	}

	for _, corr := range correlations {
		corr := corr
		t.Run(corr.name, func(t *testing.T) {
			t.Parallel()

			vars := map[string]interface{}{
				"name":              fmt.Sprintf("test-host-%s", uniqueID),
				"availability_zone": fmt.Sprintf("%sa", awsRegion),
				"host_recovery":     "on",
				"auto_placement":    "off",
			}

			for k, v := range corr.configuration {
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
				corr.validation(t, terraformOptions, awsRegion)
			})

			test_structure.RunTestStage(t, "teardown", func() {
				terraform.Destroy(t, terraformOptions)
			})
		})
	}
}

func validateDistributedAttackCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)

	// Get host IDs
	primaryHostID := terraform.Output(t, terraformOptions, "primary_host_id")
	require.NotEmpty(t, primaryHostID, "Primary host ID must be output")

	secondaryHostIDs := terraform.OutputList(t, terraformOptions, "secondary_host_ids")
	require.GreaterOrEqual(t, len(secondaryHostIDs), 2, "At least 2 secondary hosts required")

	// Verify individual host alarms
	for _, hostID := range append([]string{primaryHostID}, secondaryHostIDs...) {
		alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
		require.NoError(t, err)

		activityAlarm := findAlarmByName(alarms, "unusual_activity")
		require.NotNil(t, activityAlarm, "Each host must have unusual activity alarm")
		assert.Equal(t, float64(0.7), *activityAlarm.Threshold, "Threshold must be set to 0.7")
		assert.Equal(t, int64(300), *activityAlarm.Period, "Period must be 5 minutes")
	}

	// Verify correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, primaryHostID)
	require.NoError(t, err)

	distributedAlarm := findCompositeAlarmByName(compositeAlarms, "distributed_attack")
	require.NotNil(t, distributedAlarm, "Distributed attack correlation alarm must exist")

	// Verify correlation rule
	rule := *distributedAlarm.AlarmRule
	assert.Contains(t, rule, "COUNT(ALARM(UnusualActivityIndex))", "Rule must count alarms across hosts")
	assert.Contains(t, rule, ">= 2", "Rule must trigger when 2 or more hosts have alarms")
	assert.Contains(t, rule, "within(900)", "Rule must correlate within 15 minutes")

	// Verify correlation actions
	assert.GreaterOrEqual(t, len(distributedAlarm.AlarmActions), 2, "Must have at least 2 notification targets")
	hasSecurityCritical := false
	hasIncidentResponse := false
	for _, action := range distributedAlarm.AlarmActions {
		if strings.Contains(*action, "security-critical") {
			hasSecurityCritical = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
	}
	assert.True(t, hasSecurityCritical && hasIncidentResponse, 
		"Must notify both security-critical and incident-response")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, primaryHostID)
	assert.Equal(t, "distributed", tags["SecurityMonitoring"], "Host must have distributed security monitoring tag")
	assert.Equal(t, "true", tags["CorrelationEnabled"], "Host must have correlation enabled tag")
}

func validateServiceDependencyCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)

	// Get host IDs
	hostIDs := terraform.OutputList(t, terraformOptions, "service_host_ids")
	require.GreaterOrEqual(t, len(hostIDs), 3, "At least 3 hosts required for service dependency test")

	// Map to store host IDs by role
	hostsByRole := make(map[string]string)
	roles := []string{"web", "app", "db"}

	// Verify individual host alarms
	for i, hostID := range hostIDs {
		role := roles[i]
		hostsByRole[role] = hostID
		
		alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
		require.NoError(t, err)

		errorRateAlarm := findAlarmByName(alarms, "error_rate")
		require.NotNil(t, errorRateAlarm, fmt.Sprintf("%s host must have error rate alarm", role))
		assert.Equal(t, float64(5), *errorRateAlarm.Threshold, "Error threshold must be 5%")
		assert.Equal(t, int64(300), *errorRateAlarm.Period, "Period must be 5 minutes")
	}

	// Verify service failure correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostsByRole["web"])
	require.NoError(t, err)

	serviceFailureAlarm := findCompositeAlarmByName(compositeAlarms, "service_failure")
	require.NotNil(t, serviceFailureAlarm, "Service failure correlation alarm must exist")

	// Verify service failure rule
	rule := *serviceFailureAlarm.AlarmRule
	assert.Contains(t, rule, "ALARM(HTTPErrorRate)", "Rule must check web tier errors")
	assert.Contains(t, rule, "ALARM(ApplicationErrorRate)", "Rule must check app tier errors")
	assert.Contains(t, rule, "ALARM(DatabaseErrorRate)", "Rule must check database errors")
	
	// Verify cascading failure alarm
	cascadingFailureAlarm := findCompositeAlarmByName(compositeAlarms, "cascading_failure")
	require.NotNil(t, cascadingFailureAlarm, "Cascading failure correlation alarm must exist")
	
	// Verify cascading failure rule (timing of propagation)
	cascadingRule := *cascadingFailureAlarm.AlarmRule
	assert.Contains(t, cascadingRule, "ALARM(DatabaseErrorRate)", "Rule must detect DB errors first")
	assert.Contains(t, cascadingRule, "ALARM(ApplicationErrorRate) within(300)", "Rule must detect app errors within 5 minutes")
	assert.Contains(t, cascadingRule, "ALARM(HTTPErrorRate) within(600)", "Rule must detect web errors within 10 minutes")

	// Verify correlation actions
	assert.GreaterOrEqual(t, len(serviceFailureAlarm.AlarmActions), 2, "Must have at least 2 notification targets")
	hasServiceCritical := false
	hasOperationsTeam := false
	for _, action := range serviceFailureAlarm.AlarmActions {
		if strings.Contains(*action, "service-critical") {
			hasServiceCritical = true
		}
		if strings.Contains(*action, "operations-team") {
			hasOperationsTeam = true
		}
	}
	assert.True(t, hasServiceCritical && hasOperationsTeam, 
		"Must notify both service-critical and operations-team")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostsByRole["web"])
	assert.Equal(t, "end-to-end", tags["ServiceMonitoring"], "Host must have end-to-end service monitoring tag")
	assert.Equal(t, "true", tags["CorrelationEnabled"], "Host must have correlation enabled tag")
}

func validateSecurityBoundaryCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)

	// Get host IDs
	hostIDs := terraform.OutputList(t, terraformOptions, "boundary_host_ids")
	require.GreaterOrEqual(t, len(hostIDs), 2, "At least 2 hosts required for boundary test")

	// Map to store host IDs by role
	hostsByRole := make(map[string]string)
	roles := []string{"edge", "internal"}

	// Verify individual host alarms
	for i, hostID := range hostIDs {
		role := roles[i]
		hostsByRole[role] = hostID
		
		alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
		require.NoError(t, err)

		if role == "edge" {
			intrusionAlarm := findAlarmByName(alarms, "intrusion_attempts")
			require.NotNil(t, intrusionAlarm, "Edge host must have intrusion attempts alarm")
			assert.Equal(t, float64(10), *intrusionAlarm.Threshold, "Intrusion threshold must be 10")
		} else if role == "internal" {
			accessAlarm := findAlarmByName(alarms, "unauthorized_access")
			require.NotNil(t, accessAlarm, "Internal host must have unauthorized access alarm")
			assert.Equal(t, float64(0), *accessAlarm.Threshold, "Unauthorized access threshold must be 0")
		}
	}

	// Verify boundary breach correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostsByRole["edge"])
	require.NoError(t, err)

	boundaryAlarm := findCompositeAlarmByName(compositeAlarms, "boundary_breach")
	require.NotNil(t, boundaryAlarm, "Boundary breach correlation alarm must exist")

	// Verify boundary breach rule
	rule := *boundaryAlarm.AlarmRule
	assert.Contains(t, rule, "ALARM(IntrusionAttempts)", "Rule must check edge intrusion attempts")
	assert.Contains(t, rule, "ALARM(UnauthorizedAccess)", "Rule must check internal unauthorized access")
	assert.Contains(t, rule, "within(900)", "Rule must correlate within 15 minutes")

	// Verify correlation actions
	assert.GreaterOrEqual(t, len(boundaryAlarm.AlarmActions), 2, "Must have at least 2 notification targets")
	hasSecurityBoundary := false
	hasIncidentResponse := false
	for _, action := range boundaryAlarm.AlarmActions {
		if strings.Contains(*action, "security-boundary") {
			hasSecurityBoundary = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
	}
	assert.True(t, hasSecurityBoundary && hasIncidentResponse, 
		"Must notify both security-boundary and incident-response teams")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostsByRole["edge"])
	assert.Equal(t, "enabled", tags["SecurityBoundary"], "Host must have security boundary enabled tag")
	assert.Equal(t, "true", tags["CorrelationEnabled"], "Host must have correlation enabled tag")
}

func validateMultiRegionCorrelation(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)

	// Get host IDs for the primary region
	primaryHostID := terraform.Output(t, terraformOptions, "primary_region_host_id")
	require.NotEmpty(t, primaryHostID, "Primary region host ID must be output")

	// Verify primary region host alarm
	alarms, err := getAlarmsForHost(cloudwatchClient, primaryHostID)
	require.NoError(t, err)

	authFailureAlarm := findAlarmByName(alarms, "auth_failure")
	require.NotNil(t, authFailureAlarm, "Primary region host must have auth failure alarm")
	assert.Equal(t, float64(5), *authFailureAlarm.Threshold, "Auth failure threshold must be 5")
	assert.Equal(t, int64(300), *authFailureAlarm.Period, "Period must be 5 minutes")

	// Verify multi-region correlation alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, primaryHostID)
	require.NoError(t, err)

	coordinatedAttackAlarm := findCompositeAlarmByName(compositeAlarms, "coordinated_attack")
	require.NotNil(t, coordinatedAttackAlarm, "Coordinated attack correlation alarm must exist")

	// Verify multi-region correlation rule
	rule := *coordinatedAttackAlarm.AlarmRule
	assert.Contains(t, rule, "COUNT(ALARM(AuthFailure)) >= 2", "Rule must count auth failures across regions")
	assert.Contains(t, rule, "across regions", "Rule must specify cross-region correlation")
	assert.Contains(t, rule, "within(1800)", "Rule must correlate within 30 minutes")

	// Verify correlation actions
	assert.GreaterOrEqual(t, len(coordinatedAttackAlarm.AlarmActions), 2, "Must have at least 2 notification targets")
	hasGlobalSecurity := false
	hasCIRTTeam := false
	for _, action := range coordinatedAttackAlarm.AlarmActions {
		if strings.Contains(*action, "global-security") {
			hasGlobalSecurity = true
		}
		if strings.Contains(*action, "cirt-team") {
			hasCIRTTeam = true
		}
	}
	assert.True(t, hasGlobalSecurity && hasCIRTTeam, 
		"Must notify both global-security and CIRT teams")

	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, primaryHostID)
	assert.Equal(t, "enabled", tags["GlobalMonitoring"], "Host must have global monitoring enabled tag")
	assert.Equal(t, "multi-region", tags["CorrelationLevel"], "Host must have multi-region correlation level tag")
}

