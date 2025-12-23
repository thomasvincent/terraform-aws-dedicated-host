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

func TestAdvancedAlertSequences(t *testing.T) {
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
			name: "pci_dss_alert_sequence",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"unauthorized_access_attempt": map[string]interface{}{
						"metric_name": "UnauthorizedAPIAttempts",
						"threshold": 1,
						"period": 60,
						"evaluation_periods": 1,
					},
					"configuration_change": map[string]interface{}{
						"metric_name": "ConfigurationChanges",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"sensitive_data_access": map[string]interface{}{
						"metric_name": "SensitiveDataAccess",
						"threshold": 0,
						"period": 60,
						"evaluation_periods": 1,
					},
					"sequence_window": 900, // 15 minutes
					"compliance_framework": "pci-dss",
					"required_notifications": []string{
						"security_team",
						"compliance_team",
						"incident_response",
					},
					"notification_escalation": map[string]interface{}{
						"initial": []string{
							"arn:aws:sns:us-west-2:123456789012:pci-monitoring",
						},
						"escalated": []string{
							"arn:aws:sns:us-west-2:123456789012:pci-security-team",
							"arn:aws:sns:us-west-2:123456789012:compliance-team",
						},
						"critical": []string{
							"arn:aws:sns:us-west-2:123456789012:incident-response",
							"arn:aws:sns:us-west-2:123456789012:executive-team",
						},
					},
				},
				"tags": map[string]string{
					"Compliance": "pci-dss",
					"PCIControl": "10.6.1",
					"DataClassification": "restricted",
				},
			},
			validation: validatePCIDSSSequence,
		},
		{
			name: "ransomware_detection_sequence",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"file_system_changes": map[string]interface{}{
						"metric_name": "FileSystemOperations",
						"threshold": 1000,
						"period": 60,
						"evaluation_periods": 1,
					},
					"encryption_operations": map[string]interface{}{
						"metric_name": "CryptoOperations",
						"threshold": 100,
						"period": 60,
						"evaluation_periods": 1,
					},
					"network_anomaly": map[string]interface{}{
						"metric_name": "NetworkOutBytes",
						"threshold": 1000000000, // 1GB
						"period": 300,
						"evaluation_periods": 1,
					},
					"sequence_window": 600, // 10 minutes
					"response_actions": []string{
						"isolate_host",
						"block_network",
						"snapshot_filesystem",
					},
					"notification_targets": []string{
						"arn:aws:sns:us-west-2:123456789012:security-critical",
						"arn:aws:sns:us-west-2:123456789012:incident-response",
						"arn:aws:sns:us-west-2:123456789012:forensics-team",
					},
				},
				"tags": map[string]string{
					"SecurityMonitoring": "enhanced",
					"RansomwareProtection": "enabled",
					"IncidentResponse": "automated",
				},
			},
			validation: validateRansomwareSequence,
		},
		{
			name: "lateral_movement_sequence",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"credential_access": map[string]interface{}{
						"metric_name": "CredentialAccess",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"privilege_escalation": map[string]interface{}{
						"metric_name": "PrivilegeEscalation",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"network_discovery": map[string]interface{}{
						"metric_name": "NetworkDiscovery",
						"threshold": 100,
						"period": 300,
						"evaluation_periods": 1,
					},
					"unusual_process": map[string]interface{}{
						"metric_name": "UnusualProcessExecution",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"sequence_window": 1800, // 30 minutes
					"detection_actions": []string{
						"enable_enhanced_monitoring",
						"capture_process_data",
						"network_isolation",
					},
					"notification_targets": []string{
						"arn:aws:sns:us-west-2:123456789012:threat-detection",
						"arn:aws:sns:us-west-2:123456789012:soc-team",
						"arn:aws:sns:us-west-2:123456789012:incident-response",
					},
				},
				"tags": map[string]string{
					"ThreatDetection": "advanced",
					"SecurityMonitoring": "enhanced",
					"MITRECategory": "lateral-movement",
				},
			},
			validation: validateLateralMovementSequence,
		},
		{
			name: "hipaa_data_exfiltration_sequence",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"sequence_alerts": map[string]interface{}{
					"unusual_access_pattern": map[string]interface{}{
						"metric_name": "UnusualAccessPattern",
						"threshold": 0,
						"period": 300,
						"evaluation_periods": 1,
					},
					"data_access_volume": map[string]interface{}{
						"metric_name": "DataAccessVolume",
						"threshold": 100000000, // 100MB
						"period": 300,
						"evaluation_periods": 1,
					},
					"external_data_transfer": map[string]interface{}{
						"metric_name": "ExternalDataTransfer",
						"threshold": 10000000, // 10MB
						"period": 300,
						"evaluation_periods": 1,
					},
					"sensitive_data_operation": map[string]interface{}{
						"metric_name": "PHIDataOperation",
						"threshold": 0,
						"period": 60,
						"evaluation_periods": 1,
					},
					"sequence_window": 1200, // 20 minutes
					"compliance_framework": "hipaa",
					"required_notifications": []string{
						"security_team",
						"compliance_team",
						"privacy_officer",
						"incident_response",
					},
				},
				"tags": map[string]string{
					"Compliance": "hipaa",
					"DataClassification": "phi",
					"SecurityControl": "data-leakage-prevention",
				},
			},
			validation: validateHIPAAExfiltrationSequence,
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

func validatePCIDSSSequence(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify PCI DSS specific alarms
	unauthorizedAccessAlarm := findAlarmByName(alarms, "unauthorized_access_attempt")
	require.NotNil(t, unauthorizedAccessAlarm)
	assert.Equal(t, int64(60), *unauthorizedAccessAlarm.Period)
	assert.Equal(t, "breaching", *unauthorizedAccessAlarm.TreatMissingData)

	sensitiveDataAlarm := findAlarmByName(alarms, "sensitive_data_access")
	require.NotNil(t, sensitiveDataAlarm)
	assert.Equal(t, int64(60), *sensitiveDataAlarm.Period)

	// Verify composite sequence alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	pciSequenceAlarm := findCompositeAlarmByName(compositeAlarms, "pci_dss_violation_sequence")
	require.NotNil(t, pciSequenceAlarm)

	// Verify PCI-specific sequence timing
	rule := *pciSequenceAlarm.AlarmRule
	assert.Contains(t, rule, "within(900)")
	assert.Contains(t, rule, "ALARM(unauthorized_access_attempt)")
	assert.Contains(t, rule, "ALARM(sensitive_data_access)")

	// Verify escalation pattern
	assert.GreaterOrEqual(t, len(pciSequenceAlarm.AlarmActions), 3)
	hasSecurityTeam := false
	hasComplianceTeam := false
	hasIncidentResponse := false
	for _, action := range pciSequenceAlarm.AlarmActions {
		if strings.Contains(*action, "pci-security-team") {
			hasSecurityTeam = true
		}
		if strings.Contains(*action, "compliance-team") {
			hasComplianceTeam = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
	}
	assert.True(t, hasSecurityTeam && hasComplianceTeam && hasIncidentResponse, 
		"PCI DSS requires notifications to security team, compliance team, and incident response")

	// Verify PCI DSS tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "pci-dss", tags["Compliance"], "Host must be tagged with PCI-DSS compliance framework")
	assert.Equal(t, "10.6.1", tags["PCIControl"], "Host must reference specific PCI DSS control")
	assert.Equal(t, "restricted", tags["DataClassification"], "Host must have appropriate data classification")
}

func validateRansomwareSequence(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify ransomware detection alarms
	fsChangesAlarm := findAlarmByName(alarms, "file_system_changes")
	require.NotNil(t, fsChangesAlarm, "File system changes alarm must exist")
	assert.Equal(t, int64(60), *fsChangesAlarm.Period, "File system monitoring requires 1-minute granularity")
	assert.Equal(t, float64(1000), *fsChangesAlarm.Threshold, "File system threshold must detect high-volume changes")

	cryptoOpsAlarm := findAlarmByName(alarms, "encryption_operations")
	require.NotNil(t, cryptoOpsAlarm, "Encryption operations alarm must exist")
	assert.Equal(t, int64(60), *cryptoOpsAlarm.Period, "Crypto operations require 1-minute granularity")

	networkAnomalyAlarm := findAlarmByName(alarms, "network_anomaly")
	require.NotNil(t, networkAnomalyAlarm, "Network anomaly alarm must exist")
	assert.Equal(t, float64(1000000000), *networkAnomalyAlarm.Threshold, "Network threshold must detect large outbound transfers")

	// Verify composite sequence alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	ransomwareAlarm := findCompositeAlarmByName(compositeAlarms, "ransomware_detection")
	require.NotNil(t, ransomwareAlarm, "Ransomware composite alarm must exist")

	// Verify ransomware sequence timing
	rule := *ransomwareAlarm.AlarmRule
	assert.Contains(t, rule, "within(600)", "Ransomware detection requires 10-minute window")
	assert.Contains(t, rule, "ALARM(file_system_changes)", "Must monitor file system activity")
	assert.Contains(t, rule, "ALARM(encryption_operations)", "Must monitor crypto operations")
	assert.Contains(t, rule, "ALARM(network_anomaly)", "Must monitor network anomalies")

	// Verify all required notifications
	assert.GreaterOrEqual(t, len(ransomwareAlarm.AlarmActions), 3, "Must have at least 3 notification targets")
	hasSecurityTeam := false
	hasIncidentResponse := false
	hasForensicsTeam := false
	for _, action := range ransomwareAlarm.AlarmActions {
		if strings.Contains(*action, "security-critical") {
			hasSecurityTeam = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
		if strings.Contains(*action, "forensics-team") {
			hasForensicsTeam = true
		}
	}
	assert.True(t, hasSecurityTeam && hasIncidentResponse && hasForensicsTeam, 
		"Ransomware detection requires notifications to security, incident response, and forensics teams")

	// Verify security tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "enhanced", tags["SecurityMonitoring"], "Host must have enhanced security monitoring")
	assert.Equal(t, "enabled", tags["RansomwareProtection"], "Host must have ransomware protection enabled")
	assert.Equal(t, "automated", tags["IncidentResponse"], "Host must have automated incident response")
}

func validateLateralMovementSequence(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify lateral movement detection alarms
	credentialAccessAlarm := findAlarmByName(alarms, "credential_access")
	require.NotNil(t, credentialAccessAlarm, "Credential access alarm must exist")
	assert.Equal(t, float64(0), *credentialAccessAlarm.Threshold, "Any credential access must trigger alert")

	privilegeEscalationAlarm := findAlarmByName(alarms, "privilege_escalation")
	require.NotNil(t, privilegeEscalationAlarm, "Privilege escalation alarm must exist")
	assert.Equal(t, float64(0), *privilegeEscalationAlarm.Threshold, "Any privilege escalation must trigger alert")

	networkDiscoveryAlarm := findAlarmByName(alarms, "network_discovery")
	require.NotNil(t, networkDiscoveryAlarm, "Network discovery alarm must exist")

	unusualProcessAlarm := findAlarmByName(alarms, "unusual_process")
	require.NotNil(t, unusualProcessAlarm, "Unusual process alarm must exist")

	// Verify composite sequence alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	lateralMovementAlarm := findCompositeAlarmByName(compositeAlarms, "lateral_movement")
	require.NotNil(t, lateralMovementAlarm, "Lateral movement composite alarm must exist")

	// Verify lateral movement sequence timing
	rule := *lateralMovementAlarm.AlarmRule
	assert.Contains(t, rule, "within(1800)", "Lateral movement detection requires 30-minute window")
	assert.Contains(t, rule, "ALARM(credential_access)", "Must monitor credential access")
	assert.Contains(t, rule, "ALARM(privilege_escalation)", "Must monitor privilege escalation")
	assert.Contains(t, rule, "ALARM(network_discovery)", "Must monitor network discovery")
	assert.Contains(t, rule, "ALARM(unusual_process)", "Must monitor unusual processes")

	// Verify notifications
	assert.GreaterOrEqual(t, len(lateralMovementAlarm.AlarmActions), 3, "Must have at least 3 notification targets")
	hasThreatDetection := false
	hasSOCTeam := false
	hasIncidentResponse := false
	for _, action := range lateralMovementAlarm.AlarmActions {
		if strings.Contains(*action, "threat-detection") {
			hasThreatDetection = true
		}
		if strings.Contains(*action, "soc-team") {
			hasSOCTeam = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
	}
	assert.True(t, hasThreatDetection && hasSOCTeam && hasIncidentResponse, 
		"Lateral movement detection requires notifications to threat detection, SOC, and incident response teams")

	// Verify security tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "advanced", tags["ThreatDetection"], "Host must have advanced threat detection")
	assert.Equal(t, "enhanced", tags["SecurityMonitoring"], "Host must have enhanced security monitoring")
	assert.Equal(t, "lateral-movement", tags["MITRECategory"], "Host must reference MITRE ATT&CK category")
}

func validateHIPAAExfiltrationSequence(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)

	cloudwatchClient := cloudwatch.New(sess)
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)

	alarms, err := getAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	// Verify HIPAA data exfiltration alarms
	unusualAccessAlarm := findAlarmByName(alarms, "unusual_access_pattern")
	require.NotNil(t, unusualAccessAlarm, "Unusual access pattern alarm must exist")
	assert.Equal(t, float64(0), *unusualAccessAlarm.Threshold, "Any unusual access pattern must trigger alert")

	dataVolumeAlarm := findAlarmByName(alarms, "data_access_volume")
	require.NotNil(t, dataVolumeAlarm, "Data access volume alarm must exist")
	assert.Equal(t, float64(100000000), *dataVolumeAlarm.Threshold, "Data volume threshold must detect large data access")

	externalTransferAlarm := findAlarmByName(alarms, "external_data_transfer")
	require.NotNil(t, externalTransferAlarm, "External transfer alarm must exist")
	assert.Equal(t, float64(10000000), *externalTransferAlarm.Threshold, "External transfer threshold must detect PHI data transfers")

	phiOperationAlarm := findAlarmByName(alarms, "sensitive_data_operation")
	require.NotNil(t, phiOperationAlarm, "PHI data operation alarm must exist")
	assert.Equal(t, int64(60), *phiOperationAlarm.Period, "PHI operation monitoring requires 1-minute granularity")

	// Verify composite sequence alarm
	compositeAlarms, err := getCompositeAlarmsForHost(cloudwatchClient, hostID)
	require.NoError(t, err)

	hipaaAlarm := findCompositeAlarmByName(compositeAlarms, "hipaa_data_exfiltration")
	require.NotNil(t, hipaaAlarm, "HIPAA data exfiltration composite alarm must exist")

	// Verify HIPAA sequence timing
	rule := *hipaaAlarm.AlarmRule
	assert.Contains(t, rule, "within(1200)", "HIPAA data exfiltration detection requires 20-minute window")
	assert.Contains(t, rule, "ALARM(unusual_access_pattern)", "Must monitor unusual access patterns")
	assert.Contains(t, rule, "ALARM(data_access_volume)", "Must monitor data access volume")
	assert.Contains(t, rule, "ALARM(external_data_transfer)", "Must monitor external data transfers")
	assert.Contains(t, rule, "ALARM(sensitive_data_operation)", "Must monitor PHI data operations")

	// Verify required notifications
	assert.GreaterOrEqual(t, len(hipaaAlarm.AlarmActions), 4, "Must have at least 4 notification targets for HIPAA")
	hasSecurityTeam := false
	hasComplianceTeam := false
	hasPrivacyOfficer := false
	hasIncidentResponse := false
	for _, action := range hipaaAlarm.AlarmActions {
		if strings.Contains(*action, "security-team") {
			hasSecurityTeam = true
		}
		if strings.Contains(*action, "compliance-team") {
			hasComplianceTeam = true
		}
		if strings.Contains(*action, "privacy-officer") {
			hasPrivacyOfficer = true
		}
		if strings.Contains(*action, "incident-response") {
			hasIncidentResponse = true
		}
	}
	assert.True(t, hasSecurityTeam && hasComplianceTeam && hasPrivacyOfficer && hasIncidentResponse, 
		"HIPAA requires notifications to security, compliance, privacy officer, and incident response")

	// Verify HIPAA tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "hipaa", tags["Compliance"], "Host must be tagged with HIPAA compliance framework")
	assert.Equal(t, "phi", tags["DataClassification"], "Host must have PHI data classification")
	assert.Equal(t, "data-leakage-prevention", tags["SecurityControl"], "Host must have data leakage prevention controls")
}

