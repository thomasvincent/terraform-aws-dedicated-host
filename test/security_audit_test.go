package test

import (
	"fmt"
	"testing"
	"time"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMonitoringEncryptionRequirements tests encryption requirements for monitoring data
func TestMonitoringEncryptionRequirements(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	encryptionTestCases := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "kms_encrypted_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
				},
				"monitoring_encryption": map[string]interface{}{
					"kms_key_id":      "alias/dedicated-host-monitoring",
					"encrypt_metrics": true,
					"encrypt_logs":    true,
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-security",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "pci-dss",
					"DataClassification": "confidential",
					"EncryptionEnabled":  "true",
				},
			},
			validation: validateKMSEncryptedMonitoring,
		},
		{
			name: "cmk_encrypted_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
				},
				"monitoring_encryption": map[string]interface{}{
					"kms_key_id":         "alias/customer-managed-key",
					"encrypt_metrics":    true,
					"encrypt_logs":       true,
					"encryption_context": map[string]string{
						"Environment": "production",
						"Project":     "dedicated-host",
					},
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-security",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "hipaa",
					"DataClassification": "phi",
					"EncryptionEnabled":  "true",
					"CMKEnabled":         "true",
				},
			},
			validation: validateCMKEncryptedMonitoring,
		},
		{
			name: "unencrypted_monitoring",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:alerts",
				},
				"monitoring_encryption": map[string]interface{}{
					"encrypt_metrics": false,
					"encrypt_logs":    false,
				},
				"tags": map[string]string{
					"Environment":        "development",
					"Project":            "monitoring-testing",
					"ManagedBy":          "terraform",
					"CostCenter":         "development",
					"DataClassification": "internal",
					"EncryptionEnabled":  "false",
				},
			},
			validation: validateUnencryptedMonitoring,
		},
	}

	for _, tc := range encryptionTestCases {
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

// TestAuditLoggingRequirements tests audit logging configurations
func TestAuditLoggingRequirements(t *testing.T) {
	t.Parallel()

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)

	auditLoggingTestCases := []struct {
		name           string
		configuration  map[string]interface{}
		validation     func(*testing.T, *terraform.Options, string)
	}{
		{
			name: "comprehensive_audit_logging",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
				},
				"audit_logging": map[string]interface{}{
					"enabled":               true,
					"log_group_name":        "dedicated-host-audit-logs",
					"retention_in_days":     730, // 2 years
					"export_to_s3":          true,
					"s3_bucket":             "audit-logs-bucket",
					"log_metric_filters":    true,
					"log_api_calls":         true,
					"log_configuration_changes": true,
					"log_data_access":       true,
					"log_tag_changes":       true,
					"encrypted":             true,
					"kms_key_id":           "alias/audit-logs-key",
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-security",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "pci-dss,hipaa,sox",
					"DataClassification": "confidential",
					"AuditLoggingEnabled": "true",
				},
			},
			validation: validateComprehensiveAuditLogging,
		},
		{
			name: "minimal_audit_logging",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:alerts",
				},
				"audit_logging": map[string]interface{}{
					"enabled":               true,
					"log_group_name":        "dedicated-host-basic-logs",
					"retention_in_days":     90, // 3 months
					"log_metric_filters":    true,
					"log_configuration_changes": true,
					"encrypted":             false,
				},
				"tags": map[string]string{
					"Environment":        "development",
					"Project":            "monitoring-testing",
					"ManagedBy":          "terraform",
					"CostCenter":         "development",
					"DataClassification": "internal",
					"AuditLoggingEnabled": "true",
				},
			},
			validation: validateMinimalAuditLogging,
		},
		{
			name: "compliance_audit_logging",
			configuration: map[string]interface{}{
				"enable_monitoring": true,
				"alarm_actions": []string{
					"arn:aws:sns:us-west-2:123456789012:security-alerts",
					"arn:aws:sns:us-west-2:123456789012:compliance-team",
				},
				"audit_logging": map[string]interface{}{
					"enabled":               true,
					"log_group_name":        "dedicated-host-compliance-logs",
					"retention_in_days":     3650, // 10 years
					"export_to_s3":          true,
					"s3_bucket":             "compliance-logs-bucket",
					"log_metric_filters":    true,
					"log_api_calls":         true,
					"log_configuration_changes": true,
					"log_data_access":       true,
					"log_tag_changes":       true,
					"encrypted":             true,
					"kms_key_id":           "alias/compliance-logs-key",
					"immutable_storage":    true,
					"log_validation":       true,
				},
				"tags": map[string]string{
					"Environment":        "production",
					"Project":            "monitoring-security",
					"ManagedBy":          "terraform",
					"CostCenter":         "security",
					"Compliance":         "sox",
					"DataClassification": "confidential",
					"AuditLoggingEnabled": "true",
					"RetentionPolicy":     "10years",
					"ImmutableLogs":       "true",
				},
			},
			validation: validateComplianceAuditLogging,
		},
	}

	for _, tc := range auditLoggingTestCases {
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

// Validation functions for encryption testing

func validateKMSEncryptedMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS clients
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	logsClient := cloudwatchlogs.New(sess)
	kmsClient := kms.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Verify KMS configuration
	monitoringEncryption := terraformOptions.Vars["monitoring_encryption"].(map[string]interface{})
	kmsKeyID := monitoringEncryption["kms_key_id"].(string)
	
	// Verify KMS key exists
	describeKeyInput := &kms.DescribeKeyInput{
		KeyId: awssdk.String(kmsKeyID),
	}
	keyResult, err := kmsClient.DescribeKey(describeKeyInput)
	require.NoError(t, err)
	assert.NotNil(t, keyResult.KeyMetadata)
	assert.False(t, *keyResult.KeyMetadata.KeyState == "PendingDeletion", "KMS key should be active")
	
	// Verify CloudWatch logs are encrypted
	logGroupName := fmt.Sprintf("/aws/dedicated-host/%s", hostID)
	describeLogGroupsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupName),
	}
	logResult, err := logsClient.DescribeLogGroups(describeLogGroupsInput)
	require.NoError(t, err)
	
	// Check if log group exists and is encrypted
	var logGroupEncrypted bool
	for _, logGroup := range logResult.LogGroups {
		if strings.HasPrefix(*logGroup.LogGroupName, logGroupName) {
			assert.NotNil(t, logGroup.KmsKeyId, "Log group should be encrypted with KMS")
			logGroupEncrypted = true
			break
		}
	}
	assert.True(t, logGroupEncrypted, "Encrypted log group should exist")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "true", tags["EncryptionEnabled"])
	assert.Contains(t, tags, "DataClassification")
	assert.Contains(t, tags, "Compliance")
}

func validateCMKEncryptedMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS clients
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	cloudwatchClient := cloudwatch.New(sess)
	logsClient := cloudwatchlogs.New(sess)
	kmsClient := kms.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Verify KMS configuration
	monitoringEncryption := terraformOptions.Vars["monitoring_encryption"].(map[string]interface{})
	kmsKeyID := monitoringEncryption["kms_key_id"].(string)
	
	// Verify KMS key exists and is a customer managed key
	describeKeyInput := &kms.DescribeKeyInput{
		KeyId: awssdk.String(kmsKeyID),
	}
	keyResult, err := kmsClient.DescribeKey(describeKeyInput)
	require.NoError(t, err)
	assert.NotNil(t, keyResult.KeyMetadata)
	assert.False(t, *keyResult.KeyMetadata.KeyManager == "AWS", "Key should be customer managed")
	
	// Verify CloudWatch logs are encrypted with the CMK
	logGroupName := fmt.Sprintf("/aws/dedicated-host/%s", hostID)
	describeLogGroupsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupName),
	}
	logResult, err := logsClient.DescribeLogGroups(describeLogGroupsInput)
	require.NoError(t, err)
	
	// Check if log group exists and is encrypted with the right key
	var logGroupEncrypted bool
	for _, logGroup := range logResult.LogGroups {
		if strings.HasPrefix(*logGroup.LogGroupName, logGroupName) {
			assert.NotNil(t, logGroup.KmsKeyId, "Log group should be encrypted with KMS")
			assert.Contains(t, *logGroup.KmsKeyId, "customer-managed-key", "Log group should be encrypted with the customer managed key")
			logGroupEncrypted = true
			break
		}
	}
	assert.True(t, logGroupEncrypted, "Encrypted log group with CMK should exist")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "true", tags["EncryptionEnabled"])
	assert.Equal(t, "true", tags["CMKEnabled"])
	assert.Equal(t, "hipaa", tags["Compliance"])
	assert.Equal(t, "phi", tags["DataClassification"])
}

func validateUnencryptedMonitoring(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS clients
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	logsClient := cloudwatchlogs.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Verify monitoring encryption configuration
	monitoringEncryption := terraformOptions.Vars["monitoring_encryption"].(map[string]interface{})
	assert.False(t, monitoringEncryption["encrypt_metrics"].(bool))
	assert.False(t, monitoringEncryption["encrypt_logs"].(bool))
	
	// Verify CloudWatch logs are not encrypted
	logGroupName := fmt.Sprintf("/aws/dedicated-host/%s", hostID)
	describeLogGroupsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupName),
	}
	logResult, err := logsClient.DescribeLogGroups(describeLogGroupsInput)
	require.NoError(t, err)
	
	// Check if log group exists and is not encrypted
	for _, logGroup := range logResult.LogGroups {
		if strings.HasPrefix(*logGroup.LogGroupName, logGroupName) {
			assert.Nil(t, logGroup.KmsKeyId, "Log group should not be encrypted")
			break
		}
	}
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "false", tags["EncryptionEnabled"])
	assert.Equal(t, "internal", tags["DataClassification"])
	assert.NotContains(t, tags, "Compliance")
}

// Validation functions for audit logging testing

func validateComprehensiveAuditLogging(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS clients
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	logsClient := cloudwatchlogs.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Verify audit logging configuration
	auditLogging := terraformOptions.Vars["audit_logging"].(map[string]interface{})
	assert.True(t, auditLogging["enabled"].(bool))
	assert.Equal(t, 730, auditLogging["retention_in_days"])
	assert.True(t, auditLogging["export_to_s3"].(bool))
	assert.True(t, auditLogging["log_metric_filters"].(bool))
	assert.True(t, auditLogging["log_api_calls"].(bool))
	assert.True(t, auditLogging["log_configuration_changes"].(bool))
	assert.True(t, auditLogging["log_data_access"].(bool))
	assert.True(t, auditLogging["log_tag_changes"].(bool))
	assert.True(t, auditLogging["encrypted"].(bool))
	
	// Verify log group configuration
	logGroupName := auditLogging["log_group_name"].(string)
	describeLogGroupsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupName),
	}
	logResult, err := logsClient.DescribeLogGroups(describeLogGroupsInput)
	require.NoError(t, err)
	
	// Check if log group exists with the right configuration
	var logGroupFound bool
	for _, logGroup := range logResult.LogGroups {
		if *logGroup.LogGroupName == logGroupName {
			assert.Equal(t, int64(730), *logGroup.RetentionInDays)
			assert.NotNil(t, logGroup.KmsKeyId, "Audit logs should be encrypted")
			logGroupFound = true
			break
		}
	}
	assert.True(t, logGroupFound, "Audit log group should exist")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "true", tags["AuditLoggingEnabled"])
	assert.Contains(t, tags["Compliance"], "pci-dss")
	assert.Contains(t, tags["Compliance"], "hipaa")
	assert.Contains(t, tags["Compliance"], "sox")
}

func validateMinimalAuditLogging(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS clients
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	logsClient := cloudwatchlogs.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Verify audit logging configuration
	auditLogging := terraformOptions.Vars["audit_logging"].(map[string]interface{})
	assert.True(t, auditLogging["enabled"].(bool))
	assert.Equal(t, 90, auditLogging["retention_in_days"])
	assert.True(t, auditLogging["log_metric_filters"].(bool))
	assert.True(t, auditLogging["log_configuration_changes"].(bool))
	assert.False(t, auditLogging["encrypted"].(bool))
	
	// Verify log group configuration
	logGroupName := auditLogging["log_group_name"].(string)
	describeLogGroupsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupName),
	}
	logResult, err := logsClient.DescribeLogGroups(describeLogGroupsInput)
	require.NoError(t, err)
	
	// Check if log group exists with the right configuration
	var logGroupFound bool
	for _, logGroup := range logResult.LogGroups {
		if *logGroup.LogGroupName == logGroupName {
			assert.Equal(t, int64(90), *logGroup.RetentionInDays)
			assert.Nil(t, logGroup.KmsKeyId, "Basic audit logs may not be encrypted")
			logGroupFound = true
			break
		}
	}
	assert.True(t, logGroupFound, "Audit log group should exist")
	
	// Verify tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "true", tags["AuditLoggingEnabled"])
	assert.Equal(t, "internal", tags["DataClassification"])
}

func validateComplianceAuditLogging(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	// Create AWS clients
	sess, err := session.NewSession(&awssdk.Config{
		Region: awssdk.String(awsRegion),
	})
	require.NoError(t, err)
	
	logsClient := cloudwatchlogs.New(sess)
	
	// Get host ID
	hostID := terraform.Output(t, terraformOptions, "host_id")
	require.NotEmpty(t, hostID)
	
	// Verify audit logging configuration for compliance
	auditLogging := terraformOptions.Vars["audit_logging"].(map[string]interface{})
	assert.True(t, auditLogging["enabled"].(bool))
	assert.Equal(t, 3650, auditLogging["retention_in_days"]) // 10 years
	assert.True(t, auditLogging["export_to_s3"].(bool))
	assert.True(t, auditLogging["log_metric_filters"].(bool))
	assert.True(t, auditLogging["log_api_calls"].(bool))
	assert.True(t, auditLogging["log_configuration_changes"].(bool))
	assert.True(t, auditLogging["log_data_access"].(bool))
	assert.True(t, auditLogging["log_tag_changes"].(bool))
	assert.True(t, auditLogging["encrypted"].(bool))
	assert.True(t, auditLogging["immutable_storage"].(bool))
	assert.True(t, auditLogging["log_validation"].(bool))
	
	// Verify log group configuration
	logGroupName := auditLogging["log_group_name"].(string)
	describeLogGroupsInput := &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: awssdk.String(logGroupName),
	}
	logResult, err := logsClient.DescribeLogGroups(describeLogGroupsInput)
	require.NoError(t, err)
	
	// Check if log group exists with the right configuration
	var logGroupFound bool
	for _, logGroup := range logResult.LogGroups {
		if *logGroup.LogGroupName == logGroupName {
			assert.Equal(t, int64(3650), *logGroup.RetentionInDays)
			assert.NotNil(t, logGroup.KmsKeyId, "Compliance audit logs must be encrypted")
			logGroupFound = true
			break
		}
	}
	assert.True(t, logGroupFound, "Compliance audit log group should exist")
	
	// Verify compliance tags
	tags := aws.GetTagsForEc2Host(t, awsRegion, hostID)
	assert.Equal(t, "true", tags["AuditLoggingEnabled"])
	assert.Equal(t, "sox", tags["Compliance"])
	assert.Equal(t, "10years", tags["RetentionPolicy"])
	assert.Equal(t, "true", tags["ImmutableLogs"])
}

