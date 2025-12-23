package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/backup"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDedicatedHostRecoveryEnabled tests that host recovery can be enabled
func TestDedicatedHostRecoveryEnabled(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":          hostName,
			"host_recovery": "on",
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the example
	terraform.InitAndApply(t, terraformOptions)

	// Verify that host recovery is enabled
	hostRecoveryStatus := terraform.Output(t, terraformOptions, "host_recovery_status")
	assert.Equal(t, "on", hostRecoveryStatus)

	// Get the host ID
	hostID := terraform.Output(t, terraformOptions, "id")
	assert.NotEmpty(t, hostID)

	// Set up AWS session
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create EC2 service client
	ec2Svc := ec2.New(sess)

	// Verify host recovery setting in AWS
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{aws.String(hostID)},
	}

	result, err := ec2Svc.DescribeHosts(input)
	require.NoError(t, err)
	require.Len(t, result.Hosts, 1)
	assert.Equal(t, "on", *result.Hosts[0].HostRecovery)
}

// TestDedicatedHostRecoveryDisabled tests that host recovery can be disabled
func TestDedicatedHostRecoveryDisabled(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":          hostName,
			"host_recovery": "off",
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the example
	terraform.InitAndApply(t, terraformOptions)

	// Verify that host recovery is disabled
	hostRecoveryStatus := terraform.Output(t, terraformOptions, "host_recovery_status")
	assert.Equal(t, "off", hostRecoveryStatus)

	// Get the host ID
	hostID := terraform.Output(t, terraformOptions, "id")
	assert.NotEmpty(t, hostID)

	// Set up AWS session
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create EC2 service client
	ec2Svc := ec2.New(sess)

	// Verify host recovery setting in AWS
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{aws.String(hostID)},
	}

	result, err := ec2Svc.DescribeHosts(input)
	require.NoError(t, err)
	require.Len(t, result.Hosts, 1)
	assert.Equal(t, "off", *result.Hosts[0].HostRecovery)
}

// TestCloudWatchAlarmCreation tests that CloudWatch alarms are created correctly
func TestCloudWatchAlarmCreation(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":             hostName,
			"enable_monitoring": true,
			// Create a mock SNS topic ARN for testing
			"alarm_actions":    []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the example
	terraform.InitAndApply(t, terraformOptions)

	// Get the host ID
	hostID := terraform.Output(t, terraformOptions, "id")
	assert.NotEmpty(t, hostID)

	// Set up AWS session
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create CloudWatch service client
	cwSvc := cloudwatch.New(sess)

	// Verify CloudWatch alarm exists
	expectedAlarmName := fmt.Sprintf("%s-host-status", hostName)
	input := &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []*string{aws.String(expectedAlarmName)},
	}

	// Use retries because CloudWatch resources may take time to propagate
	maxRetries := 30
	timeBetweenRetries := 10 * time.Second

	_, err = retry.DoWithRetryE(t, "Check CloudWatch alarm", maxRetries, timeBetweenRetries, func() (string, error) {
		result, err := cwSvc.DescribeAlarms(input)
		if err != nil {
			return "", err
		}

		if len(result.MetricAlarms) == 0 {
			return "", fmt.Errorf("CloudWatch alarm %s not found", expectedAlarmName)
		}

		return "CloudWatch alarm found", nil
	})

	require.NoError(t, err, "CloudWatch alarm verification failed")
}

// TestSSMManagementIntegration tests SSM management integration
func TestSSMManagementIntegration(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":                 hostName,
			"enable_ssm_management": true,
			"ssm_activation_tier":  "advanced",
			"ssm_document_name":    "AWS-ConfigureAWSHost",
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the example
	terraform.InitAndApply(t, terraformOptions)

	// Verify SSM management is enabled
	ssmEnabled := terraform.Output(t, terraformOptions, "ssm_management_enabled")
	assert.Equal(t, "true", ssmEnabled)

	// Get the SSM activation ID
	ssmActivationID := terraform.Output(t, terraformOptions, "ssm_activation_id")
	assert.NotEmpty(t, ssmActivationID)

	// Set up AWS session
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create SSM service client
	ssmSvc := ssm.New(sess)

	// Verify SSM activation exists
	input := &ssm.DescribeActivationsInput{
		Filters: []*ssm.DescribeActivationsFilter{
			{
				FilterKey: aws.String("ActivationIds"),
				FilterValues: []*string{
					aws.String(ssmActivationID),
				},
			},
		},
	}

	result, err := ssmSvc.DescribeActivations(input)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.ActivationList), 1)
}

// TestAutomatedBackupConfiguration tests AWS Backup integration
func TestAutomatedBackupConfiguration(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":                   hostName,
			"enable_automated_backups": true,
			"backup_plan_schedule":   "cron(0 2 * * ? *)",
			"backup_retention_days":  30,
			"recovery_point_tags": map[string]interface{}{
				"BackupType": "Test",
			},
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the example
	terraform.InitAndApply(t, terraformOptions)

	// Verify backup is enabled
	backupEnabled := terraform.Output(t, terraformOptions, "backup_enabled")
	assert.Equal(t, "true", backupEnabled)

	// Get the backup vault ID and plan ID
	backupVaultID := terraform.Output(t, terraformOptions, "backup_vault_id")
	backupPlanID := terraform.Output(t, terraformOptions, "backup_plan_id")
	assert.NotEmpty(t, backupVaultID)
	assert.NotEmpty(t, backupPlanID)

	// Set up AWS session
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create AWS Backup service client
	backupSvc := backup.New(sess)

	// Verify backup vault exists
	vaultInput := &backup.DescribeBackupVaultInput{
		BackupVaultName: aws.String(backupVaultID),
	}

	_, err = backupSvc.DescribeBackupVault(vaultInput)
	require.NoError(t, err)

	// Verify backup plan exists
	planInput := &backup.DescribeBackupPlanInput{
		BackupPlanId: aws.String(backupPlanID),
	}

	planResult, err := backupSvc.DescribeBackupPlan(planInput)
	require.NoError(t, err)
	assert.NotNil(t, planResult.BackupPlan)
	assert.Equal(t, fmt.Sprintf("%s-backup-plan", hostName), *planResult.BackupPlan.BackupPlanName)
}

// TestCompleteRecoveryWorkflow tests a complete recovery workflow with all features enabled
func TestCompleteRecoveryWorkflow(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":                   hostName,
			"host_recovery":          "on",
			"enable_monitoring":      true,
			"enable_ssm_management":  true,
			"enable_automated_backups": true,
			"alarm_actions":          []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the example
	terraform.InitAndApply(t, terraformOptions)

	// Verify all recovery mechanisms are enabled
	hostRecoveryStatus := terraform.Output(t, terraformOptions, "host_recovery_status")
	ssmEnabled := terraform.Output(t, terraformOptions, "ssm_management_enabled")
	backupEnabled := terraform.Output(t, terraformOptions, "backup_enabled")

	assert.Equal(t, "on", hostRecoveryStatus)
	assert.Equal(t, "true", ssmEnabled)
	assert.Equal(t, "true", backupEnabled)

	// Get resource IDs
	hostID := terraform.Output(t, terraformOptions, "id")
	assert.NotEmpty(t, hostID)

	// Verify tags that enable various recovery features
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create EC2 service client
	ec2Svc := ec2.New(sess)

	// Verify host tags
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{aws.String(hostID)},
	}

	result, err := ec2Svc.DescribeHosts(input)
	require.NoError(t, err)
	require.Len(t, result.Hosts, 1)

	// Check for SSM management tag
	var hasSsmTag, hasBackupTag bool
	for _, tag := range result.Hosts[0].Tags {
		if *tag.Key == "SSMManaged" && *tag.Value == "true" {
			hasSsmTag = true
		}
		if *tag.Key == "AutomatedBackup" && *tag.Value == "enabled" {
			hasBackupTag = true
		}
	}

	assert.True(t, hasSsmTag, "Host should have SSMManaged tag")
	assert.True(t, hasBackupTag, "Host should have AutomatedBackup tag")
}

// TestRemediationWorkflowScenario tests a specific remediation workflow scenario
func TestRemediationWorkflowScenario(t *testing.T) {
	t.Parallel()

	// Unique name for resources to avoid conflicts
	uniqueID := random.UniqueId()
	hostName := fmt.Sprintf("test-host-%s", uniqueID)

	// First, deploy with host recovery disabled
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
		Vars: map[string]interface{}{
			"name":          hostName,
			"host_recovery": "off",
		},
	})

	// Clean up resources when the test is complete
	defer terraform.Destroy(t, terraformOptions)

	// Deploy the initial configuration
	terraform.InitAndApply(t, terraformOptions)

	// Verify host recovery is initially disabled
	hostRecoveryStatus := terraform.Output(t, terraformOptions, "host_recovery_status")
	assert.Equal(t, "off", hostRecoveryStatus)

	// Now simulate a remediation action by enabling host recovery
	// Update the Terraform configuration
	terraformOptions.Vars["host_recovery"] = "on"
	terraform.Apply(t, terraformOptions)

	// Verify host recovery is now enabled
	hostRecoveryStatus = terraform.Output(t, terraformOptions, "host_recovery_status")
	assert.Equal(t, "on", hostRecoveryStatus)

	// Get the host ID
	hostID := terraform.Output(t, terraformOptions, "id")
	assert.NotEmpty(t, hostID)

	// Verify the change in AWS
	awsRegion := terraform.Output(t, terraformOptions, "availability_zone")[:9] // Extract region from AZ
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})
	require.NoError(t, err)

	// Create EC2 service client
	ec2Svc := ec2.New(sess)

	// Verify host recovery setting in AWS
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{aws.String(hostID)},
	}

	result, err := ec2Svc.DescribeHosts(input)
	require.NoError(t, err)
	require.Len(t, result.Hosts, 1)
	assert.Equal(t, "on", *result.Hosts[0].HostRecovery)
}

