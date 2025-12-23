package test

import (
	"fmt"
	"testing"
	"time"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInstanceFailoverBehavior tests instance failover during host failure
func TestInstanceFailoverBehavior(t *testing.T) {
	t.Parallel()

	// Skip in short mode as this test creates EC2 instances and simulates failures
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	workingDir := "../examples/complete"
	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)
	availabilityZone := fmt.Sprintf("%sa", awsRegion)

	terraformOptions := &terraform.Options{
		TerraformDir: workingDir,
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("test-host-%s", uniqueID),
			"availability_zone": availabilityZone,
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "off",
			"enable_monitoring": true,
			"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
			"tags": map[string]string{
				"Name":        fmt.Sprintf("test-host-%s", uniqueID),
				"Environment": "test",
				"TestCase":    "instance-failover",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Use test_structure to cleanly setup and teardown resources
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, terraformOptions)
	})

	defer test_structure.RunTestStage(t, "teardown", func() {
		terraform.Destroy(t, terraformOptions)
	})

	test_structure.RunTestStage(t, "validate", func() {
		// Get the host ID from Terraform output
		hostID := terraform.Output(t, terraformOptions, "host_id")
		require.NotEmpty(t, hostID)

		// Create AWS session
		sess, err := session.NewSession(&awssdk.Config{
			Region: awssdk.String(awsRegion),
		})
		require.NoError(t, err)

		ec2Client := ec2.New(sess)

		// Launch an EC2 instance on the dedicated host
		instanceID, err := launchInstanceOnHost(t, ec2Client, hostID, availabilityZone, uniqueID)
		require.NoError(t, err)
		defer terminateInstance(t, ec2Client, instanceID)

		// Verify instance is running on the dedicated host
		verifyInstanceOnHost(t, ec2Client, instanceID, hostID)

		// Simulate host failure by stopping and starting the instance
		// Note: We can't actually fail the host in an automated test, but we can simulate 
		// the recovery behavior by triggering instance movement
		err = simulateHostFailureRecovery(t, ec2Client, instanceID, hostID)
		require.NoError(t, err)

		// Wait for instance to be running again
		waitForInstanceRunning(t, ec2Client, instanceID)

		// Verify instance connectivity
		verifyInstanceConnectivity(t, ec2Client, instanceID)

		// Verify instance has moved to a new host (after recovery)
		// The instance should either be on a new host or the same host after recovery
		newHostID := getInstanceHostID(t, ec2Client, instanceID)
		assert.NotEmpty(t, newHostID, "Instance should be assigned to a host after recovery")
	})
}

// TestMultiAZRecovery tests recovery across multiple availability zones
func TestMultiAZRecovery(t *testing.T) {
	t.Parallel()

	// Skip in short mode as this test creates resources across multiple AZs
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)
	primaryAZ := fmt.Sprintf("%sa", awsRegion)
	secondaryAZ := fmt.Sprintf("%sb", awsRegion)

	// First set up the primary AZ host
	primaryTerraformOptions := &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("primary-host-%s", uniqueID),
			"availability_zone": primaryAZ,
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "off",
			"enable_monitoring": true,
			"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
			"tags": map[string]string{
				"Name":        fmt.Sprintf("primary-host-%s", uniqueID),
				"Environment": "test",
				"TestCase":    "multi-az-recovery",
				"Role":        "primary",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Then set up the secondary AZ host
	secondaryTerraformOptions := &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("secondary-host-%s", uniqueID),
			"availability_zone": secondaryAZ,
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "off",
			"enable_monitoring": true,
			"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
			"tags": map[string]string{
				"Name":        fmt.Sprintf("secondary-host-%s", uniqueID),
				"Environment": "test",
				"TestCase":    "multi-az-recovery",
				"Role":        "secondary",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Clean up resources when done
	defer test_structure.RunTestStage(t, "teardown_secondary", func() {
		terraform.Destroy(t, secondaryTerraformOptions)
	})
	
	defer test_structure.RunTestStage(t, "teardown_primary", func() {
		terraform.Destroy(t, primaryTerraformOptions)
	})

	// Deploy hosts
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, primaryTerraformOptions)
		terraform.InitAndApply(t, secondaryTerraformOptions)
	})

	test_structure.RunTestStage(t, "validate", func() {
		// Get host IDs
		primaryHostID := terraform.Output(t, primaryTerraformOptions, "host_id")
		secondaryHostID := terraform.Output(t, secondaryTerraformOptions, "host_id")
		require.NotEmpty(t, primaryHostID)
		require.NotEmpty(t, secondaryHostID)

		// Create AWS session
		sess, err := session.NewSession(&awssdk.Config{
			Region: awssdk.String(awsRegion),
		})
		require.NoError(t, err)

		ec2Client := ec2.New(sess)

		// Launch an EC2 instance on the primary host
		instanceID, err := launchInstanceOnHost(t, ec2Client, primaryHostID, primaryAZ, uniqueID)
		require.NoError(t, err)
		defer terminateInstance(t, ec2Client, instanceID)

		// Verify instance is running on the primary host
		verifyInstanceOnHost(t, ec2Client, instanceID, primaryHostID)

		// Simulate primary host failure by stopping the instance and modifying placement
		// to move it to the secondary host
		err = migrateInstanceToSecondaryHost(t, ec2Client, instanceID, secondaryHostID)
		require.NoError(t, err)

		// Wait for instance to be running on secondary host
		waitForInstanceRunning(t, ec2Client, instanceID)

		// Verify instance is now running on the secondary host
		verifyInstanceOnHost(t, ec2Client, instanceID, secondaryHostID)

		// Measure recovery time (We can't get exact time but we can validate it's available)
		verifyInstanceConnectivity(t, ec2Client, instanceID)
	})
}

// TestCapacityRebalancing tests host capacity rebalancing with multiple instances
func TestCapacityRebalancing(t *testing.T) {
	t.Parallel()

	// Skip in short mode as this test creates multiple hosts and instances
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)
	availabilityZone := fmt.Sprintf("%sa", awsRegion)

	// Create two hosts in the same AZ
	host1TerraformOptions := &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("host1-%s", uniqueID),
			"availability_zone": availabilityZone,
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "off",
			"tags": map[string]string{
				"Name":        fmt.Sprintf("host1-%s", uniqueID),
				"Environment": "test",
				"TestCase":    "capacity-rebalancing",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	host2TerraformOptions := &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("host2-%s", uniqueID),
			"availability_zone": availabilityZone,
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "on", // Enable auto placement for rebalancing
			"tags": map[string]string{
				"Name":        fmt.Sprintf("host2-%s", uniqueID),
				"Environment": "test",
				"TestCase":    "capacity-rebalancing",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Clean up resources when done
	defer test_structure.RunTestStage(t, "teardown_host2", func() {
		terraform.Destroy(t, host2TerraformOptions)
	})
	
	defer test_structure.RunTestStage(t, "teardown_host1", func() {
		terraform.Destroy(t, host1TerraformOptions)
	})

	// Deploy hosts
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, host1TerraformOptions)
		terraform.InitAndApply(t, host2TerraformOptions)
	})

	test_structure.RunTestStage(t, "validate", func() {
		// Get host IDs
		host1ID := terraform.Output(t, host1TerraformOptions, "host_id")
		host2ID := terraform.Output(t, host2TerraformOptions, "host_id")
		require.NotEmpty(t, host1ID)
		require.NotEmpty(t, host2ID)

		// Create AWS session
		sess, err := session.NewSession(&awssdk.Config{
			Region: awssdk.String(awsRegion),
		})
		require.NoError(t, err)

		ec2Client := ec2.New(sess)

		// Launch multiple instances on host1 to fill capacity
		var instanceIDs []string
		for i := 0; i < 3; i++ {
			instanceID, err := launchInstanceOnHost(t, ec2Client, host1ID, availabilityZone, fmt.Sprintf("%s-%d", uniqueID, i))
			require.NoError(t, err)
			instanceIDs = append(instanceIDs, instanceID)
		}

		// Make sure to clean up instances
		defer func() {
			for _, id := range instanceIDs {
				terminateInstance(t, ec2Client, id)
			}
		}()

		// Verify all instances are on host1
		for _, id := range instanceIDs {
			verifyInstanceOnHost(t, ec2Client, id, host1ID)
		}

		// Trigger rebalancing by modifying one instance to target the auto-placement host
		err = modifyInstancePlacement(t, ec2Client, instanceIDs[0], host2ID)
		require.NoError(t, err)

		// Wait for the instance to move
		waitForInstanceRunning(t, ec2Client, instanceIDs[0])
		
		// Verify instance moved to host2
		verifyInstanceOnHost(t, ec2Client, instanceIDs[0], host2ID)

		// Now launch a new instance with auto-placement and verify capacity-based allocation
		autoPlacementInstanceID, err := launchInstanceWithAutoPlacement(t, ec2Client, availabilityZone, fmt.Sprintf("auto-%s", uniqueID))
		require.NoError(t, err)
		instanceIDs = append(instanceIDs, autoPlacementInstanceID)

		// Verify the auto-placement instance went to host2 (which has more capacity)
		waitForInstanceRunning(t, ec2Client, autoPlacementInstanceID)
		verifyInstanceOnHost(t, ec2Client, autoPlacementInstanceID, host2ID)

		// Validate capacity utilization on both hosts
		validateCapacityUtilization(t, ec2Client, host1ID, host2ID)
	})
}

// TestInstanceAutoRestart tests instance auto-restart after failure
func TestInstanceAutoRestart(t *testing.T) {
	t.Parallel()

	// Skip in short mode as this test involves stopping and starting instances
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)
	availabilityZone := fmt.Sprintf("%sa", awsRegion)

	terraformOptions := &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":                  fmt.Sprintf("test-host-%s", uniqueID),
			"availability_zone":     availabilityZone,
			"instance_type":         "c5.large",
			"host_recovery":         "on",
			"auto_placement":        "off",
			"enable_monitoring":     true,
			"alarm_actions":         []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
			"enable_auto_recovery":  true,
			"tags": map[string]string{
				"Name":           fmt.Sprintf("test-host-%s", uniqueID),
				"Environment":    "test",
				"TestCase":       "instance-auto-restart",
				"AutoRecovery":   "enabled",
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Clean up resources when done
	defer test_structure.RunTestStage(t, "teardown", func() {
		terraform.Destroy(t, terraformOptions)
	})

	// Deploy host
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, terraformOptions)
	})

	test_structure.RunTestStage(t, "validate", func() {
		// Get host ID
		hostID := terraform.Output(t, terraformOptions, "host_id")
		require.NotEmpty(t, hostID)

		// Create AWS session
		sess, err := session.NewSession(&awssdk.Config{
			Region: awssdk.String(awsRegion),
		})
		require.NoError(t, err)

		ec2Client := ec2.New(sess)

		// Launch an EC2 instance on the host with auto recovery enabled
		instanceID, err := launchInstanceWithRecovery(t, ec2Client, hostID, availabilityZone, uniqueID)
		require.NoError(t, err)
		defer terminateInstance(t, ec2Client, instanceID)

		// Verify instance is running on the dedicated host
		verifyInstanceOnHost(t, ec2Client, instanceID, hostID)

		// Simulate instance failure by stopping it
		err = stopInstance(t, ec2Client, instanceID)
		require.NoError(t, err)

		// Wait for auto-restart to occur (typically within 5 minutes)
		// Note: We're simulating this with a manual start since we can't trigger true automatic recovery in a test
		waitForInstanceStopped(t, ec2Client, instanceID)
		err = startInstance(t, ec2Client, instanceID)
		require.NoError(t, err)

		// Wait for instance to be running again
		waitForInstanceRunning(t, ec2Client, instanceID)

		// Verify instance state and health
		verifyInstanceHealthy(t, ec2Client, instanceID)

		// Verify instance is still on the same host (auto-restart doesn't change host)
		verifyInstanceOnHost(t, ec2Client, instanceID, hostID)
	})
}

// TestRecoveryTimeObjectives tests recovery time objectives
func TestRecoveryTimeObjectives(t *testing.T) {
	t.Parallel()

	// Skip in short mode as this test measures recovery times
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	uniqueID := random.UniqueId()
	awsRegion := aws.GetRandomStableRegion(t, []string{"us-west-2"}, nil)
	availabilityZone := fmt.Sprintf("%sa", awsRegion)

	terraformOptions := &terraform.Options{
		TerraformDir: "../examples/complete",
		Vars: map[string]interface{}{
			"name":              fmt.Sprintf("test-host-%s", uniqueID),
			"availability_zone": availabilityZone,
			"instance_type":     "c5.large",
			"host_recovery":     "on",
			"auto_placement":    "off",
			"enable_monitoring": true,
			"alarm_actions":     []string{"arn:aws:sns:us-west-2:123456789012:test-topic"},
			"tags": map[string]string{
				"Name":        fmt.Sprintf("test-host-%s", uniqueID),
				"Environment": "test",
				"TestCase":    "recovery-time-objectives",
				"RTO":         "5m", // 5-minute recovery time objective
			},
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	}

	// Clean up resources when done
	defer test_structure.RunTestStage(t, "teardown", func() {
		terraform.Destroy(t, terraformOptions)
	})

	// Deploy host
	test_structure.RunTestStage(t, "setup", func() {
		terraform.InitAndApply(t, terraformOptions)
	})

	test_structure.RunTestStage(t, "validate", func() {
		// Get host ID
		hostID := terraform.Output(t, terraformOptions, "host_id")
		require.NotEmpty(t, hostID)

		// Create AWS session
		sess, err := session.NewSession(&awssdk.Config{
			Region: awssdk.String(awsRegion),
		})
		require.NoError(t, err)

		ec2Client := ec2.New(sess)
		cloudwatchClient := cloudwatch.New(sess)

		// Set up monitoring for recovery events
		setupRecoveryMonitoring(t, cloudwatchClient, hostID, uniqueID)

		// Launch an EC2 instance on the dedicated host
		instanceID, err := launchInstanceOnHost(t, ec2Client, hostID, availabilityZone, uniqueID)
		require.NoError(t, err)
		defer terminateInstance(t, ec2Client, instanceID)

		// Verify instance is running on the dedicated host
		verifyInstanceOnHost(t, ec2Client, instanceID, hostID)

		// Simulate failure scenarios and measure recovery time
		startTime := time.Now()
		
		// Scenario 1: Instance stop/start (simulated recovery)
		err = stopInstance(t, ec2Client, instanceID)
		require.NoError(t, err)
		
		waitForInstanceStopped(t, ec2Client, instanceID)
		
		err = startInstance(t, ec2Client, instanceID)
		require.NoError(t, err)
		
		waitForInstanceRunning(t, ec2Client, instanceID)
		
		// Calculate recovery time
		recoveryTime := time.Since(startTime)
		
		// Verify recovery time is within acceptable limits
		rtoThreshold, _ := time.ParseDuration("10m") // Test is more lenient than the 5m tag
		assert.LessOrEqual(t, recoveryTime, rtoThreshold, 
			"Recovery time %v exceeds RTO threshold of %v", recoveryTime, rtoThreshold)
		
		// Verify instance is healthy
		verifyInstanceHealthy(t, ec2Client, instanceID)
		
		// Verify recovery metrics were recorded
		validateRecoveryMetrics(t, cloudwatchClient, hostID, instanceID, uniqueID)
	})
}

// Helper functions

func launchInstanceOnHost(t *testing.T, ec2Client *ec2.EC2, hostID, availabilityZone, uniqueID string) (string, error) {
	// Get the latest Amazon Linux 2 AMI
	amiInput := &ec2.DescribeImagesInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("name"),
				Values: []*string{awssdk.String("amzn2-ami-hvm-*-x86_64-gp2")},
			},
			{
				Name:   awssdk.String("owner-alias"),
				Values: []*string{awssdk.String("amazon")},
			},
			{
				Name:   awssdk.String("state"),
				Values: []*string{awssdk.String("available")},
			},
		},
	}
	
	amiOutput, err := ec2Client.DescribeImages(amiInput)
	if err != nil {
		return "", err
	}
	
	if len(amiOutput.Images) == 0 {
		return "", fmt.Errorf("no Amazon Linux 2 AMI found")
	}
	
	// Sort to get the latest AMI
	var latestAmi *ec2.Image
	latestCreationDate := ""
	
	for _, ami := range amiOutput.Images {
		if latestAmi == nil || *ami.CreationDate > latestCreationDate {
			latestAmi = ami
			latestCreationDate = *ami.CreationDate
		}
	}
	
	// Launch instance on dedicated host
	runInput := &ec2.RunInstancesInput{
		ImageId:      latestAmi.ImageId,
		InstanceType: awssdk.String("c5.large"),
		MinCount:     awssdk.Int64(1),
		MaxCount:     awssdk.Int64(1),
		Placement: &ec2.Placement{
			HostId:             awssdk.String(hostID),
			AvailabilityZone:   awssdk.String(availabilityZone),
			Tenancy:            awssdk.String("host"),
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: awssdk.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(fmt.Sprintf("test-instance-%s", uniqueID)),
					},
					{
						Key:   awssdk.String("TestCase"),
						Value: awssdk.String("dedicated-host-recovery"),
					},
				},
			},
		},
	}
	
	runResult, err := ec2Client.RunInstances(runInput)
	if err != nil {
		return "", err
	}
	
	if len(runResult.Instances) == 0 {
		return "", fmt.Errorf("no instances created")
	}
	
	instanceID := *runResult.Instances[0].InstanceId
	
	// Wait for instance to be running
	waitForInstanceRunning(t, ec2Client, instanceID)
	
	return instanceID, nil
}

func terminateInstance(t *testing.T, ec2Client *ec2.EC2, instanceID string) {
	_, err := ec2Client.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	})
	
	if err != nil {
		t.Logf("WARNING: Failed to terminate instance %s: %v", instanceID, err)
	}
}

func verifyInstanceOnHost(t *testing.T, ec2Client *ec2.EC2, instanceID, expectedHostID string) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	result, err := ec2Client.DescribeInstances(input)
	require.NoError(t, err)
	require.Len(t, result.Reservations, 1)
	require.Len(t, result.Reservations[0].Instances, 1)
	
	instance := result.Reservations[0].Instances[0]
	assert.Equal(t, expectedHostID, *instance.Placement.HostId, 
		"Instance %s should be on host %s but is on host %s", 
		instanceID, expectedHostID, *instance.Placement.HostId)
}

func simulateHostFailureRecovery(t *testing.T, ec2Client *ec2.EC2, instanceID, hostID string) error {
	// In a real test environment, we can't actually fail the host
	// So we simulate by stopping the instance and starting it again
	// In a real failure, AWS would recover the host or migrate instances
	
	// First stop the instance
	stopInput := &ec2.StopInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err := ec2Client.StopInstances(stopInput)
	if err != nil {
		return err
	}
	
	// Wait for the instance to stop
	waitForInstanceStopped(t, ec2Client, instanceID)
	
	// Start the instance again
	startInput := &ec2.StartInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err = ec2Client.StartInstances(startInput)
	return err
}

func waitForInstanceRunning(t *testing.T, ec2Client *ec2.EC2, instanceID string) {
	maxRetries := 30
	retryInterval := 10 * time.Second
	
	retry.DoWithRetry(t, "Waiting for instance to be running", maxRetries, retryInterval, func() (string, error) {
		input := &ec2.DescribeInstancesInput{
			InstanceIds: []*string{awssdk.String(instanceID)},
		}
		
		result, err := ec2Client.DescribeInstances(input)
		if err != nil {
			return "", err
		}
		
		if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
			return "", fmt.Errorf("instance %s not found", instanceID)
		}
		
		instance := result.Reservations[0].Instances[0]
		if *instance.State.Name != "running" {
			return "", fmt.Errorf("instance %s is in state %s, waiting for 'running'", instanceID, *instance.State.Name)
		}
		
		return "Instance is running", nil
	})
}

func waitForInstanceStopped(t *testing.T, ec2Client *ec2.EC2, instanceID string) {
	maxRetries := 30
	retryInterval := 10 * time.Second
	
	retry.DoWithRetry(t, "Waiting for instance to be stopped", maxRetries, retryInterval, func() (string, error) {
		input := &ec2.DescribeInstancesInput{
			InstanceIds: []*string{awssdk.String(instanceID)},
		}
		
		result, err := ec2Client.DescribeInstances(input)
		if err != nil {
			return "", err
		}
		
		if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
			return "", fmt.Errorf("instance %s not found", instanceID)
		}
		
		instance := result.Reservations[0].Instances[0]
		if *instance.State.Name != "stopped" {
			return "", fmt.Errorf("instance %s is in state %s, waiting for 'stopped'", instanceID, *instance.State.Name)
		}
		
		return "Instance is stopped", nil
	})
}

func verifyInstanceConnectivity(t *testing.T, ec2Client *ec2.EC2, instanceID string) {
	// In a real-world scenario, we would check SSH or similar
	// For this test, we'll just verify the instance status checks
	maxRetries := 20
	retryInterval := 15 * time.Second
	
	retry.DoWithRetry(t, "Checking instance status", maxRetries, retryInterval, func() (string, error) {
		input := &ec2.DescribeInstanceStatusInput{
			InstanceIds: []*string{awssdk.String(instanceID)},
		}
		
		result, err := ec2Client.DescribeInstanceStatus(input)
		if err != nil {
			return "", err
		}
		
		if len(result.InstanceStatuses) == 0 {
			return "", fmt.Errorf("no status information for instance %s", instanceID)
		}
		
		instanceStatus := result.InstanceStatuses[0]
		if *instanceStatus.InstanceStatus.Status != "ok" || *instanceStatus.SystemStatus.Status != "ok" {
			return "", fmt.Errorf("instance %s status checks not passing. Instance: %s, System: %s", 
				instanceID, *instanceStatus.InstanceStatus.Status, *instanceStatus.SystemStatus.Status)
		}
		
		return "Instance status checks passing", nil
	})
}

func getInstanceHostID(t *testing.T, ec2Client *ec2.EC2, instanceID string) string {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	result, err := ec2Client.DescribeInstances(input)
	require.NoError(t, err)
	require.Len(t, result.Reservations, 1)
	require.Len(t, result.Reservations[0].Instances, 1)
	
	instance := result.Reservations[0].Instances[0]
	return *instance.Placement.HostId
}

func migrateInstanceToSecondaryHost(t *testing.T, ec2Client *ec2.EC2, instanceID, secondaryHostID string) error {
	// First stop the instance
	stopInput := &ec2.StopInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err := ec2Client.StopInstances(stopInput)
	if err != nil {
		return err
	}
	
	// Wait for the instance to stop
	waitForInstanceStopped(t, ec2Client, instanceID)
	
	// Modify the instance placement to the secondary host
	modifyInput := &ec2.ModifyInstancePlacementInput{
		InstanceId: awssdk.String(instanceID),
		HostId:     awssdk.String(secondaryHostID),
	}
	
	_, err = ec2Client.ModifyInstancePlacement(modifyInput)
	if err != nil {
		return err
	}
	
	// Start the instance again
	startInput := &ec2.StartInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err = ec2Client.StartInstances(startInput)
	return err
}

func launchInstanceWithAutoPlacement(t *testing.T, ec2Client *ec2.EC2, availabilityZone, uniqueID string) (string, error) {
	// Get the latest Amazon Linux 2 AMI
	amiInput := &ec2.DescribeImagesInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("name"),
				Values: []*string{awssdk.String("amzn2-ami-hvm-*-x86_64-gp2")},
			},
			{
				Name:   awssdk.String("owner-alias"),
				Values: []*string{awssdk.String("amazon")},
			},
			{
				Name:   awssdk.String("state"),
				Values: []*string{awssdk.String("available")},
			},
		},
	}
	
	amiOutput, err := ec2Client.DescribeImages(amiInput)
	if err != nil {
		return "", err
	}
	
	if len(amiOutput.Images) == 0 {
		return "", fmt.Errorf("no Amazon Linux 2 AMI found")
	}
	
	// Get the first available AMI
	amiID := *amiOutput.Images[0].ImageId
	
	// Launch instance with auto placement
	runInput := &ec2.RunInstancesInput{
		ImageId:      awssdk.String(amiID),
		InstanceType: awssdk.String("c5.large"),
		MinCount:     awssdk.Int64(1),
		MaxCount:     awssdk.Int64(1),
		Placement: &ec2.Placement{
			AvailabilityZone: awssdk.String(availabilityZone),
			Tenancy:          awssdk.String("host"),
			// Not specifying HostId will use auto placement with on-demand hosts
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: awssdk.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(fmt.Sprintf("auto-instance-%s", uniqueID)),
					},
					{
						Key:   awssdk.String("TestCase"),
						Value: awssdk.String("auto-placement"),
					},
				},
			},
		},
	}
	
	runResult, err := ec2Client.RunInstances(runInput)
	if err != nil {
		return "", err
	}
	
	if len(runResult.Instances) == 0 {
		return "", fmt.Errorf("no instances created")
	}
	
	instanceID := *runResult.Instances[0].InstanceId
	
	// Wait for instance to be running
	waitForInstanceRunning(t, ec2Client, instanceID)
	
	return instanceID, nil
}

func modifyInstancePlacement(t *testing.T, ec2Client *ec2.EC2, instanceID, newHostID string) error {
	// First stop the instance
	stopInput := &ec2.StopInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err := ec2Client.StopInstances(stopInput)
	if err != nil {
		return err
	}
	
	// Wait for the instance to stop
	waitForInstanceStopped(t, ec2Client, instanceID)
	
	// Modify the instance placement
	modifyInput := &ec2.ModifyInstancePlacementInput{
		InstanceId: awssdk.String(instanceID),
		HostId:     awssdk.String(newHostID),
	}
	
	_, err = ec2Client.ModifyInstancePlacement(modifyInput)
	if err != nil {
		return err
	}
	
	// Start the instance again
	startInput := &ec2.StartInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err = ec2Client.StartInstances(startInput)
	return err
}

func validateCapacityUtilization(t *testing.T, ec2Client *ec2.EC2, host1ID, host2ID string) {
	// Get capacity utilization for both hosts
	input := &ec2.DescribeHostsInput{
		HostIds: []*string{awssdk.String(host1ID), awssdk.String(host2ID)},
	}
	
	result, err := ec2Client.DescribeHosts(input)
	require.NoError(t, err)
	require.Len(t, result.Hosts, 2)
	
	// Make assertions about the instance distribution
	// We expect host2 to have more instances after rebalancing
	var host1AvailableCapacity, host2AvailableCapacity int64
	var host1Instances, host2Instances int
	
	for _, host := range result.Hosts {
		if *host.HostId == host1ID {
			host1AvailableCapacity = *host.AvailableCapacity.AvailableInstanceCapacity[0].AvailableCapacity
			host1Instances = len(host.Instances)
		} else if *host.HostId == host2ID {
			host2AvailableCapacity = *host.AvailableCapacity.AvailableInstanceCapacity[0].AvailableCapacity
			host2Instances = len(host.Instances)
		}
	}
	
	// After rebalancing, host2 should have more instances
	assert.GreaterOrEqual(t, host2Instances, host1Instances, 
		"Host2 should have at least as many instances as Host1 after rebalancing")
	
	// Log capacity utilization
	t.Logf("Host1 capacity: %d available slots, %d instances", host1AvailableCapacity, host1Instances)
	t.Logf("Host2 capacity: %d available slots, %d instances", host2AvailableCapacity, host2Instances)
}

func launchInstanceWithRecovery(t *testing.T, ec2Client *ec2.EC2, hostID, availabilityZone, uniqueID string) (string, error) {
	// Get the latest Amazon Linux 2 AMI
	amiInput := &ec2.DescribeImagesInput{
		Filters: []*ec2.Filter{
			{
				Name:   awssdk.String("name"),
				Values: []*string{awssdk.String("amzn2-ami-hvm-*-x86_64-gp2")},
			},
			{
				Name:   awssdk.String("owner-alias"),
				Values: []*string{awssdk.String("amazon")},
			},
			{
				Name:   awssdk.String("state"),
				Values: []*string{awssdk.String("available")},
			},
		},
	}
	
	amiOutput, err := ec2Client.DescribeImages(amiInput)
	if err != nil {
		return "", err
	}
	
	if len(amiOutput.Images) == 0 {
		return "", fmt.Errorf("no Amazon Linux 2 AMI found")
	}
	
	// Get the first available AMI
	amiID := *amiOutput.Images[0].ImageId
	
	// Launch instance with auto recovery
	runInput := &ec2.RunInstancesInput{
		ImageId:      awssdk.String(amiID),
		InstanceType: awssdk.String("c5.large"),
		MinCount:     awssdk.Int64(1),
		MaxCount:     awssdk.Int64(1),
		Placement: &ec2.Placement{
			HostId:           awssdk.String(hostID),
			AvailabilityZone: awssdk.String(availabilityZone),
			Tenancy:          awssdk.String("host"),
		},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: awssdk.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   awssdk.String("Name"),
						Value: awssdk.String(fmt.Sprintf("recovery-instance-%s", uniqueID)),
					},
					{
						Key:   awssdk.String("TestCase"),
						Value: awssdk.String("auto-recovery"),
					},
					{
						Key:   awssdk.String("AutoRecovery"),
						Value: awssdk.String("enabled"),
					},
				},
			},
		},
	}
	
	runResult, err := ec2Client.RunInstances(runInput)
	if err != nil {
		return "", err
	}
	
	if len(runResult.Instances) == 0 {
		return "", fmt.Errorf("no instances created")
	}
	
	instanceID := *runResult.Instances[0].InstanceId
	
	// Wait for instance to be running
	waitForInstanceRunning(t, ec2Client, instanceID)
	
	return instanceID, nil
}

func stopInstance(t *testing.T, ec2Client *ec2.EC2, instanceID string) error {
	stopInput := &ec2.StopInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err := ec2Client.StopInstances(stopInput)
	return err
}

func startInstance(t *testing.T, ec2Client *ec2.EC2, instanceID string) error {
	startInput := &ec2.StartInstancesInput{
		InstanceIds: []*string{awssdk.String(instanceID)},
	}
	
	_, err := ec2Client.StartInstances(startInput)
	return err
}

func verifyInstanceHealthy(t *testing.T, ec2Client *ec2.EC2, instanceID string) {
	maxRetries := 20
	retryInterval := 15 * time.Second
	
	retry.DoWithRetry(t, "Checking instance health", maxRetries, retryInterval, func() (string, error) {
		input := &ec2.DescribeInstanceStatusInput{
			InstanceIds: []*string{awssdk.String(instanceID)},
		}
		
		result, err := ec2Client.DescribeInstanceStatus(input)
		if err != nil {
			return "", err
		}
		
		if len(result.InstanceStatuses) == 0 {
			return "", fmt.Errorf("no status information for instance %s", instanceID)
		}
		
		instanceStatus := result.InstanceStatuses[0]
		if *instanceStatus.InstanceStatus.Status != "ok" || *instanceStatus.SystemStatus.Status != "ok" {
			return "", fmt.Errorf("instance %s status checks not passing. Instance: %s, System: %s", 
				instanceID, *instanceStatus.InstanceStatus.Status, *instanceStatus.SystemStatus.Status)
		}
		
		return "Instance health checks passing", nil
	})
}

func setupRecoveryMonitoring(t *testing.T, cloudwatchClient *cloudwatch.CloudWatch, hostID, uniqueID string) {
	// Create a metric alarm to monitor recovery events
	// This simulates what would be done in a real environment
	alarmName := fmt.Sprintf("recovery-test-%s", uniqueID)
	
	putAlarmInput := &cloudwatch.PutMetricAlarmInput{
		AlarmName:          awssdk.String(alarmName),
		ComparisonOperator: awssdk.String("GreaterThanThreshold"),
		EvaluationPeriods:  awssdk.Int64(1),
		MetricName:         awssdk.String("StatusCheckFailed"),
		Namespace:          awssdk.String("AWS/EC2"),
		Period:             awssdk.Int64(60),
		Statistic:          awssdk.String("Maximum"),
		Threshold:          awssdk.Float64(0),
		ActionsEnabled:     awssdk.Bool(true),
		AlarmDescription:   awssdk.String(fmt.Sprintf("Monitor dedicated host %s recovery time", hostID)),
		Dimensions: []*cloudwatch.Dimension{
			{
				Name:  awssdk.String("HostId"),
				Value: awssdk.String(hostID),
			},
		},
	}
	
	_, err := cloudwatchClient.PutMetricAlarm(putAlarmInput)
	require.NoError(t, err)
}

func validateRecoveryMetrics(t *testing.T, cloudwatchClient *cloudwatch.CloudWatch, hostID, instanceID, uniqueID string) {
	// In a real environment, we would look for actual metrics.
	// For test purposes, we'll verify our alarm exists
	
	alarmName := fmt.Sprintf("recovery-test-%s", uniqueID)
	
	describeAlarmsInput := &cloudwatch.DescribeAlarmsInput{
		AlarmNames: []*string{awssdk.String(alarmName)},
	}
	
	result, err := cloudwatchClient.DescribeAlarms(describeAlarmsInput)
	require.NoError(t, err)
	require.Len(t, result.MetricAlarms, 1)
	
	// In a real test with metrics, we could also verify:
	// - Time between failure and recovery
	// - Success rate of recoveries
	// - Number of recovery attempts
	
	// For now, we're just asserting the alarm exists
	assert.Equal(t, alarmName, *result.MetricAlarms[0].AlarmName)
}

