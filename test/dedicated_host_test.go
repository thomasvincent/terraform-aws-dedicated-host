package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestDedicatedHostComplete(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		NoColor:      true,
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	// Verify outputs
	dedicatedHostId := terraform.Output(t, terraformOptions, "dedicated_host_id")
	dedicatedHostArn := terraform.Output(t, terraformOptions, "dedicated_host_arn")
	availabilityZone := terraform.Output(t, terraformOptions, "availability_zone")

	assert.NotEmpty(t, dedicatedHostId, "Dedicated Host ID should not be empty")
	assert.NotEmpty(t, dedicatedHostArn, "Dedicated Host ARN should not be empty")
	assert.Equal(t, "us-west-2a", availabilityZone, "Availability Zone should match the input")
}