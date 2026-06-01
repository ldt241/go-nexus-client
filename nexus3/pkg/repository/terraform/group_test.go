package terraform

import (
	"math/rand"
	"strconv"
	"testing"

	"github.com/datadrivers/go-nexus-client/nexus3/pkg/tools"
	"github.com/datadrivers/go-nexus-client/nexus3/schema/repository"
	"github.com/stretchr/testify/assert"
)

// getTestTerraformGroupRepository returns a Terraform group repository configuration
// that is suitable for Create/Get/Update/Delete integration tests.
func getTestTerraformGroupRepository(name string) repository.TerraformGroupRepository {
	return repository.TerraformGroupRepository{
		Name:   name,
		Online: true,

		Group: repository.Group{
			MemberNames: []string{},
		},
		Storage: repository.Storage{
			BlobStoreName:               "default",
			StrictContentTypeValidation: true,
		},
		Terraform: repository.TerraformAttributes{
			RequireAuthentication: false,
		},
	}
}

func TestTerraformGroupRepository(t *testing.T) {
	if tools.GetEnv("SKIP_PRO_TESTS", "false") == "true" {
		t.Skip("Skipping Nexus Pro tests")
	}

	service := getTestService()
	repo := getTestTerraformGroupRepository("test-terraform-repo-group-" + strconv.Itoa(rand.Intn(1024)))

	testProxyRepo := getTestTerraformProxyRepository("test-terraform-group-proxy-" + strconv.Itoa(rand.Intn(1024)))
	defer service.Proxy.Delete(testProxyRepo.Name)
	err := service.Proxy.Create(testProxyRepo)
	assert.Nil(t, err)
	repo.Group.MemberNames = append(repo.Group.MemberNames, testProxyRepo.Name)

	err = service.Group.Create(repo)
	assert.Nil(t, err)
	generatedRepo, err := service.Group.Get(repo.Name)
	assert.Nil(t, err)
	assert.Equal(t, repo.Online, generatedRepo.Online)
	assert.Equal(t, repo.Group, generatedRepo.Group)
	assert.Equal(t, repo.Storage, generatedRepo.Storage)
	assert.Equal(t, repo.Terraform, generatedRepo.Terraform)

	updatedRepo := repo
	updatedRepo.Online = false

	err = service.Group.Update(repo.Name, updatedRepo)
	assert.Nil(t, err)
	generatedRepo, err = service.Group.Get(updatedRepo.Name)
	assert.Nil(t, err)
	assert.Equal(t, updatedRepo.Online, generatedRepo.Online)

	err = service.Group.Delete(repo.Name)
	assert.Nil(t, err)
}
