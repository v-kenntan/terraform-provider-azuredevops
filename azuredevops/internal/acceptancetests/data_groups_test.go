package acceptancetests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/microsoft/terraform-provider-azuredevops/azuredevops/internal/acceptancetests/testutils"
)

// Validates that a configuration containing a project group lookup is able to read the resource correctly.
// Because this is a data source, there are no resources to inspect in AzDO
func TestAccGroupsDataSource_Read_Project(t *testing.T) {
	projectName := testutils.GenerateResourceName()
	tfNode := "data.azuredevops_groups.groups"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:  func() { testutils.PreCheck(t, nil) },
		Providers: testutils.GetProviders(),
		Steps: []resource.TestStep{
			{
				Config: hclGroupsDataSourceBasic(projectName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(tfNode, "project_id"),
					resource.TestCheckResourceAttrSet(tfNode, "groups.#"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_Read_NoProject(t *testing.T) {
	tfNode := "data.azuredevops_groups.groups"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:  func() { testutils.PreCheck(t, nil) },
		Providers: testutils.GetProviders(),
		Steps: []resource.TestStep{
			{
				Config: hclGroupsDataSourceAllGroups(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(tfNode, "groups.#"),
				),
			},
		},
	})
}

func TestAccGroupsDataSource_ProjectID_FiltersOutCollectionGroups(t *testing.T) {
	projectName := testutils.GenerateResourceName()

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutils.PreCheck(t, nil) },
		Providers: testutils.GetProviders(),
		Steps: []resource.TestStep{
			{
				Config: hclGroupsDataProjectScopedConfig(projectName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAllGroupDomainsContainProjectID("data.azuredevops_groups.scoped", "groups", "domain", "azuredevops_project.test"),
				),
			},
		},
	})
}

func hclGroupsDataSourceBasic(projectName string) string {
	return fmt.Sprintf(`
resource "azuredevops_project" "project" {
  name               = "%[1]s"
  description        = "description"
  visibility         = "private"
  version_control    = "Git"
  work_item_template = "Agile"
}

data "azuredevops_groups" "groups" {
  project_id = azuredevops_project.project.id
}
`, projectName)
}

func hclGroupsDataSourceAllGroups() string {
	return `data "azuredevops_groups" "groups" {}`
}

func hclGroupsDataProjectScopedConfig(projectName string) string {
	return fmt.Sprintf(`
resource "azuredevops_project" "test" {
  name = %q
}

data "azuredevops_groups" "scoped" {
  project_id = azuredevops_project.test.id
}
`, projectName)
}

func testAccCheckAllGroupDomainsContainProjectID(groupsAddr, listAttr, domainField, projectResourceAddr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		grs, ok := s.RootModule().Resources[groupsAddr]
		if !ok {
			return fmt.Errorf("not found: %s", groupsAddr)
		}
		prs, ok := s.RootModule().Resources[projectResourceAddr]
		if !ok {
			return fmt.Errorf("not found: %s", projectResourceAddr)
		}
		projectID := prs.Primary.ID

		for k, v := range grs.Primary.Attributes {
			if strings.HasPrefix(k, listAttr+".") && strings.HasSuffix(k, "."+domainField) {
				if !strings.Contains(v, projectID) {
					return fmt.Errorf("expected %s to contain project id %s, got %q", k, projectID, v)
				}
			}
		}
		return nil
	}
}
