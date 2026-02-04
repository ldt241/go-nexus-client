package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/datadrivers/go-nexus-client/nexus3/pkg/client"
	pkgtools "github.com/datadrivers/go-nexus-client/nexus3/pkg/tools"
	schemasecurity "github.com/datadrivers/go-nexus-client/nexus3/schema/security"
)

const (
    securityPrivilegesAPIEndpoint = securityAPIEndpoint + "/privileges"
)

// Service dùng API cũ (deprecated)
type DeprecatedPrivilegeService client.Service

func NewDeprecatedPrivilegeService(c *client.Client) *DeprecatedPrivilegeService {
    return &DeprecatedPrivilegeService{
        Client: c,
    }
}

func (s *DeprecatedPrivilegeService) List() ([]schemasecurity.Privilege, error) {
    body, resp, err := s.Client.Get(securityPrivilegesAPIEndpoint, nil)
    if err != nil {
        return nil, err
    }

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("could not read privileges: HTTP: %d, %s", resp.StatusCode, string(body))
    }

    var privileges []schemasecurity.Privilege
    if err := json.Unmarshal(body, &privileges); err != nil {
        return nil, fmt.Errorf("could not unmarshal privileges: %v", err)
    }

    return privileges, nil
}

func (s *DeprecatedPrivilegeService) Create(p schemasecurity.Privilege) error {
    ioReader, err := pkgtools.JsonMarshalInterfaceToIOReader(p)
    if err != nil {
        return err
    }

    body, resp, err := s.Client.Post(
        fmt.Sprintf("%s/%s", securityPrivilegesAPIEndpoint, strings.ToLower(p.Type)),
        ioReader,
    )
    if err != nil {
        return err
    }

    if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated {
        return fmt.Errorf(
            "could not create privilege %q: HTTP: %d, %s",
            p.Name, resp.StatusCode, string(body),
        )
    }

    return nil
}

func (s *DeprecatedPrivilegeService) Get(name string) (*schemasecurity.Privilege, error) {
    privileges, err := s.List()
    if err != nil {
        return nil, err
    }

    for _, p := range privileges {
        if p.Name == name {
            return &p, nil
        }
    }

    return nil, nil
}

func (s *DeprecatedPrivilegeService) Update(name string, p schemasecurity.Privilege) error {
    ioReader, err := pkgtools.JsonMarshalInterfaceToIOReader(p)
    if err != nil {
        return err
    }

    body, resp, err := s.Client.Put(
        fmt.Sprintf("%s/%s/%s", securityPrivilegesAPIEndpoint, p.Type, name),
        ioReader,
    )
    if err != nil {
        return err
    }

    if resp.StatusCode != http.StatusNoContent {
        return fmt.Errorf(
            "could not update privilege %q: HTTP %d, %s",
            name, resp.StatusCode, string(body),
        )
    }

    return nil
}

func (s *DeprecatedPrivilegeService) Delete(name string) error {
    body, resp, err := s.Client.Delete(fmt.Sprintf("%s/%s", securityPrivilegesAPIEndpoint, name))
    if err != nil {
        return err
    }

    if resp.StatusCode != http.StatusNoContent {
        return fmt.Errorf(
            "could not delete privilege %q: HTTP: %d, %s",
            name, resp.StatusCode, string(body),
        )
    }
    return nil
}
