package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/datadrivers/go-nexus-client/nexus3/pkg/client"
	"github.com/datadrivers/go-nexus-client/nexus3/pkg/tools"
)

type RepositoryService[R any] struct {
	endpoint string
	client   *client.Client
}

var (
	repositoryCreateReadTimeout       = 30 * time.Second
	repositoryCreateReadRetryInterval = time.Second
)

func NewRepositoryService[R any](ep string, c *client.Client) *RepositoryService[R] {
	return &RepositoryService[R]{
		endpoint: ep,
		client:   c,
	}
}

func (s *RepositoryService[R]) Create(repo R) error {
	data, err := tools.JsonMarshalInterfaceToIOReader(repo)
	if err != nil {
		return err
	}
	body, resp, err := s.client.Post(s.endpoint, data)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("could not create repository %v: HTTP: %d, %s", repo, resp.StatusCode, string(body))
	}

	if repositoryName, ok := getRepositoryName(repo); ok {
		if err := s.waitForRepository(repositoryName); err != nil {
			return fmt.Errorf("could not create repository %q: repository was not readable after create response HTTP: %d, %s: %w", repositoryName, resp.StatusCode, string(body), err)
		}
	}

	return nil
}

func getRepositoryName[R any](repo R) (string, bool) {
	value := reflect.ValueOf(repo)
	if !value.IsValid() {
		return "", false
	}

	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return "", false
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return "", false
	}

	name := value.FieldByName("Name")
	if !name.IsValid() {
		return "", false
	}

	if name.Kind() == reflect.String {
		return name.String(), name.String() != ""
	}

	if name.Kind() == reflect.Pointer && !name.IsNil() && name.Elem().Kind() == reflect.String {
		return name.Elem().String(), name.Elem().String() != ""
	}

	return "", false
}

func (s *RepositoryService[R]) waitForRepository(id string) error {
	deadline := time.Now().Add(repositoryCreateReadTimeout)
	for {
		body, resp, err := s.client.Get(fmt.Sprintf("%s/%s", s.endpoint, id), nil)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		readErr := fmt.Errorf("could not read repository '%s': HTTP: %d, %s", id, resp.StatusCode, string(body))
		if resp.StatusCode != http.StatusNotFound || time.Now().After(deadline) {
			return readErr
		}

		time.Sleep(repositoryCreateReadRetryInterval)
	}
}

func (s *RepositoryService[R]) Get(id string) (*R, error) {
	repo := new(R)
	body, resp, err := s.client.Get(fmt.Sprintf("%s/%s", s.endpoint, id), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not read repository '%s': HTTP: %d, %s", id, resp.StatusCode, string(body))
	}
	if err = json.Unmarshal(body, repo); err != nil {
		return nil, fmt.Errorf("could not unmarshal repository: %v", err)
	}
	return repo, nil
}

func (s *RepositoryService[R]) Update(id string, repo R) error {
	data, err := tools.JsonMarshalInterfaceToIOReader(repo)
	if err != nil {
		return err
	}
	body, resp, err := s.client.Put(fmt.Sprintf("%s/%s", s.endpoint, id), data)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("could not update repository '%s': HTTP: %d, %s", id, resp.StatusCode, string(body))
	}
	return nil
}

func (s *RepositoryService[R]) Delete(id string) error {
	return DeleteRepository(s.client, id)
}
