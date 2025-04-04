package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	consolemodel "github.com/sven-victor/ez-console/pkg/model"
	consoleservice "github.com/sven-victor/ez-console/pkg/service"
	"github.com/sven-victor/ez-console/server"
	"github.com/sven-victor/ez-utils/log"
)

func init() {
	consoleservice.RegisterDefaultSettings(context.Background(), consolemodel.SettingSystemHomePage, "/ui/", "System home page")
	consoleservice.RegisterDefaultSettings(context.Background(), consolemodel.SettingSystemName, "EZ-Auth", "System name")
}

type BaseService struct {
	server.Service
}

// RecursiveCreateOrganizationalUnitEntry recursively creates an organizationalUnit entry in LDAP
func (s *BaseService) RecursiveCreateOrganizationalUnitEntry(ctx context.Context, dn string) error {
	logger := log.GetContextLogger(ctx)
	ldapClient, err := s.GetLDAPSession(ctx)
	if err != nil {
		return err
	}
	defer ldapClient.Close()
	// check entry exists
	level.Debug(logger).Log("msg", "Checking entry exists", "dn", dn)
	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	)
	result, err := ldapClient.Search(searchRequest)
	if (err != nil && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject)) || (err == nil && len(result.Entries) == 0) {
		level.Debug(logger).Log("msg", "Entry not found", "dn", dn)
		// check parent entry exists
		attr, parentDN, found := strings.Cut(dn, ",")
		if found {
			err = s.RecursiveCreateOrganizationalUnitEntry(ctx, parentDN)
			if err != nil {
				return err
			}
		}
		// create entry
		level.Debug(logger).Log("msg", "Creating entry", "dn", dn)
		req := ldap.NewAddRequest(dn, nil)
		req.Attributes = []ldap.Attribute{
			{Type: "objectClass", Vals: []string{"top", "organizationalUnit"}},
		}
		for _, attr := range strings.Split(attr, "+") {
			attrName, attrValue, found := strings.Cut(attr, "=")
			if !found {
				return fmt.Errorf("invalid ldap attribute: %s", attr)
			}
			req.Attributes = append(req.Attributes, ldap.Attribute{
				Type: attrName,
				Vals: []string{attrValue},
			})
		}

		err = ldapClient.Add(req)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}
