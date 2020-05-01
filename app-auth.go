package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
)

type permissionPathEntry struct {
	PathPat *regexp.Regexp
	IsAuth  bool
}

var permPaths = map[string]*permissionPathEntry{
	"all":             &permissionPathEntry{regexp.MustCompile(".*"), false},
	"userPrefix":      &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/"), false},
	"userAuth":        &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/auth$"), true},
	"userPrivStore":   &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/privStore"), false},
	"userStore":       &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/store"), false},
	"loginAuth":       &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/login/[^/]+/auth$"), true},
	"domainAuth":      &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/auth$"), true},
	"domainPrivStore": &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/privStore"), false},
	"domainStore":     &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/store"), false},
	"domainLoc":       &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/loc"), false},
}

type permissionMapEntry struct {
	PathPat  string
	UserType *userTypeConfig
	CanWrite bool
}

var permissions = []permissionMapEntry{
	permissionMapEntry{"all", rootUserTypeConfig, true},
	permissionMapEntry{"userPrefix", userUserTypeConfig, false},
	permissionMapEntry{"userAuth", userUserTypeConfig, true},
	permissionMapEntry{"userPrivStore", userUserTypeConfig, true},
	permissionMapEntry{"userPrivStore", loginUserTypeConfig, true},
	permissionMapEntry{"userStore", nil, false},
	permissionMapEntry{"userStore", userUserTypeConfig, true},
	permissionMapEntry{"userStore", loginUserTypeConfig, true},
	permissionMapEntry{"loginAuth", loginUserTypeConfig, true},
	permissionMapEntry{"domainAuth", loginUserTypeConfig, true},
	permissionMapEntry{"domainPrivStore", loginUserTypeConfig, true},
	permissionMapEntry{"domainPrivStore", domainUserTypeConfig, true},
	permissionMapEntry{"domainStore", nil, false},
	permissionMapEntry{"domainStore", loginUserTypeConfig, true},
	permissionMapEntry{"domainStore", domainUserTypeConfig, true},
	permissionMapEntry{"domainLoc", nil, false},
	permissionMapEntry{"domainLoc", loginUserTypeConfig, true},
	permissionMapEntry{"domainLoc", domainUserTypeConfig, true},
}

func (app *AthenaStoreApplication) canAccess(forWrite bool, login *loginEntry, path string) (isGranted bool, isAuthPath bool) {
	prefixCache := make(map[string][]string)
	matchPrefix := ""

	for _, perm := range permissions {
		if login.Type != perm.UserType || (forWrite && !perm.CanWrite) {
			// not intended for our user type or it's r/o, so skip
			continue
		}
		permPath := permPaths[perm.PathPat]
		if _, ok := prefixCache[perm.PathPat]; !ok {
			prefixCache[perm.PathPat] = permPath.PathPat.FindStringSubmatch(path)
		}
		matches := prefixCache[perm.PathPat]
		if matches == nil {
			continue
		}
		if len(matches) <= 1 {
			// this pattern matches with no qualifiers, accept it and go
			isGranted = true
			if permPath.IsAuth {
				isAuthPath = true
			}
		}
		if matchPrefix == "" {
			// the permission is asking for a matching user, might as well figure out what ours is
			apexEntry := login
			if apexEntry.Parent != nil {
				apexEntry = apexEntry.Parent
			}
			matchPrefix = apexEntry.path()
		}
		if matches[1] == matchPrefix {
			isGranted = true
			if permPath.IsAuth {
				isAuthPath = true
			}
		}
	}
	return
}

func (app *AthenaStoreApplication) isValid(tx *athenaTx, login *loginEntry) (code uint32, codeDescr string) {
	for key, value := range tx.Msg {
		if login != nil {
			canAccess, _ := app.canAccess(true, login, key)
			if !canAccess {
				return ErrorUnauth, fmt.Sprintf("Not authorized to write to %s", key)
			}
		} else if valueAsMap, ok := value.(map[string]interface{}); ok {
			canAccess := false

			// we need to special-case users creating a new user account, which would appear as a self-signed write to a nonexistent userAuth location
			userAuthPath := permPaths["userAuth"].PathPat.FindStringSubmatch(key)
			if userAuthPath != nil {
				// attempt to decode the value into a login Entry
				reqAcctData := &loginEntry{Type: userUserTypeConfig}
				err := reqAcctData.decodeAccountData(valueAsMap, key)
				if err == nil && reqAcctData.Name != "" && bytes.Equal(reqAcctData.Pubkey, tx.Pkey) {
					// okay this is properly self-signed, if the user doesn't exist then we'll consider this a valid createUser request
					if gAcctData, err := GetBadgerVal(app.currentBatch, key); gAcctData == nil && err == nil {
						canAccess = true
					}
				}
			}
			if !canAccess {
				return ErrorUnknownUser, fmt.Sprintf("Did not recognize key %s", base64.RawURLEncoding.EncodeToString(tx.Pkey))
			}
		}
	}
	return 0, ""
}
