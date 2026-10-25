package domain

import "slices"

// PermissionSet is a set of permissions with O(1) lookups.
type PermissionSet map[Permission]struct{}

func NewPermissionSet(perms ...Permission) PermissionSet {
	s := make(PermissionSet, len(perms))
	for _, p := range perms {
		s[p] = struct{}{}
	}
	return s
}

func (s PermissionSet) Has(p Permission) bool {
	_, ok := s[p]
	return ok
}

func (s PermissionSet) HasAll(perms ...Permission) bool {
	for _, p := range perms {
		if !s.Has(p) {
			return false
		}
	}
	return true
}

// Sorted returns the permissions as a sorted slice.
func (s PermissionSet) Sorted() []Permission {
	out := make([]Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}
