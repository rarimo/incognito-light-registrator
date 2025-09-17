/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type RegisterCert struct {
	Key
	Attributes RegisterCertAttributes `json:"attributes"`
}
type RegisterCertRequest struct {
	Data     RegisterCert `json:"data"`
	Included Included     `json:"included"`
}

type RegisterCertListRequest struct {
	Data     []RegisterCert `json:"data"`
	Included Included       `json:"included"`
	Links    *Links         `json:"links"`
}

// MustRegisterCert - returns RegisterCert from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustRegisterCert(key Key) *RegisterCert {
	var registerCert RegisterCert
	if c.tryFindEntry(key, &registerCert) {
		return &registerCert
	}
	return nil
}
