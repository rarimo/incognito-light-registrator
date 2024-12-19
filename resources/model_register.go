/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type Register struct {
	Key
	Attributes RegisterAttributes `json:"attributes"`
}
type RegisterResponse struct {
	Data     Register `json:"data"`
	Included Included `json:"included"`
}

type RegisterListResponse struct {
	Data     []Register `json:"data"`
	Included Included   `json:"included"`
	Links    *Links     `json:"links"`
}

// MustRegister - returns Register from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustRegister(key Key) *Register {
	var register Register
	if c.tryFindEntry(key, &register) {
		return &register
	}
	return nil
}
