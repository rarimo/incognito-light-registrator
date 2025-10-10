/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type RegisterId struct {
	Key
	Attributes RegisterIdAttributes `json:"attributes"`
}
type RegisterIdResponse struct {
	Data     RegisterId `json:"data"`
	Included Included   `json:"included"`
}

type RegisterIdListResponse struct {
	Data     []RegisterId `json:"data"`
	Included Included     `json:"included"`
	Links    *Links       `json:"links"`
}

// MustRegisterId - returns RegisterId from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustRegisterId(key Key) *RegisterId {
	var registerID RegisterId
	if c.tryFindEntry(key, &registerID) {
		return &registerID
	}
	return nil
}
