/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type VerifySod struct {
	Key
	Attributes VerifySodAttributes `json:"attributes"`
}
type VerifySodResponse struct {
	Data     VerifySod `json:"data"`
	Included Included  `json:"included"`
}

type VerifySodListResponse struct {
	Data     []VerifySod `json:"data"`
	Included Included    `json:"included"`
	Links    *Links      `json:"links"`
}

// MustVerifySod - returns VerifySod from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustVerifySod(key Key) *VerifySod {
	var verifySod VerifySod
	if c.tryFindEntry(key, &verifySod) {
		return &verifySod
	}
	return nil
}
