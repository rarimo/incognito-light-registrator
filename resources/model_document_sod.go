/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type DocumentSod struct {
	Key
	Attributes DocumentSodAttributes `json:"attributes"`
}
type DocumentSodResponse struct {
	Data     DocumentSod `json:"data"`
	Included Included    `json:"included"`
}

type DocumentSodListResponse struct {
	Data     []DocumentSod `json:"data"`
	Included Included      `json:"included"`
	Links    *Links        `json:"links"`
}

// MustDocumentSod - returns DocumentSod from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustDocumentSod(key Key) *DocumentSod {
	var documentSod DocumentSod
	if c.tryFindEntry(key, &documentSod) {
		return &documentSod
	}
	return nil
}
