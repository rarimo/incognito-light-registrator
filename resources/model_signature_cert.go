/*
 * GENERATED. Do not modify. Your changes might be overwritten!
 */

package resources

type SignatureCert struct {
	Key
	Attributes SignatureCertAttributes `json:"attributes"`
}
type SignatureCertResponse struct {
	Data     SignatureCert `json:"data"`
	Included Included      `json:"included"`
}

type SignatureCertListResponse struct {
	Data     []SignatureCert `json:"data"`
	Included Included        `json:"included"`
	Links    *Links          `json:"links"`
}

// MustSignatureCert - returns SignatureCert from include collection.
// if entry with specified key does not exist - returns nil
// if entry with specified key exists but type or ID mismatches - panics
func (c *Included) MustSignatureCert(key Key) *SignatureCert {
	var signatureCert SignatureCert
	if c.tryFindEntry(key, &signatureCert) {
		return &signatureCert
	}
	return nil
}
