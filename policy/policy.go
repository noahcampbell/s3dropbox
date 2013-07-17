package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Condition interface {
	Matches(key, value string) bool
	Name() string
}

/*
Support for condition "eq".

http://docs.aws.amazon.com/AmazonS3/latest/dev/HTTPPOSTForms.html#ConditionMatching
*/
type ConditionEq struct {
	Key   string
	Value string
}

func (c ConditionEq) MarshalJSON() (b []byte, ok error) {
	writer := bytes.NewBuffer(b)
	_, ok = writer.WriteString(`{"`)
	_, ok = writer.WriteString(c.Key)
	_, ok = writer.WriteString(`": "`)
	_, ok = writer.WriteString(c.Value)
	_, ok = writer.WriteString(`"}`)
	return writer.Bytes(), nil
}

func (c ConditionEq) Matches(key, value string) bool {
	return c.Key == key && c.Value == value
}

func (c ConditionEq) Name() string {
	return c.Key
}

/*
Support for condition starts-with.

http://docs.aws.amazon.com/AmazonS3/latest/dev/HTTPPOSTForms.html#ConditionMatching
*/
type ConditionStartsWith struct {
	Key   string
	Value string
}

func (c ConditionStartsWith) MarshalJSON() (b []byte, ok error) {
	writer := bytes.NewBuffer(b)
	_, ok = writer.WriteString(`["starts-with", "`)
	_, ok = writer.WriteString(c.Key)
	_, ok = writer.WriteString(`", "`)
	_, ok = writer.WriteString(c.Value)
	_, ok = writer.WriteString(`"]`)
	return writer.Bytes(), nil
}

func (c ConditionStartsWith) Matches(key, value string) bool {
	return c.Key == key && c.Value == value
}

func (c ConditionStartsWith) Name() string {
	return c.Key
}

/*
Support for condition range elements.

http://docs.aws.amazon.com/AmazonS3/latest/dev/HTTPPOSTForms.html#ConditionMatching
*/
type ConditionRange struct {
	key      string
	min, max float64
}

func (c ConditionRange) Matches(key, value string) bool {
	return c.key == key
}

func (c ConditionRange) Name() string {
	return c.key
}

/*
Policy contains the expiration and set of conditions.

See http://docs.aws.amazon.com/AmazonS3/latest/dev/HTTPPOSTForms.html#HTTPPOSTConstructPolicy
*/
type Policy struct {
	Expiration time.Time   `json:"expiration"`
	Conditions []Condition `json:"conditions"`
	raw        []byte      `json:"-"`
}

func (p *Policy) ConditionMatches(key, value string) bool {
	for _, condition := range p.Conditions {
		if condition.Matches(key, value) {
			return true
		}
	}
	return false
}

func (p *Policy) Condition(key string) (condition Condition, ok error) {
	for _, condition := range p.Conditions {
		if condition.Name() == key {
			return condition, nil
		}
	}
	return nil, errors.New("Unable to locate condition")
}

func (p *Policy) UnmarshalJSON(bytes []byte) error {

	var doc struct {
		Expiration *time.Time    `json:"expiration"`
		Conditions []interface{} `json:"conditions"`
	}

	if ok := json.Unmarshal(bytes, &doc); ok != nil {
		fmt.Printf("Error: %+v", ok)
		return ok
	}

	if doc.Expiration == nil {
		return errors.New("Missing expiration element.")
	}

	if doc.Conditions == nil {
		return errors.New("Missing conditions element.")
	}

	p.Expiration = *doc.Expiration

	for _, condition := range doc.Conditions {
		switch condition.(type) {
		case map[string]interface{}:
			m := condition.(map[string]interface{})
			for k, v := range m {
				p.AddConditionEq(k, v.(string))
			}
		case []interface{}:
			l := condition.([]interface{})
			switch l[0].(string) {
			case "starts-with":
				p.AddConditionStartsWith(l[1].(string), l[2].(string))
			case "eq":
				p.AddConditionEq(l[1].(string), l[2].(string))
			default:
				p.AddConditionRange(l[0].(string), l[1].(float64), l[2].(float64))
			}
		default:
			panic("unreachable")
		}
	}
	return p.checkForRequiredFields()
}

func (p *Policy) checkForRequiredFields() error {
	found := []bool{false, false}
	for i, field := range []string{"$key", "bucket"} {
		for _, condition := range p.Conditions {
			if condition.Name() == field {
				found[i] = true
				continue
			}
		}
	}
	if found[0] && found[1] {
		return nil
	}
	return errors.New("Missing required field.")
}

func NewPolicy(expiration time.Time) (policy *Policy, ok error) {
	return &Policy{expiration, make([]Condition, 0, 0), nil}, nil
}

func ParsePolicy(bytes []byte) (policy *Policy, ok error) {
	ok = json.Unmarshal(bytes, &policy)
	if ok != nil {
		return
	}
	policy.raw = bytes
	return
}

func (p *Policy) AddConditionEq(field, value string) {
	p.Conditions = append(p.Conditions, ConditionEq{field, value})
}

func (p *Policy) AddConditionStartsWith(field, value string) {
	p.Conditions = append(p.Conditions, ConditionStartsWith{field, value})
}

func (p *Policy) AddConditionRange(field string, min, max float64) {
	p.Conditions = append(p.Conditions, ConditionRange{field, min, max})
}

/*
Signer provide the ability to create the base64 encoded policy and
the hmac signed by the AWS Credentials.
*/
type Signer struct {
	policy         *Policy
	awsSecretKeyId string
	awsSecretKey   string
}

func NewS3DropboxSigner(AWSSecretKeyId string, AWSSecretKey string) (signer *Signer, ok error) {
	return &Signer{nil, AWSSecretKeyId, AWSSecretKey}, nil
}

/*
Add a policy to be signed.  This will replace any existing policy.
*/
func (signer *Signer) AddPolicy(policy *Policy) (ok error) {
	if policy == nil {
		return errors.New("Missing policy")
	}
	signer.policy = policy
	return nil
}

/*
Sign the policy and generate the base64 encoded policy and the hmac based
on the aws secret key.
*/
func (signer *Signer) Sign() (base64enc, sig []byte, ok error) {
	if signer.policy == nil {
		return nil, nil, errors.New("Missing policy.  Use AddPolicy(...) to add a policy.")
	}
	base64enc = signer.base64encodePolicy()
	sig = signer.hmacPolicy(base64enc)
	return
}

func (signer *Signer) base64encodePolicy() (base64enc []byte) {
	base64enc = make([]byte, base64.StdEncoding.EncodedLen(len(signer.policy.raw)))
	base64.StdEncoding.Encode(base64enc, signer.policy.raw)
	return
}

func (signer *Signer) hmacPolicy(enc []byte) (sig []byte) {
	hasher := hmac.New(sha1.New, []byte(signer.awsSecretKey))
	hasher.Write(enc)
	rawsig := hasher.Sum(nil)
	sig = make([]byte, base64.StdEncoding.EncodedLen(len(rawsig)))
	base64.StdEncoding.Encode(sig, rawsig)
	return
}
