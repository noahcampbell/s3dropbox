package s3dropbox

import (
	"encoding/json"
	"testing"
	"time"
)

func nowPlusOneYear() time.Time {
	now := time.Now()
	return now.AddDate(1, 0, 0)
}

func TestCreatePolicy(t *testing.T) {
	expiration := nowPlusOneYear()
	var policy *Policy
	var ok error
	if policy, ok = NewPolicy(expiration); ok != nil {
		t.Errorf("Default policy should be created")
	}
	if policy.Expiration != expiration {
		t.Errorf("NewPolicy did not correctly set the expiration")
	}
}

func checkUnmarshaledConditionLength(t *testing.T, cond []interface{}, cnt int) {
	if len(cond) != cnt {
		t.Errorf("Eq conditions should consist of %d strings in an array: %s", cnt, cond)
	}
}

func checkConditionEq(t *testing.T, cond map[string]interface{}, key, value string) {
	if cond[key] != value {
		t.Errorf("key and value not set correctly.")
	}
}

func checkConditionStartWith(t *testing.T, cond []interface{}, key, value string) {
	checkUnmarshaledConditionLength(t, cond, 3)
	if cond[0] != "starts-with" || cond[1] != key || cond[2] != value {
		t.Errorf("starts-with key and value not set correctly.  Expected %s=%s.  Got: %s=%s", key, value, cond[1], cond[2])
	}
}

func convertToRawInterface(t *testing.T, policy *Policy) map[string]interface{} {
	b, ok := json.Marshal(policy)
	if ok != nil {
		t.Errorf("Unable to marshal a policy json object. %s", ok)
	}
	var raw interface{}
	ok = json.Unmarshal(b, &raw)
	if ok != nil {
		t.Errorf("Unable to unmarshal previous json.")
	}
	return raw.(map[string]interface{})
}

func checkConditionCount(t *testing.T, p *Policy, cnt int) {
	if len(p.Conditions) != cnt {
		t.Errorf("Condition not added to Policy's conditions list")
	}
}

func checkUnmarshalPolicyStructure(t *testing.T, results map[string]interface{}) {
	if _, found := results["expiration"]; !found {
		t.Errorf("Unable to locate 'expiration' within policy!")
	}
	if _, found := results["conditions"]; !found {
		t.Errorf("Unable to locate 'conditions' within policy!")
	}
}

func toMap(v interface{}, el int) map[string]interface{} {
	return v.([]interface{})[el].(map[string]interface{})
}

func toArray(v interface{}, el int) []interface{} {
	return v.([]interface{})[el].([]interface{})
}

func TestUnmarshalledPolicyStructure(t *testing.T) {
	policy, _ := NewPolicy(nowPlusOneYear())
	results := convertToRawInterface(t, policy)
	checkUnmarshalPolicyStructure(t, results)
}

func TestAddConditionToPolicy(t *testing.T) {
	policy, _ := NewPolicy(nowPlusOneYear())
	policy.AddConditionEq("acl", "private")
	checkConditionCount(t, policy, 1)
	conditions, _ := convertToRawInterface(t, policy)["conditions"]
	checkConditionEq(t, toMap(conditions, 0), "acl", "private")
}

func TestAddConditionStartsWith(t *testing.T) {
	policy, _ := NewPolicy(nowPlusOneYear())
	policy.AddConditionStartsWith("$key", "/foo/bar")
	conditions, _ := convertToRawInterface(t, policy)["conditions"]
	checkConditionStartWith(t, toArray(conditions, 0), "$key", "/foo/bar")
}
