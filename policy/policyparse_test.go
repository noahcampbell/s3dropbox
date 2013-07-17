package policy

import (
	"testing"
)

const (
	no_condition_policy               = `{"expiration": "2012-01-01T00:00:00.000Z"}`
	no_expiration_policy              = `{"conditions": []}`
	missing_conditions_bucket_and_key = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [{"foobar": "barfoo"}]}`
	missing_conditions_bucket         = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [{"$key": "barfoo"}]}`
	exact_match                       = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [ {"$key": "barfoo"}, {"bucket": "bucketfoo"}, {"el": "val"}, ["eq", "el2", "val2"] ] }`
	startswith_match                  = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [ {"$key": "barfoo"}, {"bucket": "bucketfoo"}, ["starts-with", "sw", "val"] ] }`
	range_match                       = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [{"$key": "barfoo"}, {"bucket": "bucketfoo"}, ["foobar", 1, 10]]}`
)

func TestDegenerateParsePolicyNil(t *testing.T) {
	if _, ok := ParsePolicy(nil); ok == nil {
		t.Errorf("ParsePolicy(nil) should return an error")
	}
}

func TestDegenerateParsePolicyNoConditions(t *testing.T) {
	if _, ok := ParsePolicy([]byte(no_condition_policy)); ok == nil {
		t.Errorf("Invalid document is missing conditions and did not return an error.")
	}
}

func TestDegenerateParsePolicyNoExpiration(t *testing.T) {
	if _, ok := ParsePolicy([]byte(no_expiration_policy)); ok == nil {
		t.Errorf("Invalid document is missing expiration and did not return an error.")
	}
}

func TestDegenerateParsePolicyMissingBucketAndKey(t *testing.T) {
	if _, ok := ParsePolicy([]byte(missing_conditions_bucket_and_key)); ok == nil {
		t.Errorf("Invalid document is missing key and bucket conditions and did not return an error.")
	}
}

func TestDegenerateParsePolicyMissingBucket(t *testing.T) {
	if _, ok := ParsePolicy([]byte(missing_conditions_bucket)); ok == nil {
		t.Errorf("Invalid document is missing bucket conditions and did not return an error.")
	}
}

func checkConditionStartsWithType(t *testing.T, policy *Policy, key string) {
	if cond, ok := policy.Condition(key); ok == nil {
		if _, ok := cond.(ConditionStartsWith); !ok {
			t.Errorf("Condition should be type ConditionStartsWith")
		}
	} else {
		t.Errorf("Unable to locate matching condition")
	}
}

func checkConditionEqType(t *testing.T, policy *Policy, key string) {
	if cond, ok := policy.Condition(key); ok == nil {
		if _, ok := cond.(ConditionEq); !ok {
			t.Errorf("Condition should be type ConditionEq")
		}
	} else {
		t.Errorf("Unable to locate matching condition")
	}
}

func checkConditionRangeType(t *testing.T, policy *Policy, key string) {
	if cond, ok := policy.Condition(key); ok == nil {
		if _, ok := cond.(ConditionRange); !ok {
			t.Errorf("Condition should be type ConditionEq")
		}
	} else {
		t.Errorf("Unable to locate matching condition")
	}
}

func TestParsePolicyExactMatch(t *testing.T) {
	var policy *Policy
	var ok error
	if policy, ok = ParsePolicy([]byte(exact_match)); ok != nil {
		t.Errorf("Unable to parse exact_match_dict policy")
	}

	checkConditionEqType(t, policy, "el")
	checkConditionEqType(t, policy, "el2")
}

func TestParsePolicyStartsWithMatch(t *testing.T) {
	var policy *Policy
	var ok error
	if policy, ok = ParsePolicy([]byte(startswith_match)); ok != nil {
		t.Errorf("Unable to parse startswith_match policy")
	}

	checkConditionStartsWithType(t, policy, "sw")
}

func TestParsePolicyRangeMatch(t *testing.T) {
	var policy *Policy
	var ok error
	if policy, ok = ParsePolicy([]byte(range_match)); ok != nil {
		t.Errorf("Unable to parse range_match policy")
	}

	checkConditionRangeType(t, policy, "foobar")
}
