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
	startswith_match_invalid          = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [ {"starts-with", "key", "barfoo"}, {"bucket": "bucketfoo"}, ["starts-with", "sw", "val"] ] }`
	startswith_match                  = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [ ["starts-with", "$key", "barfoo"], {"bucket": "bucketfoo"}, ["starts-with", "$sw", "val"] ] }`
	range_match                       = `{"expiration": "2012-01-01T00:00:00.000Z", "conditions": [{"$key": "barfoo"}, {"bucket": "bucketfoo"}, ["foobar", 1, 10]]}`
)

const (
	COND_EQ = iota
	COND_STARTWITH
	COND_RANGE
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

func checkConditionType(condition Condition) int {
	switch condition.(type) {
	case ConditionEq:
		return COND_EQ
	case ConditionStartsWith:
		return COND_STARTWITH
	case ConditionRange:
		return COND_RANGE
	default:
		panic("Unknown type of condition")
	}
}

func checkCondition(t *testing.T, policy *Policy, conditionType int, key, value string) {
	if cond, ok := policy.Condition(key); ok {
		if checkConditionType(cond) != conditionType {
			t.Errorf("Condition should be type %s", conditionType)
		}
		if cond.ValueString() != value {
			t.Errorf("Condition value not correct.  Expected: %s, Actual: %s", value, cond.ValueString())
		}
	} else {
		t.Errorf("Unable to locate matching condition")
	}
}

func checkConditionStartsWithType(t *testing.T, policy *Policy, key, value string) {
	checkCondition(t, policy, COND_STARTWITH, key, value)
}

func checkConditionEqType(t *testing.T, policy *Policy, key, value string) {
	checkCondition(t, policy, COND_EQ, key, value)
}

func checkConditionRangeType(t *testing.T, policy *Policy, key, value string) {
	checkCondition(t, policy, COND_RANGE, key, value)
}

func TestParsePolicyExactMatch(t *testing.T) {
	var policy *Policy
	var ok error
	if policy, ok = ParsePolicy([]byte(exact_match)); ok != nil {
		t.Errorf("Unable to parse exact_match_dict policy")
	}

	checkConditionEqType(t, policy, "el", "val")
	checkConditionEqType(t, policy, "el2", "val2")
}

func TestDegenerateParsePolicyStartsWithInvalid(t *testing.T) {
	if _, ok := ParsePolicy([]byte(startswith_match_invalid)); ok == nil {
		t.Errorf("Invalid policy, starts-with key did not start with a $, did not return an error")
	}
}

func TestParsePolicyStartsWithMatch(t *testing.T) {
	var policy *Policy
	var ok error
	if policy, ok = ParsePolicy([]byte(startswith_match)); ok != nil {
		t.Errorf("Unable to parse startswith_match policy")
	}

	checkConditionStartsWithType(t, policy, "$sw", "val")
}

func TestParsePolicyRangeMatch(t *testing.T) {
	var policy *Policy
	var ok error
	if policy, ok = ParsePolicy([]byte(range_match)); ok != nil {
		t.Errorf("Unable to parse range_match policy")
	}

	checkConditionRangeType(t, policy, "foobar", "1 10")
}
