// Package sdp implements Smart Data Placement: the ordered, first-match-wins
// rule engine that maps an upload's attributes (key, size, content type, tenant)
// onto a Redundancy Class, or rejects the upload.
//
// The schema is the one Cubbit documents for the gateway's Smart Data Placement
// editor (docs/05 §5.8):
//
//	[{"id":"video-to-cold","enabled":true,"inputStorageClass":"STANDARD",
//	  "conditions":{"operator":"AND","conditions":[
//	     {"field":"object.key","operator":"matches_regex","value":"\\.(mp4|avi|mov)$"},
//	     {"operator":"OR","conditions":[
//	        {"field":"object.size","operator":"gt","value":104857600},
//	        {"field":"object.content_type","operator":"equals","value":"video/mp4"}]}]},
//	  "action":{"type":"route","target":{"type":"fixed","redundancyClassId":"<uuid>"}}}]
package sdp

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Field names accepted in conditions.
const (
	FieldKey         = "object.key"
	FieldSize        = "object.size"
	FieldContentType = "object.content_type"
	FieldTenantName  = "tenant.name"
)

// Operators accepted in leaf conditions (the 16 documented operators).
const (
	OpEquals          = "equals"
	OpNotEquals       = "not_equals"
	OpMatchesRegex    = "matches_regex"
	OpNotMatchesRegex = "not_matches_regex"
	OpStartsWith      = "starts_with"
	OpEndsWith        = "ends_with"
	OpContains        = "contains"
	OpNotContains     = "not_contains"
	OpGreaterThan     = "gt"
	OpLessThan        = "lt"
	OpGreaterEqual    = "gte"
	OpLessEqual       = "lte"
	OpIn              = "in"
	OpNotIn           = "not_in"
	OpExists          = "exists"
	OpNotExists       = "not_exists"
)

// Action types.
const (
	ActionRoute = "route"
	ActionDrop  = "drop"
	// ActionDefault is returned when no rule matches.
	ActionDefault = "default"
)

// Errors returned by the engine.
var (
	ErrInvalidPolicy = errors.New("sdp: invalid policy")
)

// ObjectMeta is the set of facts a rule may inspect.
type ObjectMeta struct {
	Key          string
	Size         int64
	ContentType  string
	TenantName   string
	StorageClass string // the client-requested x-amz-storage-class
}

// Decision is the outcome of evaluating the policy.
type Decision struct {
	Action string // route | drop | default
	RCID   string // set for route
	RuleID string // matched rule, "" when default
}

// Policy is a compiled Smart Data Placement policy.
type Policy struct {
	rules []compiledRule
}

// compiledRule is a validated rule with regexes pre-compiled.
type compiledRule struct {
	id                string
	enabled           bool
	inputStorageClass string
	conditions        *compiledCondition
	action            Decision
}

type compiledCondition struct {
	// group is true for AND/OR nodes, false for leaves.
	group    bool
	all      bool // AND when true
	children []*compiledCondition

	field    string
	operator string
	value    value
	regex    *regexp.Regexp
}

// value holds the typed comparison value.
type value struct {
	str      string
	num      float64
	isNum    bool
	list     []string
	listNums []float64
	isList   bool
}

// Engine is a compiled policy evaluator. A nil Engine is valid and always
// returns the default decision.
type Engine struct {
	policy *Policy
}

// Compile parses and validates a policy document.
func Compile(data []byte) (*Engine, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("%w: empty policy", ErrInvalidPolicy)
	}
	var rawRules []ruleJSON
	if err := json.Unmarshal(data, &rawRules); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	p := &Policy{}
	for i, raw := range rawRules {
		rule, err := compileRule(raw, i)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, *rule)
	}
	return &Engine{policy: p}, nil
}

// New returns an engine from already-compiled rules (used by tests).
func New(rules []Rule) (*Engine, error) {
	p := &Policy{}
	for i, r := range rules {
		cr, err := compileRule(ruleJSON{
			ID:                r.ID,
			Enabled:           r.Enabled,
			InputStorageClass: r.InputStorageClass,
			Conditions:        r.Conditions,
			Action:            r.Action,
		}, i)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, *cr)
	}
	return &Engine{policy: p}, nil
}

// Rule re-exports the wire shape for programmatic construction.
type Rule struct {
	ID                string
	Enabled           *bool
	InputStorageClass string
	Conditions        *Condition
	Action            ActionJSON
}

// Rules returns the number of compiled rules.
func (e *Engine) Rules() int {
	if e == nil || e.policy == nil {
		return 0
	}
	return len(e.policy.rules)
}

// Evaluate applies the policy to an object: first match wins.
func (e *Engine) Evaluate(meta ObjectMeta) Decision {
	if e == nil || e.policy == nil {
		return Decision{Action: ActionDefault}
	}
	for i := range e.policy.rules {
		r := &e.policy.rules[i]
		if !r.enabled {
			continue
		}
		if r.inputStorageClass != "" && !strings.EqualFold(r.inputStorageClass, meta.StorageClass) {
			continue
		}
		if r.conditions != nil && !r.conditions.matches(meta) {
			continue
		}
		d := r.action
		d.RuleID = r.id
		return d
	}
	return Decision{Action: ActionDefault}
}

// ---------------------------------------------------------------------------
// Wire schema
// ---------------------------------------------------------------------------

type ruleJSON struct {
	ID                string     `json:"id"`
	Enabled           *bool      `json:"enabled"`
	InputStorageClass string     `json:"inputStorageClass"`
	Conditions        *Condition `json:"conditions"`
	Action            ActionJSON `json:"action"`
}

// Condition is a condition tree node: either a group (AND/OR) or a leaf.
type Condition struct {
	Operator   string       `json:"operator"`
	Conditions []*Condition `json:"conditions"`
	Field      string       `json:"field"`
	Value      any          `json:"value"`
}

// ActionJSON is the wire representation of a rule action.
type ActionJSON struct {
	Type   string `json:"type"`
	Target *struct {
		Type              string `json:"type"`
		RedundancyClassID string `json:"redundancyClassId"`
	} `json:"target"`
}

func compileRule(raw ruleJSON, index int) (*compiledRule, error) {
	if strings.TrimSpace(raw.ID) == "" {
		return nil, fmt.Errorf("%w: rule %d has no id", ErrInvalidPolicy, index)
	}
	enabled := true
	if raw.Enabled != nil {
		enabled = *raw.Enabled
	}
	cr := &compiledRule{
		id:                raw.ID,
		enabled:           enabled,
		inputStorageClass: strings.TrimSpace(raw.InputStorageClass),
	}
	switch strings.ToLower(strings.TrimSpace(raw.Action.Type)) {
	case ActionRoute:
		if raw.Action.Target == nil {
			return nil, fmt.Errorf("%w: rule %q route action has no target", ErrInvalidPolicy, raw.ID)
		}
		targetType := strings.ToLower(strings.TrimSpace(raw.Action.Target.Type))
		if targetType != "" && targetType != "fixed" {
			return nil, fmt.Errorf("%w: rule %q has unsupported target type %q", ErrInvalidPolicy, raw.ID, raw.Action.Target.Type)
		}
		if strings.TrimSpace(raw.Action.Target.RedundancyClassID) == "" {
			return nil, fmt.Errorf("%w: rule %q route target has no redundancyClassId", ErrInvalidPolicy, raw.ID)
		}
		cr.action = Decision{Action: ActionRoute, RCID: raw.Action.Target.RedundancyClassID}
	case ActionDrop:
		cr.action = Decision{Action: ActionDrop}
	default:
		return nil, fmt.Errorf("%w: rule %q has unsupported action type %q", ErrInvalidPolicy, raw.ID, raw.Action.Type)
	}
	if raw.Conditions != nil {
		cond, err := compileCondition(raw.Conditions, raw.ID)
		if err != nil {
			return nil, err
		}
		cr.conditions = cond
	}
	return cr, nil
}

func compileCondition(c *Condition, ruleID string) (*compiledCondition, error) {
	if c == nil {
		return nil, nil
	}
	op := strings.ToLower(strings.TrimSpace(c.Operator))
	switch op {
	case "and", "or":
		if len(c.Conditions) == 0 {
			return nil, fmt.Errorf("%w: rule %q has an empty %s group", ErrInvalidPolicy, ruleID, op)
		}
		node := &compiledCondition{group: true, all: op == "and"}
		for _, child := range c.Conditions {
			cc, err := compileCondition(child, ruleID)
			if err != nil {
				return nil, err
			}
			if cc == nil {
				return nil, fmt.Errorf("%w: rule %q has a nil condition", ErrInvalidPolicy, ruleID)
			}
			node.children = append(node.children, cc)
		}
		return node, nil
	}

	field := strings.TrimSpace(c.Field)
	switch field {
	case FieldKey, FieldSize, FieldContentType, FieldTenantName:
	default:
		return nil, fmt.Errorf("%w: rule %q uses unsupported field %q", ErrInvalidPolicy, ruleID, field)
	}

	leaf := &compiledCondition{field: field, operator: op}
	switch op {
	case OpExists, OpNotExists:
		return leaf, nil
	case OpMatchesRegex, OpNotMatchesRegex:
		s, ok := asString(c.Value)
		if !ok {
			return nil, fmt.Errorf("%w: rule %q operator %s needs a string value", ErrInvalidPolicy, ruleID, op)
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %q has invalid regex: %v", ErrInvalidPolicy, ruleID, err)
		}
		leaf.regex = re
		leaf.value = value{str: s}
	case OpIn, OpNotIn:
		list, nums, isNum, ok := asList(c.Value)
		if !ok {
			return nil, fmt.Errorf("%w: rule %q operator %s needs an array value", ErrInvalidPolicy, ruleID, op)
		}
		leaf.value = value{isList: true, list: list, listNums: nums, isNum: isNum}
	case OpGreaterThan, OpLessThan, OpGreaterEqual, OpLessEqual:
		num, ok := asNumber(c.Value)
		if !ok {
			return nil, fmt.Errorf("%w: rule %q operator %s needs a numeric value", ErrInvalidPolicy, ruleID, op)
		}
		leaf.value = value{isNum: true, num: num}
	case OpEquals, OpNotEquals, OpStartsWith, OpEndsWith, OpContains, OpNotContains:
		if field == FieldSize {
			num, ok := asNumber(c.Value)
			if !ok {
				return nil, fmt.Errorf("%w: rule %q operator %s on object.size needs a numeric value", ErrInvalidPolicy, ruleID, op)
			}
			leaf.value = value{isNum: true, num: num}
		} else {
			s, ok := asString(c.Value)
			if !ok {
				return nil, fmt.Errorf("%w: rule %q operator %s needs a string value", ErrInvalidPolicy, ruleID, op)
			}
			leaf.value = value{str: s}
		}
	default:
		return nil, fmt.Errorf("%w: rule %q uses unsupported operator %q", ErrInvalidPolicy, ruleID, op)
	}
	return leaf, nil
}

func (c *compiledCondition) matches(m ObjectMeta) bool {
	if c.group {
		if c.all {
			for _, child := range c.children {
				if !child.matches(m) {
					return false
				}
			}
			return true
		}
		for _, child := range c.children {
			if child.matches(m) {
				return true
			}
		}
		return false
	}

	// Leaf.
	if c.operator == OpExists {
		return hasField(m, c.field)
	}
	if c.operator == OpNotExists {
		return !hasField(m, c.field)
	}
	if c.field == FieldSize {
		return c.compareNumber(float64(m.Size))
	}
	return c.compareString(stringField(m, c.field))
}

func (c *compiledCondition) compareNumber(n float64) bool {
	v := c.value
	switch c.operator {
	case OpEquals:
		return n == v.num
	case OpNotEquals:
		return n != v.num
	case OpGreaterThan:
		return n > v.num
	case OpLessThan:
		return n < v.num
	case OpGreaterEqual:
		return n >= v.num
	case OpLessEqual:
		return n <= v.num
	case OpIn:
		for _, x := range v.listNums {
			if n == x {
				return true
			}
		}
		return false
	case OpNotIn:
		for _, x := range v.listNums {
			if n == x {
				return false
			}
		}
		return true
	}
	return false
}

func (c *compiledCondition) compareString(s string) bool {
	switch c.operator {
	case OpEquals:
		return s == c.value.str
	case OpNotEquals:
		return s != c.value.str
	case OpStartsWith:
		return strings.HasPrefix(s, c.value.str)
	case OpEndsWith:
		return strings.HasSuffix(s, c.value.str)
	case OpContains:
		return strings.Contains(s, c.value.str)
	case OpNotContains:
		return !strings.Contains(s, c.value.str)
	case OpMatchesRegex:
		return c.regex != nil && c.regex.MatchString(s)
	case OpNotMatchesRegex:
		return c.regex == nil || !c.regex.MatchString(s)
	case OpIn:
		for _, x := range c.value.list {
			if s == x {
				return true
			}
		}
		return false
	case OpNotIn:
		for _, x := range c.value.list {
			if s == x {
				return false
			}
		}
		return true
	}
	return false
}

func hasField(m ObjectMeta, field string) bool {
	switch field {
	case FieldKey:
		return m.Key != ""
	case FieldSize:
		return m.Size >= 0
	case FieldContentType:
		return m.ContentType != ""
	case FieldTenantName:
		return m.TenantName != ""
	}
	return false
}

func stringField(m ObjectMeta, field string) string {
	switch field {
	case FieldKey:
		return m.Key
	case FieldContentType:
		return m.ContentType
	case FieldTenantName:
		return m.TenantName
	}
	return ""
}

func asString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case float64:
		return fmt.Sprintf("%v", x), true
	}
	return "", false
}

func asNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func asList(v any) (strs []string, nums []float64, isNum bool, ok bool) {
	list, isList := v.([]any)
	if !isList {
		return nil, nil, false, false
	}
	isNum = true
	for _, item := range list {
		if s, sok := asString(item); sok {
			strs = append(strs, s)
			if _, nok := asNumber(item); nok {
				nums = append(nums, mustNumber(item))
			} else {
				isNum = false
			}
		} else {
			return nil, nil, false, false
		}
	}
	return strs, nums, isNum, true
}

func mustNumber(v any) float64 {
	if n, ok := asNumber(v); ok {
		return n
	}
	return 0
}
