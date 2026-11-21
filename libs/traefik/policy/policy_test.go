package policy

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The tests are the examples of the grammar's specification (see the package settings): every form an example is
// written in must give the example's normalized form, and every row of "What is refused" its error. A label's key
// is the part after "…policy."; a cluster's form is what stands under spec.plugin.policy, with the types YAML
// gives it.
//
// As in the specification, every example but the golden path writes "GroupDefaultScopes: openid", so that a
// group's default scopes are that one: the tests add the line where an example does not write the setting.

type obj = map[string]any

type list = []any

type lbl = map[string]string

// form is one way an example is written.
type form struct {
	name     string
	settings map[string]any
}

func labels(name string, l lbl) form  { return form{name: "labels, " + name, settings: fromLabels(l)} }
func cluster(name string, o obj) form { return form{name: "cluster, " + name, settings: o} }

// example is one example of the specification: its forms, and its normalized form. A key of
// want is the path of the part the example is about ("rules.0.paths"), and empty for the whole.
type example struct {
	name  string
	forms []form
	want  map[string]string
	// builtIn leaves GroupDefaultScopes as the example writes it, or does not.
	builtIn bool
}

// written is a form's settings with the line every example has.
func written(ex example, f form) map[string]any {
	if ex.builtIn {
		return f.settings
	}
	for key := range f.settings {
		if strings.EqualFold(key, keyGroupDefaultScopes) {
			return f.settings
		}
	}
	all := obj{keyGroupDefaultScopes: "openid"}
	for key, v := range f.settings {
		all[key] = v
	}
	return all
}

const noChecks = `"claimChecks": null, "additionalChecks": []`

const goldenPath = `{
  "rules": [
    {
      "name": "default", "priority": 3,
      "paths": ["/**"], "methods": [], "public": false,
      "scopes": {"required": ["admin.cluster", "openid"],
                 "optional": ["address", "email", "offline", "phone", "profile"]},
      "missing": {"action": "login"}, ` + noChecks + `
    }
  ]
}`

const severalRules = `{
  "rules": [
    {"name": "assets", "priority": 10, "paths": ["/assets/**"], "methods": [], "public": true,
     "scopes": {"required": ["openid"], "optional": ["admin"]}, "missing": {"action": "deny"}, ` + noChecks + `},
    {"name": "admin", "priority": 9, "paths": ["/admin/**"], "methods": [], "public": false,
     "scopes": {"required": ["admin", "openid"], "optional": []}, "missing": {"action": "deny"}, ` + noChecks + `},
    {"name": "rest", "priority": 3, "paths": ["/**"], "methods": [], "public": false,
     "scopes": {"required": ["openid"], "optional": ["admin"]}, "missing": {"action": "login"}, ` + noChecks + `}
  ]
}`

const priorityWritten = `[
  {"name": "writes", "priority": 100, "paths": ["/**"], "methods": ["POST", "PUT", "DELETE"], "public": false,
   "scopes": {"required": ["openid", "reports.write"], "optional": ["reports.read"]}, "missing": {"action": "deny"}, ` + noChecks + `},
  {"name": "reports", "priority": 11, "paths": ["/reports/**"], "methods": [], "public": false,
   "scopes": {"required": ["openid", "reports.read"], "optional": ["reports.write"]}, "missing": {"action": "deny"}, ` + noChecks + `}
]`

const groups = `{
  "rules": [
    {"name": "clusters", "priority": 12, "paths": ["/clusters/**"], "methods": [], "public": false,
     "scopes": {"required": ["admin.cluster", "openid"], "optional": ["admin.nodes"]},
     "missing": {"action": "login"}, ` + noChecks + `},
    {"name": "nodes", "priority": 9, "paths": ["/nodes/**"], "methods": [], "public": false,
     "scopes": {"required": ["admin.nodes", "openid"], "optional": ["admin.cluster"]},
     "missing": {"action": "login"}, ` + noChecks + `},
    {"name": "rest", "priority": 3, "paths": ["/**"], "methods": [], "public": false,
     "scopes": {"required": ["openapi.user"], "optional": ["graphql.openapi", "graphql.openapi.user"]},
     "missing": {"action": "login"}, ` + noChecks + `}
  ]
}`

const publicWithScopes = `{
  "rules": [
    {"name": "app", "priority": 3, "paths": ["/**"], "methods": [], "public": true,
     "scopes": {"required": ["graphql.openapi", "graphql.openapi.user", "openid"], "optional": []},
     "missing": {"action": "login"}, ` + noChecks + `}
  ]
}`

// groupsLabels is E6 as labels. A test that changes it takes its own copy.
func groupsLabels() lbl {
	return lbl{
		"Groups.users.Scopes.optional": "graphql.openapi graphql.openapi.user",
		"Rules.clusters.Paths":         "/clusters/**",
		"Rules.clusters.Group":         "operators",
		"Rules.clusters.Scopes":        "admin.cluster",
		"Rules.clusters.Missing":       "login",
		"Rules.nodes.Paths":            "/nodes/**",
		"Rules.nodes.Group":            "operators",
		"Rules.nodes.Scopes":           "admin.nodes",
		"Rules.nodes.Missing":          "login",
		"Rules.rest.Group":             "users",
		"Rules.rest.Scopes":            "openapi.user",
		"Rules.rest.Missing":           "login",
	}
}

// groupsCluster is E6 as a cluster's object, with the group operators and more fields of the rule clusters as
// given.
func groupsCluster(operators obj, clusters obj) obj {
	o := obj{
		"Groups": obj{"users": obj{"Scopes": obj{"optional": "graphql.openapi graphql.openapi.user"}}},
		"Rules": obj{
			"clusters": obj{"Paths": "/clusters/**", "Group": "operators", "Scopes": "admin.cluster", "Missing": "login"},
			"nodes":    obj{"Paths": "/nodes/**", "Group": "operators", "Scopes": "admin.nodes", "Missing": "login"},
			"rest":     obj{"Group": "users", "Scopes": "openapi.user", "Missing": "login"},
		},
	}
	if operators != nil {
		o["Groups"].(obj)["operators"] = operators
	}
	for key, v := range clusters {
		o["Rules"].(obj)["clusters"].(obj)[key] = v
	}
	return o
}

func examples() []example {
	const (
		twoPaths     = `["/reports/**", "/exports/**"]`
		bothRequired = `{"required": ["openid", "reports.read", "reports.write"], "optional": []}`
		oneOfEach    = `{"required": ["openid", "reports.read"], "optional": ["reports.write"]}`
		dotted       = `{"required": ["admin.cluster", "openid"], "optional": []}`
		login        = `{"action": "login"}`
	)

	return []example{
		{
			name:    "the golden path",
			builtIn: true,
			forms: []form{
				labels("", lbl{"Scopes": "admin.cluster", "Missing": "login"}),
				cluster("", obj{"Scopes": "admin.cluster", "Missing": "login"}),
			},
			want: map[string]string{"": goldenPath},
		},
		{
			name: "E1 a list, five ways",
			forms: []form{
				labels("a delimited text", lbl{"Rules.reports.Paths": "/reports/**,/exports/**"}),
				labels("brackets", lbl{"Rules.reports.Paths[0]": "/reports/**", "Rules.reports.Paths[1]": "/exports/**"}),
				labels("dots", lbl{"Rules.reports.Paths.0": "/reports/**", "Rules.reports.Paths.1": "/exports/**"}),
				cluster("a list", obj{"Rules": obj{"reports": obj{"Paths": list{"/reports/**", "/exports/**"}}}}),
				cluster("a delimited text", obj{"Rules": obj{"reports": obj{"Paths": "/reports/**,/exports/**"}}}),
			},
			want: map[string]string{"rules.0.paths": twoPaths},
		},
		{
			name: "E1 one value is a list of one",
			forms: []form{
				labels("", lbl{"Rules.reports.Paths": "/reports/**"}),
				cluster("", obj{"Rules": obj{"reports": obj{"Paths": "/reports/**"}}}),
			},
			want: map[string]string{"rules.0.paths": `["/reports/**"]`},
		},
		{
			name: "E2 scopes, required as they are written",
			forms: []form{
				labels("a delimited text", lbl{"Rules.reports.Scopes": "reports.read reports.write"}),
				cluster("a delimited text", obj{"Rules": obj{"reports": obj{"Scopes": "reports.read reports.write"}}}),
				cluster("a list of values", obj{"Rules": obj{"reports": obj{"Scopes": list{"reports.read", "reports.write"}}}}),
				labels("indexed values", lbl{"Rules.reports.Scopes.0": "reports.read", "Rules.reports.Scopes.1": "reports.write"}),
				labels("brackets", lbl{"Rules.reports.Scopes[0]": "reports.read", "Rules.reports.Scopes[1]": "reports.write"}),
				labels("entries with a field", lbl{"Rules.reports.Scopes.0.name": "reports.read", "Rules.reports.Scopes.1.name": "reports.write"}),
				cluster("entries with a field", obj{"Rules": obj{"reports": obj{"Scopes": list{obj{"name": "reports.read"}, obj{"name": "reports.write"}}}}}),
				labels("under required", lbl{"Rules.reports.Scopes.required": "reports.read reports.write"}),
			},
			want: map[string]string{"rules.0.scopes": bothRequired},
		},
		{
			name: "E2 required and optional",
			forms: []form{
				labels("", lbl{"Rules.reports.Scopes.required": "reports.read", "Rules.reports.Scopes.optional": "reports.write"}),
				cluster("", obj{"Rules": obj{"reports": obj{"Scopes": obj{"required": "reports.read", "optional": list{"reports.write"}}}}}),
				labels("each member in a form of its own", lbl{"Rules.reports.Scopes.required.0.name": "reports.read", "Rules.reports.Scopes.optional[0]": "reports.write"}),
				cluster("dotted keys", obj{"Rules": obj{"reports": obj{"Scopes.required": list{obj{"name": "reports.read"}}, "Scopes.optional": "reports.write"}}}),
			},
			want: map[string]string{"rules.0.scopes": oneOfEach},
		},
		{
			name: "E2 keys",
			forms: []form{
				labels("", lbl{"Rules.staff.Scopes.required.admin": "true", "Rules.staff.Scopes.optional.auditor": "true"}),
				cluster("", obj{"Rules": obj{"staff": obj{"Scopes": obj{"required": obj{"admin": true}, "optional": obj{"auditor": true}}}}}),
			},
			want: map[string]string{"rules.0.scopes": `{"required": ["admin", "openid"], "optional": ["auditor"]}`},
		},
		{
			name: "E2 keys without the object are required scopes",
			forms: []form{
				labels("", lbl{"Rules.staff.Scopes.admin": "true"}),
				cluster("", obj{"Rules": obj{"staff": obj{"Scopes": obj{"admin": true}}}}),
			},
			want: map[string]string{"rules.0.scopes": `{"required": ["admin", "openid"], "optional": []}`},
		},
		{
			name: "E3 a scope whose name has a dot",
			forms: []form{
				labels("a value", lbl{"Rules.page.Scopes": "admin.cluster"}),
				labels("an entry's name", lbl{"Rules.page.Scopes.0.name": "admin.cluster"}),
				labels("a key that is not the scope's name", lbl{"Rules.page.Scopes.cluster.name": "admin.cluster"}),
				cluster("a value", obj{"Rules": obj{"page": obj{"Scopes": "admin.cluster"}}}),
				cluster("an entry's name", obj{"Rules": obj{"page": obj{"Scopes": list{obj{"name": "admin.cluster"}}}}}),
				cluster("a key that is not the scope's name", obj{"Rules": obj{"page": obj{"Scopes": obj{"cluster": obj{"name": "admin.cluster"}}}}}),
			},
			want: map[string]string{"rules.0.scopes": dotted},
		},
		{
			name: "E4 several rules, named",
			forms: []form{
				labels("", lbl{
					"Rules.assets.Paths":  "/assets/**",
					"Rules.assets.Public": "true",
					"Rules.admin.Paths":   "/admin/**",
					"Rules.admin.Scopes":  "admin",
					"Rules.rest.Missing":  "login",
				}),
				cluster("", obj{"Rules": obj{
					"assets": obj{"Paths": "/assets/**", "Public": true},
					"admin":  obj{"Paths": "/admin/**", "Scopes": "admin"},
					"rest":   obj{"Missing": "login"},
				}}),
			},
			want: map[string]string{"": severalRules},
		},
		{
			name: "E4 several rules, a list",
			forms: []form{
				cluster("", obj{"Rules": list{
					obj{"Paths": "/assets/**", "Public": true},
					obj{"Paths": "/admin/**", "Scopes": "admin"},
					obj{"Missing": "login"},
				}}),
				labels("brackets", lbl{
					"Rules[0].Paths": "/assets/**", "Rules[0].Public": "true",
					"Rules[1].Paths": "/admin/**", "Rules[1].Scopes": "admin",
					"Rules[2].Missing": "login",
				}),
				labels("dots", lbl{
					"Rules.0.Paths": "/assets/**", "Rules.0.Public": "true",
					"Rules.1.Paths": "/admin/**", "Rules.1.Scopes": "admin",
					"Rules.2.Missing": "login",
				}),
			},
			want: map[string]string{"": strings.NewReplacer(
				`"name": "assets"`, `"name": "0"`, `"name": "admin", "priority"`, `"name": "1", "priority"`, `"name": "rest"`, `"name": "2"`,
			).Replace(severalRules)},
		},
		{
			name: "E4 a priority written out",
			forms: []form{
				labels("", lbl{
					"Rules.writes.Methods":  "POST,PUT,DELETE",
					"Rules.writes.Scopes":   "reports.write",
					"Rules.writes.Priority": "100",
					"Rules.reports.Paths":   "/reports/**",
					"Rules.reports.Scopes":  "reports.read",
				}),
				cluster("a number as YAML reads it", obj{"Rules": obj{
					"writes":  obj{"Methods": "POST,PUT,DELETE", "Scopes": "reports.write", "Priority": float64(100)},
					"reports": obj{"Paths": "/reports/**", "Scopes": "reports.read"},
				}}),
				cluster("a whole number", obj{"Rules": obj{
					"writes":  obj{"Methods": "POST,PUT,DELETE", "Scopes": "reports.write", "Priority": 100},
					"reports": obj{"Paths": "/reports/**", "Scopes": "reports.read"},
				}}),
			},
			want: map[string]string{"rules": priorityWritten},
		},
		{
			name: "E5 a login",
			forms: []form{
				labels("a value", lbl{"Rules.page.Missing": "login"}),
				labels("a key", lbl{"Rules.page.Missing.login": "true"}),
				cluster("a value", obj{"Rules": obj{"page": obj{"Missing": "login"}}}),
				cluster("a key", obj{"Rules": obj{"page": obj{"Missing": obj{"login": true}}}}),
				labels("under a name of its own", lbl{"Rules.page.Missing.sign-in.action": "login"}),
				cluster("under a name of its own", obj{"Rules": obj{"page": obj{"Missing": obj{"sign-in": obj{"action": "login"}}}}}),
			},
			want: map[string]string{"rules.0.missing": login},
		},
		{
			name: "E5 not written, a rule refuses",
			forms: []form{
				labels("", lbl{"Rules.page.Paths": "/page"}),
				cluster("", obj{"Rules": obj{"page": obj{"Paths": "/page"}}}),
			},
			want: map[string]string{"rules.0.missing": `{"action": "deny"}`},
		},
		{
			name: "E6 groups",
			forms: []form{
				labels("", groupsLabels()),
				cluster("", groupsCluster(nil, nil)),
			},
			want: map[string]string{"": groups},
		},
		{
			name: "E7 a public rule that names scopes",
			forms: []form{
				labels("", lbl{"Rules.app.Public": "true", "Rules.app.Scopes": "graphql.openapi graphql.openapi.user"}),
				cluster("", obj{"Rules": obj{"app": obj{"Public": true, "Scopes": "graphql.openapi graphql.openapi.user"}}}),
			},
			want: map[string]string{"": publicWithScopes},
		},
		{
			name: "E7 a public rule's login, written",
			forms: []form{
				labels("", lbl{"Rules.app.Public": "true", "Rules.app.Scopes": "admin", "Rules.app.Missing": "login"}),
				cluster("", obj{"Rules": obj{"app": obj{"Public": true, "Scopes": obj{"optional": "admin"}, "Missing": obj{"login": true}}}}),
			},
			want: map[string]string{"rules.0.public": `true`, "rules.0.missing": login},
		},
		{
			name: "E7 a public rule with optional scopes of its own asks for them by a login",
			forms: []form{
				labels("", lbl{"Rules.app.Public": "true", "Rules.app.Scopes.optional": "admin"}),
				cluster("", obj{"Rules": obj{"app": obj{"Public": true, "Scopes": obj{"optional": "admin"}}}}),
			},
			want: map[string]string{"rules.0.missing": login},
		},
		{
			name: "E7 a public rule without scopes of its own refuses nobody, and asks for nothing",
			forms: []form{
				labels("", lbl{"Rules.page.Public": "true", "Rules.other.Paths": "/other", "Rules.other.Scopes": "admin"}),
				cluster("", obj{"Rules": obj{"page": obj{"Public": true}, "other": obj{"Paths": "/other", "Scopes": "admin"}}}),
			},
			want: map[string]string{
				"rules.1.name":    `"page"`,
				"rules.1.scopes":  `{"required": ["openid"], "optional": ["admin"]}`,
				"rules.1.missing": `{"action": "deny"}`,
			},
		},
		{
			name: "Checks",
			forms: []form{
				labels("", lbl{
					"Rules.bulk.Paths": "/bulk/**", "Rules.bulk.Scopes": "reports.write",
					"Rules.bulk.AdditionalChecks": "weekdays,internal_client",
				}),
				cluster("", obj{"Rules": obj{"bulk": obj{
					"Paths": "/bulk/**", "Scopes": "reports.write", "AdditionalChecks": list{"weekdays", "internal_client"},
				}}}),
			},
			want: map[string]string{
				"rules.0.claimChecks":      `null`,
				"rules.0.additionalChecks": `["weekdays", "internal_client"]`,
			},
		},
	}
}

func TestExamples(t *testing.T) {
	for _, ex := range examples() {
		for _, f := range ex.forms {
			name := ex.name + " (" + strings.TrimSuffix(f.name, ", ") + ")"
			got, err := Normalize(written(ex, f))
			if err != nil {
				t.Errorf("%s: refused: %v", name, err)
				continue
			}
			tree := decode(t, name, encode(t, got))
			for path, want := range ex.want {
				part, ok := at(tree, path)
				if !ok {
					t.Errorf("%s: the normalized form has no %q:\n%s", name, path, encode(t, got))
					continue
				}
				if !reflect.DeepEqual(part, decode(t, name, want)) {
					t.Errorf("%s: %q is\n%s\nand should be\n%s", name, path, encode(t, part), want)
				}
			}
		}
	}
}

// listsOf is the two lists of the rule of that name, each as the specification's tables write a list: its
// scopes with a space between them.
func listsOf(t *testing.T, name string, s *Settings, rule string) (required, optional string, found *Rule) {
	for _, r := range s.Rules {
		if r.Name == rule {
			if r.Scopes.Required == nil || r.Scopes.Optional == nil {
				t.Errorf("%s: a list of the rule %s is null, and should be []", name, rule)
			}
			return strings.Join(r.Scopes.Required, " "), strings.Join(r.Scopes.Optional, " "), r
		}
	}
	t.Errorf("%s: no rule %s in\n%s", name, rule, encode(t, s))
	return "", "", nil
}

// The table of E6: the rule clusters under other settings of its group and of its own.
func TestGroupSettings(t *testing.T) {
	const group, rule = "Groups.operators.RequestAllScopesForAnyMember", "Rules.clusters.RequestOtherGroupScopes"
	for _, row := range []struct {
		group, rule        string
		required, optional string
	}{
		{"", "", "admin.cluster openid", "admin.nodes"},
		{"true", "", "admin.cluster admin.nodes openid", ""},
		{"required", "", "admin.cluster admin.nodes openid", ""},
		{"false", "", "admin.cluster openid", ""},
		{"", "optional", "admin.cluster", "admin.nodes openid"},
		{"required", "optional", "admin.cluster", "admin.nodes openid"},
		{"", "required", "admin.cluster admin.nodes openid", ""},
		{"required", "false", "admin.cluster", ""},
	} {
		l := groupsLabels()
		var operators, clusters obj
		if row.group != "" {
			l[group] = row.group
			operators = obj{"RequestAllScopesForAnyMember": asCluster(row.group)}
		}
		if row.rule != "" {
			l[rule] = row.rule
			clusters = obj{"RequestOtherGroupScopes": asCluster(row.rule)}
		}
		ex := example{}
		for _, f := range []form{labels("", l), cluster("", groupsCluster(operators, clusters))} {
			name := f.name + "the group " + strconv.Quote(row.group) + ", the rule " + strconv.Quote(row.rule)
			got, err := Normalize(written(ex, f))
			if err != nil {
				t.Errorf("%s: refused: %v", name, err)
				continue
			}
			required, optional, _ := listsOf(t, name, got, "clusters")
			if required != row.required || optional != row.optional {
				t.Errorf("%s: required %q, optional %q, and should be %q and %q", name, required, optional, row.required, row.optional)
			}
		}
	}
}

// asCluster is a setting's value as a cluster's object has it: true and false are booleans there.
func asCluster(text string) any {
	switch text {
	case "true":
		return true
	case "false":
		return false
	}
	return text
}

// The rows of the handover "required and optional scopes, one group per rule, checks": what the table of E6
// leaves out. Every row but 15 writes "GroupDefaultScopes: openid".
func TestRows(t *testing.T) {
	const required = "required"
	rules := func(r obj) obj { return obj{"Rules": r} }
	with := func(o obj, key string, v any) obj {
		o[key] = v
		return o
	}
	for _, row := range []struct {
		n                  int
		labels             lbl
		cluster            obj
		rule               string
		required, optional string
		claim, additional  string
	}{
		{n: 1,
			labels: lbl{"Rules.a.Scopes.required": "x", "Rules.a.Scopes.optional": "y",
				"Groups.default.RequestAllScopesForAnyMember": required},
			cluster: with(rules(obj{"a": obj{"Scopes": obj{"required": "x", "optional": list{"y"}}}}),
				"Groups", obj{"default": obj{"RequestAllScopesForAnyMember": required}}),
			required: "openid x", optional: "y"},
		{n: 2,
			labels: lbl{"Rules.a.Scopes.required": "x", "Rules.a.Scopes.optional": "y", "Rules.b.Scopes.optional": "y",
				"Groups.default.RequestAllScopesForAnyMember": required},
			cluster: with(rules(obj{
				"a": obj{"Scopes": obj{"required": "x", "optional": list{"y"}}},
				"b": obj{"Scopes": obj{"optional": "y"}}}),
				"Groups", obj{"default": obj{"RequestAllScopesForAnyMember": required}}),
			required: "openid x y"},
		{n: 3,
			labels: lbl{"Rules.a.Scopes": "x", "Groups.default.Scopes.required": "w", "Groups.default.Scopes.optional": "v",
				"Groups.default.RequestAllScopesForAnyMember": required},
			cluster: with(rules(obj{"a": obj{"Scopes": "x"}}), "Groups", obj{"default": obj{
				"Scopes": obj{"required": list{"w"}, "optional": "v"}, "RequestAllScopesForAnyMember": required}}),
			required: "w x", optional: "v"},
		{n: 4,
			labels: lbl{"Rules.a.Scopes": "x", "Rules.b.Scopes": "z", "Groups.default.Scopes.required": "z"},
			cluster: with(rules(obj{"a": obj{"Scopes": "x"}, "b": obj{"Scopes": list{"z"}}}),
				"Groups", obj{"default": obj{"Scopes": obj{"required": "z"}}}),
			required: "x", optional: "z"},
		{n: 5,
			labels: lbl{"Rules.a.Scopes": "x", "Rules.b.Scopes": "z", "Groups.default.Scopes.required": "z",
				"Groups.default.RequestAllScopesForAnyMember": required},
			cluster: with(rules(obj{"a": obj{"Scopes": "x"}, "b": obj{"Scopes": list{"z"}}}),
				"Groups", obj{"default": obj{"Scopes": obj{"required": "z"}, "RequestAllScopesForAnyMember": required}}),
			required: "x z"},
		{n: 6,
			labels: lbl{"Rules.a.Scopes": "x", "Rules.b.Scopes.required": "z", "Rules.b.Scopes.optional": "y",
				"Groups.default.RequestAllScopesForAnyMember": "true"},
			cluster: with(rules(obj{"a": obj{"Scopes": "x"}, "b": obj{"Scopes": obj{"required": "z", "optional": "y"}}}),
				"Groups", obj{"default": obj{"RequestAllScopesForAnyMember": true}}),
			required: "openid x z", optional: "y"},
		{n: 7,
			labels: lbl{"Rules.a.Scopes": "x", "Rules.b.Scopes": "z", "Rules.c.Scopes.optional": "z",
				"Groups.default.RequestAllScopesForAnyMember": "true"},
			cluster: with(rules(obj{"a": obj{"Scopes": "x"}, "b": obj{"Scopes": "z"}, "c": obj{"Scopes": obj{"optional": "z"}}}),
				"Groups", obj{"default": obj{"RequestAllScopesForAnyMember": true}}),
			required: "openid x", optional: "z"},
		{n: 8,
			labels:   lbl{"Rules.a.Scopes": "x", "Rules.b.Scopes": "x"},
			cluster:  rules(obj{"a": obj{"Scopes": "x"}, "b": obj{"Scopes": "x"}}),
			required: "openid x"},
		{n: 9,
			labels:   lbl{"Rules.a.Scopes.optional": "y", "Rules.b.Scopes": "y"},
			cluster:  rules(obj{"a": obj{"Scopes": obj{"optional": "y"}}, "b": obj{"Scopes": "y"}}),
			required: "openid", optional: "y"},
		{n: 10,
			labels:   lbl{"Rules.a.Scopes": "x", "Rules.b.Scopes": "openid"},
			cluster:  rules(obj{"a": obj{"Scopes": "x"}, "b": obj{"Scopes": "openid"}}),
			required: "x", optional: "openid"},
		{n: 11,
			labels: lbl{"Rules.a.Group": "staff", "Rules.a.Scopes": "x", "Rules.b.Group": "users", "Rules.b.Scopes": "u",
				"Rules.c.Group": "staff", "Rules.c.Scopes": "s", "Groups.users.RequestAllScopesForAnyMember": required},
			cluster: with(rules(obj{
				"a": obj{"Group": "staff", "Scopes": "x"}, "b": obj{"Group": "users", "Scopes": "u"},
				"c": obj{"Group": "staff", "Scopes": "s"}}),
				"Groups", obj{"users": obj{"RequestAllScopesForAnyMember": required}}),
			required: "openid x", optional: "s"},
		{n: 12,
			labels:   lbl{"Rules.a.Group": "staff", "Rules.a.Scopes": "x", "Rules.b.Scopes": "z"},
			cluster:  rules(obj{"a": obj{"Group": "staff", "Scopes": "x"}, "b": obj{"Scopes": "z"}}),
			required: "openid x", optional: "z"},
		{n: 13,
			labels:   lbl{"Rules.a.Scopes": "x", "Groups.staff.Scopes": "w"},
			cluster:  with(rules(obj{"a": obj{"Scopes": "x"}}), "Groups", obj{"staff": obj{"Scopes": "w"}}),
			required: "w x"},
		{n: 14,
			labels:   lbl{"Rules.a.Scopes": "required"},
			cluster:  rules(obj{"a": obj{"Scopes": "required"}}),
			required: "openid required"},
		{n: 15,
			labels: lbl{"Rules.a.Scopes.required": "admin",
				"Rules.a.Scopes.optional":     "graphql.openapi graphql.openapi.user openapi.admin",
				"GroupDefaultScopes.required": "openid", "GroupDefaultScopes.optional": "profile email offline"},
			cluster: with(rules(obj{"a": obj{"Scopes": obj{
				"required": "admin", "optional": list{"graphql.openapi", "graphql.openapi.user", "openapi.admin"}}}}),
				"GroupDefaultScopes", obj{"required": "openid", "optional": "profile email offline"}),
			required: "admin openid", optional: "email graphql.openapi graphql.openapi.user offline openapi.admin profile"},
		{n: 16, rule: "default",
			labels:   lbl{"Scopes": "x", "RequestOtherGroupScopes": "false", "AdditionalChecks": "weekdays"},
			cluster:  obj{"Scopes": "x", "RequestOtherGroupScopes": false, "AdditionalChecks": list{"weekdays"}},
			required: "x", additional: `["weekdays"]`},
		{n: 17,
			labels:   lbl{"Rules.a.Scopes": "x"},
			cluster:  rules(obj{"a": obj{"Scopes": "x"}}),
			required: "openid x"},
		{n: 18,
			labels:   lbl{"Rules.a.Scopes": "x", "Rules.a.ClaimChecks": "rule_matches", "Rules.a.AdditionalChecks.0": "weekdays"},
			cluster:  rules(obj{"a": obj{"Scopes": "x", "ClaimChecks": "rule_matches", "AdditionalChecks": list{"weekdays"}}}),
			required: "openid x", claim: `["rule_matches"]`, additional: `["weekdays"]`},
		{n: 19,
			cluster:  rules(obj{"a": obj{"Scopes": "x", "ClaimChecks": list{}}}),
			required: "openid x", claim: `[]`},
	} {
		if row.rule == "" {
			row.rule = "a"
		}
		if row.claim == "" {
			row.claim = `null`
		}
		if row.additional == "" {
			row.additional = `[]`
		}
		forms := []form{cluster("", row.cluster)}
		if row.labels != nil {
			forms = append(forms, labels("", row.labels))
		}
		for _, f := range forms {
			name := "row " + strconv.Itoa(row.n) + " (" + strings.TrimSuffix(f.name, ", ") + ")"
			got, err := Normalize(written(example{}, f))
			if err != nil {
				t.Errorf("%s: refused: %v", name, err)
				continue
			}
			required, optional, r := listsOf(t, name, got, row.rule)
			if r == nil {
				continue
			}
			if required != row.required || optional != row.optional {
				t.Errorf("%s: required %q, optional %q, and should be %q and %q", name, required, optional, row.required, row.optional)
			}
			if claim := encode(t, r.ClaimChecks); claim != row.claim {
				t.Errorf("%s: claimChecks is %s and should be %s", name, claim, row.claim)
			}
			if additional := encode(t, r.AdditionalChecks); additional != row.additional {
				t.Errorf("%s: additionalChecks is %s and should be %s", name, additional, row.additional)
			}
		}
	}
}

// severalGroups defines the groups operators and users, for the rows that are about several groups.
func severalGroups(l lbl) lbl {
	l["Groups.operators.Scopes"] = "admin"
	l["Groups.users.Scopes"] = "openapi.user"
	return l
}

func severalGroupsCluster(rules obj) obj {
	return obj{
		"Groups": obj{"operators": obj{"Scopes": "admin"}, "users": obj{"Scopes": "openapi.user"}},
		"Rules":  rules,
	}
}

const (
	aRuleHas   = `(a rule has Paths, Methods, Public, Group, Scopes, RequestOtherGroupScopes, Missing, Priority, ClaimChecks, AdditionalChecks)`
	aPolicyHas = `(a policy has Rules, Groups, GroupDefaultScopes, Paths, Methods, Public, Group, Scopes, RequestOtherGroupScopes, Missing, Priority, ClaimChecks, AdditionalChecks)`
)

// refusals are the rows of "What is refused": the name of a row is its error.
func refusals() []example {
	return []example{
		{
			name: `Rules.page: unknown key "Scopse" ` + aRuleHas,
			forms: []form{
				labels("", lbl{"Rules.page.Scopse": "admin"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopse": "admin"}}}),
			},
		},
		{
			name: `Scopes: the rule's fields at the top and Rules cannot both be written`,
			forms: []form{
				labels("", lbl{"Scopes": "admin", "Rules.page.Paths": "/page"}),
				cluster("", obj{"Scopes": "admin", "Rules": obj{"page": obj{"Paths": "/page"}}}),
			},
		},
		{
			name: `Rules: indexed and named entries cannot be mixed`,
			forms: []form{
				labels("", lbl{"Rules.0.Paths": "/a", "Rules.page.Paths": "/page"}),
				cluster("", obj{"Rules": obj{"0": obj{"Paths": "/a"}, "page": obj{"Paths": "/page"}}}),
			},
		},
		{
			name: `Rules.page.Missing: a public rule refuses nobody (login, or not written)`,
			forms: []form{
				labels("", lbl{"Rules.page.Public": "true", "Rules.page.Missing": "deny"}),
				cluster("", obj{"Rules": obj{"page": obj{"Public": true, "Missing": "deny"}}}),
				labels("with scopes", lbl{"Rules.page.Public": "true", "Rules.page.Scopes": "admin", "Rules.page.Missing": "deny"}),
				cluster("a key", obj{"Rules": obj{"page": obj{"Public": true, "Missing": obj{"deny": true}}}}),
			},
		},
		{
			name: `Rules.page.Missing: "ask" is no action (login, deny)`,
			forms: []form{
				labels("", lbl{"Rules.page.Missing": "ask"}),
				cluster("", obj{"Rules": obj{"page": obj{"Missing": "ask"}}}),
			},
		},
		{
			name: `Rules.page.Missing: one action per rule`,
			forms: []form{
				labels("", lbl{"Rules.page.Missing.a.action": "login", "Rules.page.Missing.b.action": "deny"}),
				cluster("", obj{"Rules": obj{"page": obj{"Missing": obj{"a": obj{"action": "login"}, "b": obj{"action": "deny"}}}}}),
			},
		},
		{
			name: `Rules.page.Missing.login: unknown key "scope" (an action has action)`,
			forms: []form{
				labels("", lbl{"Rules.page.Missing.login.scope.group": "users"}),
				cluster("", obj{"Rules": obj{"page": obj{"Missing": obj{"login": obj{"scope": obj{"group": "users"}}}}}}),
				cluster("a dotted key", obj{"Rules": obj{"page": obj{"Missing": obj{"login": obj{"scope.group": "users"}}}}}),
			},
		},
		{
			name: `Rules.page.Scopes.x: unknown key "nam" (a scope has name)`,
			forms: []form{
				labels("", lbl{"Rules.page.Scopes.x.nam": "admin"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopes": obj{"x": obj{"nam": "admin"}}}}}),
			},
		},
		{
			name: `Rules.page.Scopes.0: unknown key "group" (a scope has name)`,
			forms: []form{
				labels("", lbl{"Rules.page.Scopes.0.group": "operators"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopes": list{obj{"group": "operators"}}}}}),
				labels("with its name", lbl{"Rules.page.Scopes.0.name": "admin", "Rules.page.Scopes.0.group": "operators"}),
			},
		},
		{
			name: `Rules.page.Scopes.admin: unknown key "cluster" (a scope has name); a name with a dot is a value, or an entry's name`,
			forms: []form{
				labels("", lbl{"Rules.page.Scopes.admin.cluster": "true"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopes": obj{"admin": obj{"cluster": true}}}}}),
				cluster("a dotted key", obj{"Rules": obj{"page": obj{"Scopes": obj{"admin.cluster": true}}}}),
			},
		},
		{
			name: `Rules.page.Scopes: required and optional cannot be mixed with other entries`,
			forms: []form{
				labels("", lbl{"Rules.page.Scopes.required": "a", "Rules.page.Scopes.admin": "true"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopes": obj{"required": "a", "admin": true}}}}),
				labels("an index", lbl{"Rules.page.Scopes.optional": "a", "Rules.page.Scopes.0": "admin"}),
			},
		},
		{
			name: `Rules.page: unknown key "Any" ` + aRuleHas,
			forms: []form{
				labels("", lbl{"Rules.page.Any": "a b"}),
				cluster("", obj{"Rules": obj{"page": obj{"Any": "a b"}}}),
			},
		},
		{
			name: `unknown key "Any" ` + aPolicyHas,
			forms: []form{
				labels("", lbl{"Any": "a b"}),
				cluster("", obj{"Any": list{"a", "b"}}),
			},
		},
		{
			name: `Rules.page.RequestOtherGroupScopes: "maybe" is none of false, true, required, optional`,
			forms: []form{
				labels("", lbl{"Rules.page.RequestOtherGroupScopes": "maybe"}),
				cluster("", obj{"Rules": obj{"page": obj{"RequestOtherGroupScopes": "maybe"}}}),
			},
		},
		{
			name: `Groups.g: unknown key "RequireAllScopesForAnyMember" (a group has Scopes, RequestAllScopesForAnyMember)`,
			forms: []form{
				labels("", lbl{"Groups.g.RequireAllScopesForAnyMember": "true"}),
				cluster("", obj{"Groups": obj{"g": obj{"RequireAllScopesForAnyMember": true}}}),
			},
		},
		{
			name: `Groups.g.RequestAllScopesForAnyMember: "maybe" is none of false, true, required, optional`,
			forms: []form{
				labels("", lbl{"Groups.g.RequestAllScopesForAnyMember": "maybe"}),
				cluster("", obj{"Groups": obj{"g": obj{"RequestAllScopesForAnyMember": "maybe"}}}),
			},
		},
		{
			name: `Rules.page.Priority: "high" is no number`,
			forms: []form{
				labels("", lbl{"Rules.page.Priority": "high"}),
				cluster("", obj{"Rules": obj{"page": obj{"Priority": "high"}}}),
			},
		},
		{
			name: `Rules.page.AdditionalChecks: "my-check" is no name of a check (letters, digits and _, beginning with a letter)`,
			forms: []form{
				labels("", lbl{"Rules.page.AdditionalChecks": "my-check"}),
				cluster("", obj{"Rules": obj{"page": obj{"AdditionalChecks": list{"weekdays", "my-check"}}}}),
			},
		},
		{
			name: `Rules.page: a rule names its Group where there are several groups (operators, users)`,
			forms: []form{
				labels("", severalGroups(lbl{"Rules.page.Scopes": "admin"})),
				cluster("", severalGroupsCluster(obj{"page": obj{"Scopes": "admin"}})),
				labels("groups that rules name", lbl{
					"Rules.a.Group": "users", "Rules.b.Group": "operators", "Rules.page.Scopes": "admin",
				}),
			},
		},
	}
}

func TestRefusals(t *testing.T) {
	for _, row := range refusals() {
		for _, f := range row.forms {
			got, err := Normalize(written(row, f))
			if err == nil {
				t.Errorf("%s (%s): not refused, but read as\n%s", row.name, f.name, encode(t, got))
				continue
			}
			if err.Error() != row.name {
				t.Errorf("%s: refused with\n%s\nand should be with\n%s", f.name, err, row.name)
			}
		}
	}
}

// What the grammar leaves open, and how this package settles it.
func TestSettledHere(t *testing.T) {
	read := func(o obj) string {
		got, err := Normalize(o)
		if err != nil {
			return err.Error()
		}
		return encode(t, got)
	}
	one := func(required, optional string) string {
		return `{"rules":[{"name":"default","priority":3,"paths":["/**"],"methods":[],"public":false,` +
			`"scopes":{"required":` + required + `,"optional":` + optional + `},` +
			`"missing":{"action":"deny"},"claimChecks":null,"additionalChecks":[]}]}`
	}
	const openid = "GroupDefaultScopes"
	for _, c := range []struct {
		name string
		in   obj
		want string
	}{
		{"no rule's field and no Rules is no rule", obj{}, `{"rules":[]}`},
		{"a setting that is nil is not written", obj{"Rules": nil, "Groups": nil, "Paths": nil}, `{"rules":[]}`},
		{"groups and their default scopes alone are no rule", obj{"Groups.staff.Scopes": "w", openid: "openid"}, `{"rules":[]}`},
		{"an empty value is refused", obj{"Scopes": ""}, `Scopes: an empty value`},
		{"an empty member is refused", obj{"Scopes.optional": ""}, `Scopes.optional: an empty value`},
		{"a key in another case is the same key", obj{"scopes": "admin", "Scopes": "admin"},
			`"Scopes" and "scopes" are the same key`},
		{"a scope without a key writes its name", obj{"Scopes": list{obj{}}},
			`Scopes.0: a scope without a key writes its name`},
		{"a deny has no field either", obj{"Missing": obj{"deny": obj{"scope.group": "users"}}},
			`Missing.deny: unknown key "scope" (an action has action)`},
		{"a scope is required or optional, not both: a rule's", obj{"Scopes.required": "x", "Scopes.optional": "x y"},
			`Scopes: "x" is both required and optional`},
		{"not both: in a named rule, on a cluster", obj{"Rules": obj{"page": obj{"Scopes": obj{"required": list{"a", "x"}, "optional": obj{"x": true}}}}},
			`Rules.page.Scopes: "x" is both required and optional`},
		{"not both: a group's", obj{"Scopes": "a", "Groups.staff.Scopes.required": "w x", "Groups.staff.Scopes.optional": "x"},
			`Groups.staff.Scopes: "x" is both required and optional`},
		{"not both: the default scopes", obj{"Scopes": "a", "GroupDefaultScopes.required": "openid", "GroupDefaultScopes.optional": "profile openid"},
			`GroupDefaultScopes: "openid" is both required and optional`},
		{"not both: the first in alphabetical order is named", obj{"Scopes.required": "z b", "Scopes.optional": "b z"},
			`Scopes: "b" is both required and optional`},
		{"a scope may be required by a rule and optional in its group", obj{"Scopes": "x", "Groups.default.Scopes.optional": "x"},
			one(`["x"]`, `[]`)},
		{"a scope written twice is there once", obj{"Scopes": "x x", openid: "x"}, one(`["x"]`, `[]`)},
		{"default scopes written as optional alone have no required one", obj{"Scopes": "x", "GroupDefaultScopes.optional": "profile"},
			one(`["x"]`, `["profile"]`)},
		{"a group that writes an empty list has no scopes, and none of the defaults",
			obj{"Scopes": "x", "Groups": obj{"default": obj{"Scopes": list{}}}}, one(`["x"]`, `[]`)},
		{"a group that is defined and has no rule is still a group",
			obj{"Scopes": "x", "Groups": obj{"staff": true, "users": true}},
			`a rule names its Group where there are several groups (staff, users)`},
		{"a rule without scopes names its group too", obj{"Rules.page.Public": true, "Groups": obj{"staff": true, "users": true}},
			`Rules.page: a rule names its Group where there are several groups (staff, users)`},
		{"the two settings read true and false as a boolean is read",
			obj{"Scopes": "x", "RequestOtherGroupScopes": "0", openid: "openid"}, one(`["x"]`, `[]`)},
		{"and required and optional in any case: a rule's", obj{"Scopes": "x", "RequestOtherGroupScopes": "OPTIONAL", openid: "openid"},
			one(`["x"]`, `["openid"]`)},
		{"in any case: a group's", obj{"Scopes": "x", "Groups.default.RequestAllScopesForAnyMember": "Required", openid: "openid"},
			one(`["openid","x"]`, `[]`)},
		{"another word is refused as it is written", obj{"Scopes": "x", "RequestOtherGroupScopes": "Maybe"},
			`RequestOtherGroupScopes: "Maybe" is none of false, true, required, optional`},
		{"a check's name begins with a letter", obj{"ClaimChecks": "_x"},
			`ClaimChecks: "_x" is no name of a check (letters, digits and _, beginning with a letter)`},
		{"a check's name has letters, digits and _", obj{"Scopes": "x", "ClaimChecks": "Rule_2,b", openid: "openid"},
			strings.Replace(one(`["openid","x"]`, `[]`), `"claimChecks":null`, `"claimChecks":["Rule_2","b"]`, 1)},
		{"an empty list of checks in a label is refused", obj{"AdditionalChecks": ""}, `AdditionalChecks: an empty value`},
	} {
		if got := read(c.in); got != c.want {
			t.Errorf("%s:\n%s\nand should be\n%s", c.name, got, c.want)
		}
	}
}

// Keys are read without regard to case (G8): a member's and an action's too.
func TestCase(t *testing.T) {
	lower, err := Normalize(fromLabels(lbl{
		"groupdefaultscopes":                          "openid",
		"rules.page.scopes.REQUIRED":                  "admin.cluster",
		"rules.page.scopes.Optional":                  "auditor",
		"rules.page.missing.Login":                    "TRUE",
		"rules.page.requestothergroupscopes":          "Optional",
		"rules.page.additionalchecks":                 "weekdays",
		"groups.default.requestallscopesforanymember": "FALSE",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"rules":[{"name":"page","priority":3,"paths":["/**"],"methods":[],"public":false,"scopes":{"required":["admin.cluster"],"optional":["auditor","openid"]},"missing":{"action":"login"},"claimChecks":null,"additionalChecks":["weekdays"]}]}`
	if got := encode(t, lower); got != want {
		t.Errorf("got\n%s\nand should be\n%s", got, want)
	}
}

// A boolean is read as Traefik reads a label's (strconv.ParseBool), wherever the policy's settings have one:
// Public, an entry's bare true, and the true and false of the two settings that take four values.
func TestBooleans(t *testing.T) {
	type spelling struct {
		label   string
		cluster any
	}
	trues := []spelling{{"1", 1}, {"t", "t"}, {"T", "T"}, {"true", true}, {"True", "True"}, {"TRUE", "TRUE"}}
	falses := []spelling{{"0", 0}, {"f", "f"}, {"F", "F"}, {"false", false}, {"False", "False"}, {"FALSE", "FALSE"}}
	refused := []string{"yes", "on", "tRuE", ""}

	// With the group's setting true the other rule's scope is required here, and with false it is not there.
	scopes := func(group, rule any) obj {
		return obj{"GroupDefaultScopes": "openid", "Rules.a.Scopes": "x", "Rules.b.Scopes": "z",
			"Groups.default.RequestAllScopesForAnyMember": group, "Rules.a.RequestOtherGroupScopes": rule}
	}
	for _, both := range []struct {
		spellings []spelling
		want      bool
	}{{trues, true}, {falses, false}} {
		for _, s := range both.spellings {
			for form, v := range map[string]any{"label": s.label, "cluster": s.cluster} {
				name := form + " " + strconv.Quote(s.label)
				got, err := Normalize(obj{"Rules.assets.Public": v})
				if err != nil {
					t.Errorf("%s: Public is refused: %v", name, err)
				} else if got.Rules[0].Public != both.want {
					t.Errorf("%s: Public is %v", name, got.Rules[0].Public)
				}

				want := map[bool]string{true: "openid x z", false: "openid x"}[both.want]
				if got, err = Normalize(scopes(v, "true")); err != nil {
					t.Errorf("%s: the group's setting is refused: %v", name, err)
				} else if required, _, _ := listsOf(t, name, got, "a"); required != want {
					t.Errorf("%s: with the group's setting, required is %q and should be %q", name, required, want)
				}
				want = map[bool]string{true: "openid x z", false: "x"}[both.want]
				if got, err = Normalize(scopes("required", v)); err != nil {
					t.Errorf("%s: the rule's setting is refused: %v", name, err)
				} else if required, _, _ := listsOf(t, name, got, "a"); required != want {
					t.Errorf("%s: with the rule's setting, required is %q and should be %q", name, required, want)
				}
			}
		}
	}
	for _, s := range trues {
		for form, v := range map[string]any{"label": s.label, "cluster": s.cluster} {
			got, err := Normalize(obj{"Scopes.admin": v, "Missing.login": v, "GroupDefaultScopes": "openid"})
			if err != nil {
				t.Errorf("%s %q, an entry: refused: %v", form, s.label, err)
			} else if required, _, r := listsOf(t, form, got, "default"); required != "admin openid" || r.Missing.Action != "login" {
				t.Errorf("%s %q, an entry: required %q, missing %q", form, s.label, required, r.Missing.Action)
			}
		}
	}
	for _, s := range refused {
		want := `Rules.assets.Public: ` + strconv.Quote(s) + ` is neither true nor false`
		if _, err := Normalize(obj{"Rules.assets.Public": s}); err == nil || err.Error() != want {
			t.Errorf("%v, and should be refused with\n%s", err, want)
		}
		want = `Scopes.admin: ` + strconv.Quote(s) + ` is neither true nor fields (a scope has name)`
		if _, err := Normalize(obj{"Scopes.admin": s}); err == nil || err.Error() != want {
			t.Errorf("%v, and should be refused with\n%s", err, want)
		}
	}
}

func encode(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func decode(t *testing.T, name, text string) any {
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("%s: %v in\n%s", name, err, text)
	}
	return v
}

// at is the part of a decoded JSON document at a path of keys and indexes; the empty path is the whole.
func at(tree any, path string) (any, bool) {
	if path == "" {
		return tree, true
	}
	for _, key := range strings.Split(path, ".") {
		switch x := tree.(type) {
		case map[string]any:
			next, ok := x[key]
			if !ok {
				return nil, false
			}
			tree = next
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			tree = x[i]
		default:
			return nil, false
		}
	}
	return tree, true
}
