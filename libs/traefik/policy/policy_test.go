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
}

const goldenPath = `{
  "groups": {"default": {"scopes": ["admin.cluster"], "requireAllScopesForAnyMember": true}},
  "rules": [
    {
      "name": "default", "priority": 3,
      "paths": ["/**"], "methods": [], "public": false,
      "scopes": [{"name": "admin.cluster", "group": "default"}], "any": [],
      "missing": {"action": "login", "scope": {"group": "default", "requireOtherGroupMembers": true}}
    }
  ]
}`

const severalRules = `{
  "groups": {"default": {"scopes": ["admin"], "requireAllScopesForAnyMember": true}},
  "rules": [
    {"name": "assets", "priority": 10, "paths": ["/assets/**"], "methods": [], "public": true, "scopes": [], "any": [],
     "missing": {"action": "deny"}},
    {"name": "admin", "priority": 9, "paths": ["/admin/**"], "methods": [], "public": false,
     "scopes": [{"name": "admin", "group": "default"}], "any": [], "missing": {"action": "deny"}},
    {"name": "rest", "priority": 3, "paths": ["/**"], "methods": [], "public": false, "scopes": [], "any": [],
     "missing": {"action": "login", "scope": {"group": "default", "requireOtherGroupMembers": true}}}
  ]
}`

// The same three rules written as a list: they are named 0, 1 and 2.
var severalRulesListed = strings.NewReplacer(
	`"name": "assets"`, `"name": "0"`, `"name": "admin", "priority"`, `"name": "1", "priority"`, `"name": "rest"`, `"name": "2"`,
).Replace(severalRules)

const priorityWritten = `[
  {"name": "writes", "priority": 100, "paths": ["/**"], "methods": ["POST", "PUT", "DELETE"], "public": false,
   "scopes": [{"name": "reports.write", "group": "default"}], "any": [], "missing": {"action": "deny"}},
  {"name": "reports", "priority": 11, "paths": ["/reports/**"], "methods": [], "public": false,
   "scopes": [{"name": "reports.read", "group": "default"}], "any": [], "missing": {"action": "deny"}}
]`

const twoGroups = `{
  "groups": {
    "users": {"scopes": ["graphql.openapi", "graphql.openapi.user", "openapi.user"], "requireAllScopesForAnyMember": true},
    "operators": {"scopes": ["admin", "admin.cluster"], "requireAllScopesForAnyMember": true}
  },
  "rules": [
    {"name": "clusters", "priority": 12, "paths": ["/clusters/**"], "methods": [], "public": false,
     "scopes": [{"name": "admin.cluster", "group": "operators"}], "any": [],
     "missing": {"action": "login", "scope": {"group": "users", "requireOtherGroupMembers": true}}},
    {"name": "rest", "priority": 3, "paths": ["/**"], "methods": [], "public": false,
     "scopes": [{"name": "openapi.user", "group": "users"}], "any": [],
     "missing": {"action": "login", "scope": {"group": "users", "requireOtherGroupMembers": true}}}
  ]
}`

// twoGroupsLabels is E6 as labels. A test that changes it takes its own copy.
func twoGroupsLabels() lbl {
	return lbl{
		"Groups.users.Scopes":                      "graphql.openapi graphql.openapi.user",
		"Groups.operators.Scopes":                  "admin",
		"Rules.clusters.Paths":                     "/clusters/**",
		"Rules.clusters.Scopes.0.name":             "admin.cluster",
		"Rules.clusters.Scopes.0.group":            "operators",
		"Rules.clusters.Missing.login.scope.group": "users",
		"Rules.rest.Scopes.0.name":                 "openapi.user",
		"Rules.rest.Scopes.0.group":                "users",
		"Rules.rest.Missing.login.scope.group":     "users",
	}
}

// twoGroupsCluster is E6 as a cluster's object, with the group operators and the login of clusters as given.
func twoGroupsCluster(operators obj, clustersLogin string) obj {
	return obj{
		"Groups": obj{
			"users":     obj{"Scopes": "graphql.openapi graphql.openapi.user"},
			"operators": operators,
		},
		"Rules": obj{
			"clusters": obj{
				"Paths":   "/clusters/**",
				"Scopes":  list{obj{"name": "admin.cluster", "group": "operators"}},
				"Missing": obj{"login": obj{"scope.group": clustersLogin}},
			},
			"rest": obj{
				"Scopes":  list{obj{"name": "openapi.user", "group": "users"}},
				"Missing": obj{"login": obj{"scope.group": "users"}},
			},
		},
	}
}

func examples() []example {
	e6Labels := twoGroupsLabels()
	e6Labels["Groups.operators.RequireAllScopesForAnyMember"] = "false"
	e6Labels["Rules.clusters.Missing.login.scope.group"] = "operators"

	const (
		scopesDefault = `[{"name": "reports.read", "group": "default"}, {"name": "reports.write", "group": "default"}]`
		scopesWriters = `[{"name": "reports.read", "group": "writers"}, {"name": "reports.write", "group": "writers"}]`
		scopesReaders = `[{"name": "admin", "group": "readers"}, {"name": "auditor", "group": "readers"}]`
		operatorScope = `[{"name": "admin.cluster", "group": "operators"}]`
		loginDefault  = `{"action": "login", "scope": {"group": "default", "requireOtherGroupMembers": true}}`
	)

	return []example{
		{
			name: "the golden path",
			forms: []form{
				labels("", lbl{"Scopes": "admin.cluster", "Missing": "login"}),
				cluster("", obj{"Scopes": "admin.cluster", "Missing": "login"}),
			},
			want: map[string]string{"": goldenPath},
		},
		{
			name: "E1 a list, five ways",
			forms: []form{
				labels("a delimited value", lbl{"Rules.reports.Paths": "/reports/**,/exports/**"}),
				labels("indexed", lbl{"Rules.reports.Paths[0]": "/reports/**", "Rules.reports.Paths[1]": "/exports/**"}),
				labels("indexed with dots", lbl{"Rules.reports.Paths.0": "/reports/**", "Rules.reports.Paths.1": "/exports/**"}),
				cluster("a list", obj{"Rules": obj{"reports": obj{"Paths": list{"/reports/**", "/exports/**"}}}}),
				cluster("a delimited value", obj{"Rules": obj{"reports": obj{"Paths": "/reports/**,/exports/**"}}}),
			},
			want: map[string]string{"rules.0.paths": `["/reports/**", "/exports/**"]`},
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
			name: "E1 a path with a comma is an entry of its own",
			forms: []form{
				labels("", lbl{"Rules.reports.Paths.0": "/reports/a,b"}),
				cluster("", obj{"Rules": obj{"reports": obj{"Paths": list{"/reports/a,b"}}}}),
			},
			want: map[string]string{"rules.0.paths": `["/reports/a,b"]`},
		},
		{
			name: "E2 scopes as values",
			forms: []form{
				labels("a delimited value", lbl{"Rules.reports.Scopes": "reports.read reports.write"}),
				labels("indexed", lbl{"Rules.reports.Scopes.0": "reports.read", "Rules.reports.Scopes.1": "reports.write"}),
				labels("indexed with brackets", lbl{"Rules.reports.Scopes[0]": "reports.read", "Rules.reports.Scopes[1]": "reports.write"}),
				cluster("a list", obj{"Rules": obj{"reports": obj{"Scopes": list{"reports.read", "reports.write"}}}}),
				cluster("a delimited value", obj{"Rules": obj{"reports": obj{"Scopes": "reports.read reports.write"}}}),
			},
			want: map[string]string{"rules.0.scopes": scopesDefault},
		},
		{
			name: "E2 scopes as entries with fields",
			forms: []form{
				labels("", lbl{
					"Rules.reports.Scopes.0.name":  "reports.read",
					"Rules.reports.Scopes.1.name":  "reports.write",
					"Rules.reports.Scopes.1.group": "writers",
				}),
				cluster("", obj{"Rules": obj{"reports": obj{"Scopes": list{
					obj{"name": "reports.read"},
					obj{"name": "reports.write", "group": "writers"},
				}}}}),
			},
			want: map[string]string{"rules.0.scopes": scopesWriters},
		},
		{
			name: "E2 scopes as keys",
			forms: []form{
				labels("", lbl{"Rules.staff.Scopes.admin": "true", "Rules.staff.Scopes.auditor.group": "readers"}),
				cluster("", obj{"Rules": obj{"staff": obj{"Scopes": obj{"admin": true, "auditor": obj{"group": "readers"}}}}}),
			},
			want: map[string]string{"rules.0.scopes": scopesReaders},
		},
		{
			name: "E2 Any as values",
			forms: []form{
				labels("a delimited value", lbl{"Rules.reports.Any": "reports.read reports.write"}),
				labels("indexed", lbl{"Rules.reports.Any.0": "reports.read", "Rules.reports.Any.1": "reports.write"}),
				cluster("a list", obj{"Rules": obj{"reports": obj{"Any": list{"reports.read", "reports.write"}}}}),
			},
			want: map[string]string{"rules.0.any": scopesDefault, "rules.0.scopes": `[]`},
		},
		{
			name: "E2 Any as entries with fields",
			forms: []form{
				labels("", lbl{
					"Rules.reports.Any.0.name":  "reports.read",
					"Rules.reports.Any.1.name":  "reports.write",
					"Rules.reports.Any.1.group": "writers",
				}),
				cluster("", obj{"Rules": obj{"reports": obj{"Any": list{
					obj{"name": "reports.read"},
					obj{"name": "reports.write", "group": "writers"},
				}}}}),
			},
			want: map[string]string{"rules.0.any": scopesWriters},
		},
		{
			name: "E2 Any as keys",
			forms: []form{
				labels("", lbl{"Rules.staff.Any.admin": "true", "Rules.staff.Any.auditor.group": "readers"}),
				cluster("", obj{"Rules": obj{"staff": obj{"Any": obj{"admin": true, "auditor": obj{"group": "readers"}}}}}),
			},
			want: map[string]string{"rules.0.any": scopesReaders},
		},
		{
			name: "E3 a scope whose name has a dot, as a value",
			forms: []form{
				labels("", lbl{"Rules.page.Scopes": "admin.cluster"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopes": "admin.cluster"}}}),
			},
			want: map[string]string{"rules.0.scopes": `[{"name": "admin.cluster", "group": "default"}]`},
		},
		{
			name: "E3 a scope whose name has a dot, as an entry's name",
			forms: []form{
				labels("indexed", lbl{"Rules.page.Scopes.0.name": "admin.cluster", "Rules.page.Scopes.0.group": "operators"}),
				labels("a key that is not the scope's", lbl{"Rules.page.Scopes.cluster.name": "admin.cluster", "Rules.page.Scopes.cluster.group": "operators"}),
				cluster("a list", obj{"Rules": obj{"page": obj{"Scopes": list{obj{"name": "admin.cluster", "group": "operators"}}}}}),
				cluster("a key that is not the scope's", obj{"Rules": obj{"page": obj{"Scopes": obj{"cluster": obj{"name": "admin.cluster", "group": "operators"}}}}}),
			},
			want: map[string]string{"rules.0.scopes": operatorScope},
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
			name: "E4 several rules, as a list",
			forms: []form{
				cluster("", obj{"Rules": list{
					obj{"Paths": "/assets/**", "Public": true},
					obj{"Paths": "/admin/**", "Scopes": "admin"},
					obj{"Missing": "login"},
				}}),
				labels("indexed", lbl{
					"Rules[0].Paths":   "/assets/**",
					"Rules[0].Public":  "true",
					"Rules[1].Paths":   "/admin/**",
					"Rules[1].Scopes":  "admin",
					"Rules[2].Missing": "login",
				}),
				labels("indexed with dots", lbl{
					"Rules.0.Paths":   "/assets/**",
					"Rules.0.Public":  "true",
					"Rules.1.Paths":   "/admin/**",
					"Rules.1.Scopes":  "admin",
					"Rules.2.Missing": "login",
				}),
			},
			want: map[string]string{"": severalRulesListed},
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
			name: "E5 a login, three ways",
			forms: []form{
				labels("a value", lbl{"Rules.page.Missing": "login"}),
				labels("a key", lbl{"Rules.page.Missing.login": "true"}),
				cluster("a value", obj{"Rules": obj{"page": obj{"Missing": "login"}}}),
				cluster("a key", obj{"Rules": obj{"page": obj{"Missing": obj{"login": true}}}}),
			},
			want: map[string]string{"rules.0.missing": loginDefault},
		},
		{
			// A login that names a group nobody defined is refused, so the group is defined here: by Groups.
			name: "E5 a named action, bound to a group",
			forms: []form{
				labels("", lbl{
					"Groups.operators.Scopes":                            "admin",
					"Rules.page.Missing.login-for-operators.action":      "login",
					"Rules.page.Missing.login-for-operators.scope.group": "operators",
				}),
				cluster("", obj{
					"Groups": obj{"operators": obj{"Scopes": "admin"}},
					"Rules": obj{"page": obj{"Missing": obj{
						"login-for-operators": obj{"action": "login", "scope.group": "operators"},
					}}},
				}),
			},
			want: map[string]string{"rules.0.missing": `{"action": "login", "scope": {"group": "operators", "requireOtherGroupMembers": true}}`},
		},
		{
			name: "E5 a login due only when a scope the rule needs is missing",
			forms: []form{
				labels("", lbl{"Rules.page.Missing.login.scope.requireOtherGroupMembers": "false"}),
				cluster("a dotted key", obj{"Rules": obj{"page": obj{"Missing": obj{"login": obj{"scope.requireOtherGroupMembers": false}}}}}),
				cluster("nested", obj{"Rules": obj{"page": obj{"Missing": obj{"login": obj{"scope": obj{"requireOtherGroupMembers": false}}}}}}),
			},
			want: map[string]string{"rules.0.missing": `{"action": "login", "scope": {"group": "default", "requireOtherGroupMembers": false}}`},
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
			name: "E6 two groups",
			forms: []form{
				labels("", twoGroupsLabels()),
				cluster("", twoGroupsCluster(obj{"Scopes": "admin"}, "users")),
			},
			want: map[string]string{"": twoGroups},
		},
		{
			name: "E6 a group that says it for every login that names it",
			forms: []form{
				labels("", e6Labels),
				cluster("", twoGroupsCluster(obj{"Scopes": "admin", "RequireAllScopesForAnyMember": false}, "operators")),
			},
			want: map[string]string{
				"groups.operators": `{"scopes": ["admin", "admin.cluster"], "requireAllScopesForAnyMember": false}`,
				"rules.0.name":     `"clusters"`,
				"rules.0.missing":  `{"action": "login", "scope": {"group": "operators", "requireOtherGroupMembers": false}}`,
			},
		},
	}
}

func TestExamples(t *testing.T) {
	for _, ex := range examples() {
		for _, f := range ex.forms {
			name := ex.name + " (" + strings.TrimSuffix(f.name, ", ") + ")"
			got, err := Normalize(f.settings)
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

// refusals are the rows of "What is refused": what is written, and what the Middleware says.
func refusals() []example {
	return []example{
		{
			name: `Rules.page: unknown key "Scopse" (a rule has Paths, Methods, Public, Scopes, Any, Missing, Priority)`,
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
			name: `Rules.page: a public rule has no scopes`,
			forms: []form{
				labels("", lbl{"Rules.page.Public": "true", "Rules.page.Scopes": "admin"}),
				cluster("", obj{"Rules": obj{"page": obj{"Public": true, "Scopes": "admin"}}}),
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
			name: `Rules.page.Scopes.x: unknown key "nam" (a scope has name, group)`,
			forms: []form{
				labels("", lbl{"Rules.page.Scopes.x.nam": "admin"}),
				cluster("", obj{"Rules": obj{"page": obj{"Scopes": obj{"x": obj{"nam": "admin"}}}}}),
			},
		},
		{
			name: `Rules.page.Scopes.admin: unknown key "cluster" (a scope has name, group); a name with a dot is a value, or an entry's name`,
			forms: []form{
				labels("", lbl{"Rules.page.Scopes.admin.cluster": "true"}),
				cluster("a dotted key", obj{"Rules": obj{"page": obj{"Scopes": obj{"admin.cluster": true}}}}),
				cluster("nested", obj{"Rules": obj{"page": obj{"Scopes": obj{"admin": obj{"cluster": true}}}}}),
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
			name: `Rules.page.Scopes: a scope names its group where there are several groups (operators, users)`,
			forms: []form{
				labels("", severalGroups(lbl{"Rules.page.Scopes": "admin"})),
				cluster("", severalGroupsCluster(obj{"page": obj{"Scopes": "admin"}})),
			},
		},
		{
			name: `Rules.page.Missing: a login names its scope.group where there are several groups (operators, users)`,
			forms: []form{
				labels("", severalGroups(lbl{"Rules.page.Missing": "login"})),
				cluster("", severalGroupsCluster(obj{"page": obj{"Missing": "login"}})),
			},
		},
		{
			name: `Rules.page.Missing.login.scope.group: no group "staff" (operators, users)`,
			forms: []form{
				labels("", severalGroups(lbl{"Rules.page.Missing.login.scope.group": "staff"})),
				cluster("", severalGroupsCluster(obj{"page": obj{"Missing": obj{"login": obj{"scope.group": "staff"}}}})),
			},
		},
	}
}

func TestRefusals(t *testing.T) {
	for _, row := range refusals() {
		for _, f := range row.forms {
			got, err := Normalize(f.settings)
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
	for _, c := range []struct {
		name string
		in   obj
		want string
	}{
		{"no rule's field and no Rules is no rule", obj{}, `{"groups":{},"rules":[]}`},
		{"a setting that is nil is not written", obj{"Rules": nil, "Groups": nil, "Paths": nil}, `{"groups":{},"rules":[]}`},
		{"a scope without a key writes its name", obj{"Scopes": list{obj{"group": "writers"}}},
			`Scopes.0: a scope without a key writes its name`},
		{"an empty value is refused", obj{"Scopes": ""}, `Scopes: an empty value`},
		{"a deny has no scope", obj{"Missing": obj{"deny": obj{"scope.group": "users"}}, "Groups": obj{"users": true}},
			`Missing.deny.scope: only a login has a scope`},
		{"a key in another case is the same key", obj{"scopes": "admin", "Scopes": "admin"},
			`"Scopes" and "scopes" are the same key`},
		{"a login that names a group where none is defined", obj{"Missing": obj{"login": obj{"scope.group": "staff"}}},
			`Missing.login.scope.group: no group "staff" (none is defined)`},
		{"an unknown key at the top", obj{"Rule": obj{}},
			`unknown key "Rule" (a policy has Rules, Groups, Paths, Methods, Public, Scopes, Any, Missing, Priority)`},
	} {
		if got := read(c.in); got != c.want {
			t.Errorf("%s:\n%s\nand should be\n%s", c.name, got, c.want)
		}
	}
}

// Keys are read without regard to case (G8), and an action written as a key too.
func TestCase(t *testing.T) {
	lower, err := Normalize(fromLabels(lbl{
		"rules.page.scopes": "admin.cluster",
		"rules.page.missing.Login.SCOPE.requireothergroupmembers": "false",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"groups":{"default":{"scopes":["admin.cluster"],"requireAllScopesForAnyMember":true}},"rules":[{"name":"page","priority":3,"paths":["/**"],"methods":[],"public":false,"scopes":[{"name":"admin.cluster","group":"default"}],"any":[],"missing":{"action":"login","scope":{"group":"default","requireOtherGroupMembers":false}}}]}`
	if got := encode(t, lower); got != want {
		t.Errorf("got\n%s\nand should be\n%s", got, want)
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
