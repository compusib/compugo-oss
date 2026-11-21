package settings

import (
	"fmt"
	"strings"
	"testing"
)

// A description as a plugin writes one: servers that are named entries, each with a list, a number, a switch,
// tags that may be written as values, and an object.
var (
	tagType = &Type{What: "a tag", Key: "name", Fields: []Field{
		{Name: "name", Kind: Text},
		{Name: "color", Kind: Text, Default: "grey"},
	}}
	limitsType = &Type{What: "the limits", Fields: []Field{
		{Name: "burst", Kind: Number},
	}}
	serverType = &Type{What: "a server", Fields: []Field{
		{Name: "Hosts", Kind: List, Delimiter: ","},
		{Name: "Weight", Kind: Number},
		{Name: "Enabled", Kind: Bool, Default: true},
		{Name: "Tags", Kind: Entries, Delimiter: " ", Of: tagType},
		{Name: "Limits", Kind: Object, Of: limitsType},
	}}
	pluginType = &Type{What: "the plugin", Fields: []Field{
		{Name: "Servers", Kind: Entries, Of: serverType},
		{Name: "Title", Kind: Text},
	}}
)

// show writes an entry out, so that two readings can be compared.
func show(t *Type, e *Entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s{", e.Name)
	for _, f := range t.Fields {
		if !e.Written(f.Name) {
			b.WriteString("~")
		}
		fmt.Fprintf(&b, "%s=", f.Name)
		switch f.Kind {
		case Text:
			b.WriteString(e.Text(f.Name))
		case Bool:
			fmt.Fprint(&b, e.Bool(f.Name))
		case Number:
			fmt.Fprint(&b, e.Number(f.Name))
		case List:
			fmt.Fprintf(&b, "%q", e.List(f.Name))
		case Entries:
			b.WriteString("[")
			for _, sub := range e.Entries(f.Name) {
				b.WriteString(show(f.Of, sub))
			}
			b.WriteString("]")
		case Object:
			if sub := e.Object(f.Name); sub != nil {
				b.WriteString(show(f.Of, sub))
			}
		}
		b.WriteString(" ")
	}
	b.WriteString("}")
	return b.String()
}

func TestForms(t *testing.T) {
	const want = `{Servers=[a{Hosts=["x" "y"] Weight=10 ~Enabled=true Tags=[blue{~name=blue ~color=grey }red{~name=red color=dark }] Limits=Limits{burst=5 } }] ~Title= }`
	forms := map[string]map[string]any{
		"labels": {"Servers": map[string]any{"a": map[string]any{
			"Hosts": "x,y", "Weight": "10",
			"Tags":   map[string]any{"blue": "true", "red": map[string]any{"color": "dark"}},
			"Limits": map[string]any{"burst": "5"},
		}}},
		"a cluster's types": {"Servers": map[string]any{"a": map[string]any{
			"Hosts": []any{"x", "y"}, "Weight": float64(10),
			"Tags":   map[string]any{"blue": true, "red": map[string]any{"color": "dark"}},
			"Limits": map[string]any{"burst": 5},
		}}},
		"dotted keys": {"Servers.a.Hosts.0": "x", "Servers.a.Hosts.1": "y", "Servers.a.Weight": int64(10),
			"Servers.a.Tags.blue": true, "Servers.a.Tags.red.color": "dark", "Servers.a.Limits.burst": "5"},
		"another case": {"servers": map[string]any{"a": map[string]any{
			"HOSTS": " x , y ", "weight": "10",
			"tags":   map[string]any{"blue": "TRUE", "red": map[string]any{"COLOR": "dark"}},
			"limits": map[string]any{"Burst": "5"},
		}}},
	}
	for name, raw := range forms {
		e, err := Read(pluginType, raw)
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if got := show(pluginType, e); got != want {
			t.Errorf("%s:\n%s\nand should be\n%s", name, got, want)
		}
	}
}

func TestEntryForms(t *testing.T) {
	const want = `{Servers=[a{~Hosts=[] ~Weight=0 ~Enabled=true Tags=[blue{~name=blue ~color=grey }red{~name=red ~color=grey }] ~Limits= }] ~Title= }`
	for name, tags := range map[string]any{
		"a delimited value": "blue red",
		"a list":            []any{"blue", "red"},
		"indexed":           map[string]any{"0": "blue", "1": "red"},
		"indexed, fields":   map[string]any{"0": map[string]any{"name": "blue"}, "1": map[string]any{"name": "red"}},
		"a list, fields":    []any{map[string]any{"name": "blue"}, "red"},
		"keys":              map[string]any{"red": true, "blue": "true"},
		"keys, a name":      map[string]any{"a": map[string]any{"name": "blue"}, "b": map[string]any{"name": "red"}},
	} {
		e, err := Read(pluginType, map[string]any{"Servers": map[string]any{"a": map[string]any{"Tags": tags}}})
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		got := show(pluginType, e)
		// Written as a field, the name is written; everywhere else it is the entry's name.
		got = strings.ReplaceAll(got, "a{name=blue", "blue{~name=blue")
		got = strings.ReplaceAll(got, "b{name=red", "red{~name=red")
		got = strings.ReplaceAll(got, "0{name=blue", "blue{~name=blue")
		got = strings.ReplaceAll(got, "1{name=red", "red{~name=red")
		if got != want {
			t.Errorf("%s:\n%s\nand should be\n%s", name, got, want)
		}
	}
}

func TestIndexOrder(t *testing.T) {
	e, err := Read(pluginType, map[string]any{"Servers.a.Hosts": map[string]any{"10": "c", "2": "b", "0": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.Entries("Servers")[0].List("Hosts"), ""); got != "abc" {
		t.Errorf("the list is %q and should be in the order of its indexes", got)
	}
}

func TestRefused(t *testing.T) {
	for want, raw := range map[string]map[string]any{
		`unknown key "Server" (the plugin has Servers, Title)`:                                                              {"Server": "x"},
		`Servers.a: unknown key "Host" (a server has Hosts, Weight, Enabled, Tags, Limits)`:                                 {"Servers.a.Host": "x"},
		`Servers: indexed and named entries cannot be mixed`:                                                                {"Servers.0.Hosts": "x", "Servers.a.Hosts": "y"},
		`Servers.a.Hosts: indexed and named entries cannot be mixed`:                                                        {"Servers.a.Hosts.0": "x", "Servers.a.Hosts.b": "y"},
		`Servers.a.Hosts: unknown key "b" (a list has values or indexed entries)`:                                           {"Servers.a.Hosts.b": "y"},
		`Servers.a.Hosts.0: unknown key "b" (it is one value)`:                                                              {"Servers.a.Hosts.0.b": "y"},
		`Servers.a.Hosts: an empty value`:                                                                                   {"Servers.a.Hosts": " , "},
		`Servers.a.Weight: "heavy" is no number`:                                                                            {"Servers.a.Weight": "heavy"},
		`Servers.a.Enabled: "yes" is neither true nor false`:                                                                {"Servers.a.Enabled": "yes"},
		`Servers: "a" is no entry (a server has Hosts, Weight, Enabled, Tags, Limits)`:                                      {"Servers": "a"},
		`Servers.a: "on" is neither true nor fields (a server has Hosts, Weight, Enabled, Tags, Limits)`:                    {"Servers.a": "on"},
		`Servers.a.Tags.blue: unknown key "colour" (a tag has name, color)`:                                                 {"Servers.a.Tags.blue.colour": "dark"},
		`Servers.a.Tags.dark: unknown key "blue" (a tag has name, color); a name with a dot is a value, or an entry's name`: {"Servers.a.Tags.dark.blue": true},
		`Servers.a.Tags.0: a tag without a key writes its name`:                                                             {"Servers.a.Tags.0.color": "dark"},
		`Servers.a.Limits: the limits is written with its fields (burst)`:                                                   {"Servers.a.Limits": "5"},
		`Servers: "A" and "a" are the same key`:                                                                             {"Servers": map[string]any{"A": true, "a": true}},
		`the key "Title" is written twice`:                                                                                  {"Title": "x", "Title.y": "z"},
		`Servers: the key ".a" has an empty part`:                                                                           {"Servers..a": true},
		`Title: one value, not a list`:                                                                                      {"Title": []any{"x"}},
		`Title: an empty value`:                                                                                             {"Title": ""},
	} {
		_, err := Read(pluginType, raw)
		if err == nil {
			t.Errorf("not refused, and should be with\n%s", want)
			continue
		}
		if err.Error() != want {
			t.Errorf("refused with\n%s\nand should be with\n%s", err, want)
		}
	}
}

// A boolean is read as Traefik reads a label's: strconv.ParseBool. Each spelling is tried as a field's value and
// as the bare true of an entry (G5), from a label's text and from a cluster's value.
func TestBooleans(t *testing.T) {
	type row struct {
		written any
		refused bool
		value   bool
	}
	var rows []row
	for _, s := range []string{"1", "t", "T", "true", "True", "TRUE"} {
		rows = append(rows, row{written: s, value: true})
	}
	for _, s := range []string{"0", "f", "F", "false", "False", "FALSE"} {
		rows = append(rows, row{written: s, value: false})
	}
	for _, s := range []string{"yes", "on", "tRuE", "fALSE", "2", ""} {
		rows = append(rows, row{written: s, refused: true})
	}
	// A cluster's boolean is read as it is, and its number as the text a label would have had.
	rows = append(rows,
		row{written: true, value: true}, row{written: false, value: false},
		row{written: 1, value: true}, row{written: 0, value: false},
		row{written: int64(1), value: true}, row{written: float64(0), value: false},
		row{written: 2, refused: true}, row{written: float64(0.5), refused: true},
	)
	for _, r := range rows {
		e, err := Read(pluginType, map[string]any{"Servers.a.Enabled": r.written})
		switch {
		case r.refused:
			want := fmt.Sprintf(`Servers.a.Enabled: "%v" is neither true nor false`, r.written)
			if err == nil || err.Error() != want {
				t.Errorf("the field written %#v: %v, and should be refused with\n%s", r.written, err, want)
			}
		case err != nil:
			t.Errorf("the field written %#v is refused: %v", r.written, err)
		default:
			if got := e.Entries("Servers")[0].Bool("Enabled"); got != r.value {
				t.Errorf("the field written %#v is %v", r.written, got)
			}
		}

		// An entry is there by a true alone: a false is no entry, and is refused as anything else is.
		e, err = Read(pluginType, map[string]any{"Servers.a.Tags.blue": r.written})
		if r.refused || !r.value {
			want := fmt.Sprintf(`Servers.a.Tags.blue: "%v" is neither true nor fields (a tag has name, color)`, r.written)
			if err == nil || err.Error() != want {
				t.Errorf("the entry written %#v: %v, and should be refused with\n%s", r.written, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("the entry written %#v is refused: %v", r.written, err)
			continue
		}
		if tags := e.Entries("Servers")[0].Entries("Tags"); len(tags) != 1 || tags[0].Name != "blue" {
			t.Errorf("the entry written %#v is not the entry with its defaults", r.written)
		}
	}
}

// Entries with members: a host's ports are open or closed, and a port written without either is open.
var (
	portType = &Type{What: "a port", Key: "name", Fields: []Field{{Name: "name", Kind: Text}}}
	hostType = &Type{What: "a host", Fields: []Field{
		{Name: "Ports", Kind: Entries, Delimiter: " ", Of: portType, Members: []string{"open", "closed"}},
		{Name: "Spare", Kind: Entries, Delimiter: " ", Of: portType, Members: []string{"open", "closed"},
			Default: map[string]any{"open": "http", "closed": "smtp imap"}},
	}}
)

func TestMembers(t *testing.T) {
	names := func(e *Entry, field, member string) string {
		var names []string
		for _, p := range e.Member(field, member) {
			names = append(names, p.Text("name"))
		}
		return strings.Join(names, " ")
	}
	for name, c := range map[string]struct {
		ports        any
		open, closed string
	}{
		"without a member, the first":  {"http https", "http https", ""},
		"a list without a member":      {[]any{"http", map[string]any{"name": "https"}}, "http https", ""},
		"keys without a member":        {map[string]any{"http": true, "web": map[string]any{"name": "https"}}, "http https", ""},
		"indexes without a member":     {map[string]any{"0": "http", "1": "https"}, "http https", ""},
		"both members":                 {map[string]any{"open": "http", "closed": []any{"smtp", "imap"}}, "http", "smtp imap"},
		"one member":                   {map[string]any{"closed": map[string]any{"smtp": true}}, "", "smtp"},
		"a member in another case":     {map[string]any{"CLOSED": map[string]any{"0": map[string]any{"name": "smtp"}}}, "", "smtp"},
		"a member's name as a value":   {"open closed", "open closed", ""},
		"a member's name under itself": {map[string]any{"open": map[string]any{"open": true}}, "open", ""},
		"an empty list":                {[]any{}, "", ""},
	} {
		e, err := Read(hostType, map[string]any{"Ports": c.ports})
		if err != nil {
			t.Errorf("%s: refused: %v", name, err)
			continue
		}
		if open, closed := names(e, "Ports", "open"), names(e, "Ports", "closed"); open != c.open || closed != c.closed {
			t.Errorf("%s: open %q, closed %q, and should be %q and %q", name, open, closed, c.open, c.closed)
		}
		if !e.Written("Ports") || e.Written("Spare") {
			t.Errorf("%s: Ports is written and Spare is not", name)
		}
		if open, closed := names(e, "Spare", "open"), names(e, "Spare", "closed"); open != "http" || closed != "smtp imap" {
			t.Errorf("%s: the default is open %q, closed %q", name, open, closed)
		}
	}
	e, err := Read(hostType, map[string]any{"Ports.closed.0": "smtp", "Ports.OPEN.http": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if open, closed := names(e, "Ports", "open"), names(e, "Ports", "closed"); open != "http" || closed != "smtp" {
		t.Errorf("dotted keys: open %q, closed %q", open, closed)
	}

	for want, raw := range map[string]map[string]any{
		`Ports: open and closed cannot be mixed with other entries`:                                                {"Ports.open": "http", "Ports.smtp": true},
		`Ports.closed: an empty value`:                                                                             {"Ports.closed": ""},
		`Ports.closed.smtp: unknown key "tls" (a port has name); a name with a dot is a value, or an entry's name`: {"Ports.closed.smtp.tls": true},
		`Ports.0: unknown key "open" (a port has name)`:                                                            {"Ports": []any{map[string]any{"open": "http"}}},
	} {
		_, err := Read(hostType, raw)
		if err == nil || err.Error() != want {
			t.Errorf("%v\nand should be refused with\n%s", err, want)
		}
	}
	if _, err := Read(hostType, map[string]any{"Ports.open": "http", "Ports.0": "smtp"}); err == nil ||
		err.Error() != `Ports: open and closed cannot be mixed with other entries` {
		t.Errorf("an index beside a member: %v", err)
	}
}

// The hint about a name with a dot is for a key that leads to a true: the rest of such a name written as a key.
func TestHint(t *testing.T) {
	const hint = `; a name with a dot is a value, or an entry's name`
	for want, raw := range map[string]map[string]any{
		`Ports.a: unknown key "b" (a port has name)` + hint: {"Ports.a.b": true},
		`Ports.a: unknown key "b" (a port has name)`:        {"Ports.a.b": "x"},
	} {
		if _, err := Read(hostType, raw); err == nil || err.Error() != want {
			t.Errorf("%v\nand should be\n%s", err, want)
		}
	}
	// A name with two dots leads to a true further down; a field of something else does not.
	if _, err := Read(hostType, map[string]any{"Ports.a.b.c": "1"}); err == nil || !strings.HasSuffix(err.Error(), hint) {
		t.Errorf("a name with two dots: %v", err)
	}
	if _, err := Read(hostType, map[string]any{"Ports.a.b.c": "x"}); err == nil || strings.HasSuffix(err.Error(), hint) {
		t.Errorf("a field of a field: %v", err)
	}
}
