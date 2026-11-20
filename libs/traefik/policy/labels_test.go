package policy

import (
	"sort"
	"strings"
)

// fromLabels is what Traefik hands a plugin for settings written as labels: the labels' keys are the part after
// "traefik.http.middlewares.<name>.plugin.policy.". It does what Traefik's label parser does (paerser v0.2.2, as
// Traefik v3.7.18 uses it for a plugin's free-form settings):
//
//   - a key is split at every dot, and "name[0]" is the part "name" and the index "[0]";
//   - the keys are taken in alphabetical order, and a part is matched without regard to case, its first spelling
//     kept;
//   - every value is text;
//   - a part whose first child is an index becomes a list of its children, in their order; a part with other
//     children becomes a map, and a value written on that same part is dropped.
func fromLabels(labels map[string]string) map[string]any {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	root := &labelNode{}
	for _, key := range keys {
		var parts []string
		for _, part := range strings.Split(key, ".") {
			if strings.HasSuffix(part, "]") && part[0] != '[' {
				at := strings.Index(part, "[")
				parts = append(parts, part[:at], part[at:])
			} else {
				parts = append(parts, part)
			}
		}
		node := root
		for _, part := range parts {
			node = node.child(part)
		}
		node.value = labels[key]
	}

	settings := map[string]any{}
	for _, child := range root.children {
		settings[child.name] = child.raw()
	}
	return settings
}

type labelNode struct {
	name     string
	value    string
	children []*labelNode
}

func (n *labelNode) child(name string) *labelNode {
	for _, child := range n.children {
		if strings.EqualFold(child.name, name) {
			return child
		}
	}
	child := &labelNode{name: name}
	n.children = append(n.children, child)
	return child
}

func (n *labelNode) raw() any {
	if len(n.children) == 0 {
		return n.value
	}
	first := n.children[0].name
	if strings.HasPrefix(first, "[") && strings.HasSuffix(first, "]") {
		list := make([]any, 0, len(n.children))
		for _, child := range n.children {
			list = append(list, child.raw())
		}
		return list
	}
	m := map[string]any{}
	for _, child := range n.children {
		m[child.name] = child.raw()
	}
	return m
}
