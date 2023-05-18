package p2p

type ID struct {
	ns  string
	key string
}

func NewID(ns string, key string) ID {
	return ID{ns: ns, key: key}
}

// Returns the full ID serialized as a string
func (id ID) String() string {
	return ""
}

// Returns the `/<namspace>/<service>` pair as a string
func (id ID) ServiceNamespace() string {
	return ""
}

// Returns the `<key>` as a string
func (id ID) Key() string {
	return ""
}
