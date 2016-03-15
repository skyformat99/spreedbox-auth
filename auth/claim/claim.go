package claim

type Claim struct {
	ID    string
	Value interface{}
}

func New(id string, value interface{}) *Claim {
	return &Claim{
		ID:    id,
		Value: value,
	}
}

func (c *Claim) Add(requiredClaims map[string]interface{}) {
	requiredClaims[c.ID] = c.Value
}
