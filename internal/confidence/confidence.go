// Package confidence derives an ordinal confidence from a set of signals. The
// rubric is deliberately small and mechanical so that every confidence level
// shown to an analyst can be explained and tested.
//
//	Strength  strong   exact, hard-to-fake marker (magic bytes, build info)
//	          moderate structural property or specific string
//	          weak     renamable or common property (section name, rwx flag)
//
//	Independent families = distinct Family values. Two signals in the same
//	family (for example two matches on the same bytes) count once.
//
//	high         a strong signal corroborated by at least one other family,
//	             or three or more independent families with a moderate signal
//	medium       a strong signal alone, or two independent moderate families
//	low          a single moderate signal
//	speculative  weak signals only
//
// A contradiction lowers the result one step. "Definitive" is never produced
// here: it is reserved for results proven by a validated artifact such as a
// successful unpack.
package confidence

import (
	"fmt"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Strength of one signal.
type Strength int

const (
	Weak Strength = iota
	Moderate
	Strong
)

func (s Strength) String() string { return [...]string{"weak", "moderate", "strong"}[s] }

// Parse converts the model string back to a Strength.
func Parse(s string) Strength {
	switch s {
	case "strong":
		return Strong
	case "moderate":
		return Moderate
	}
	return Weak
}

var order = []models.Confidence{models.ConfidenceSpeculative, models.ConfidenceLow, models.ConfidenceMedium, models.ConfidenceHigh}

func step(c models.Confidence, down int) models.Confidence {
	i := 0
	for j, o := range order {
		if o == c {
			i = j
		}
	}
	if i -= down; i < 0 {
		i = 0
	}
	return order[i]
}

// Derive returns the confidence and a one-line reason.
func Derive(sigs []models.Signal, contradictions int) (models.Confidence, string) {
	if len(sigs) == 0 {
		return models.ConfidenceSpeculative, "no supporting signals"
	}
	families := map[string]bool{}
	best := Weak
	moderateFamilies := map[string]bool{}
	for _, s := range sigs {
		families[s.Family] = true
		st := Parse(s.Strength)
		if st > best {
			best = st
		}
		if st >= Moderate {
			moderateFamilies[s.Family] = true
		}
	}
	n := len(families)
	var c models.Confidence
	var why string
	switch {
	case best == Strong && n >= 2:
		c, why = models.ConfidenceHigh, "a strong signal corroborated by an independent one"
	case best >= Moderate && len(moderateFamilies) >= 3:
		c, why = models.ConfidenceHigh, "three independent lines of evidence"
	case best == Strong:
		c, why = models.ConfidenceMedium, "a strong signal without independent corroboration"
	case len(moderateFamilies) >= 2:
		c, why = models.ConfidenceMedium, "two independent moderate signals"
	case best == Moderate:
		c, why = models.ConfidenceLow, "a single moderate signal"
	default:
		c, why = models.ConfidenceSpeculative, "weak signals only"
	}
	if contradictions > 0 {
		c = step(c, contradictions)
		why += fmt.Sprintf("; lowered for %d contradicting observation(s)", contradictions)
	}
	return c, why
}

// Lower returns c reduced by n steps, never below speculative.
func Lower(c models.Confidence, n int) models.Confidence { return step(c, n) }
