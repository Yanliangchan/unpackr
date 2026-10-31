package confidence

import (
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

func sig(strength, family string) models.Signal {
	return models.Signal{ID: family, Strength: strength, Family: family}
}

func TestRubric(t *testing.T) {
	cases := []struct {
		name   string
		sigs   []models.Signal
		contra int
		want   models.Confidence
	}{
		{"none", nil, 0, models.ConfidenceSpeculative},
		{"weak only", []models.Signal{sig("weak", "a"), sig("weak", "b")}, 0, models.ConfidenceSpeculative},
		{"single moderate", []models.Signal{sig("moderate", "a")}, 0, models.ConfidenceLow},
		{"same family twice counts once", []models.Signal{sig("moderate", "a"), sig("moderate", "a")}, 0, models.ConfidenceLow},
		{"two independent moderate", []models.Signal{sig("moderate", "a"), sig("moderate", "b")}, 0, models.ConfidenceMedium},
		{"strong alone", []models.Signal{sig("strong", "a")}, 0, models.ConfidenceMedium},
		{"strong plus weak other family", []models.Signal{sig("strong", "a"), sig("weak", "b")}, 0, models.ConfidenceHigh},
		{"strong twice same family", []models.Signal{sig("strong", "a"), sig("strong", "a")}, 0, models.ConfidenceMedium},
		{"three moderate families", []models.Signal{sig("moderate", "a"), sig("moderate", "b"), sig("moderate", "c")}, 0, models.ConfidenceHigh},
		{"contradiction lowers one step", []models.Signal{sig("strong", "a"), sig("moderate", "b")}, 1, models.ConfidenceMedium},
		{"cannot go below speculative", []models.Signal{sig("weak", "a")}, 5, models.ConfidenceSpeculative},
	}
	for _, c := range cases {
		got, why := Derive(c.sigs, c.contra)
		if got != c.want || why == "" {
			t.Errorf("%s: got %s (%q), want %s", c.name, got, why, c.want)
		}
	}
}

func TestNeverDefinitive(t *testing.T) {
	var sigs []models.Signal
	for _, f := range []string{"a", "b", "c", "d", "e"} {
		sigs = append(sigs, sig("strong", f))
	}
	if got, _ := Derive(sigs, 0); got == models.ConfidenceDefinitive {
		t.Fatal("definitive must be reserved for validated artifacts")
	}
}
