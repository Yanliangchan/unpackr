package reporting_test

import (
	"github.com/Yanliangchan/unpackr/internal/comparison"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

func comparisonDiff(a, b *models.Report) *models.Comparison { return comparison.Diff(a, b) }
