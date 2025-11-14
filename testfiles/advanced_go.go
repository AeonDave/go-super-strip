package main

import (
	"fmt"
	"math"
	"sort"
	"sync"
)

type measurement struct {
	label string
	value float64
}

type aggregator struct {
	mu        sync.Mutex
	readings  []measurement
	frequency map[string]int
}

func newAggregator() *aggregator {
	return &aggregator{
		readings:  make([]measurement, 0, 32),
		frequency: make(map[string]int),
	}
}

func (a *aggregator) add(label string, value float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readings = append(a.readings, measurement{label: label, value: value})
	a.frequency[label]++
}

func (a *aggregator) summary() ([]measurement, map[string]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	clone := make([]measurement, len(a.readings))
	copy(clone, a.readings)
	freq := make(map[string]int, len(a.frequency))
	for k, v := range a.frequency {
		freq[k] = v
	}
	sort.Slice(clone, func(i, j int) bool {
		if clone[i].label == clone[j].label {
			return clone[i].value < clone[j].value
		}
		return clone[i].label < clone[j].label
	})
	return clone, freq
}

type stats struct {
	min   float64
	max   float64
	mean  float64
	stdev float64
}

func computeStats(values []float64) stats {
	if len(values) == 0 {
		return stats{}
	}
	minVal, maxVal := values[0], values[0]
	total := 0.0
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
		total += v
	}
	mean := total / float64(len(values))
	variance := 0.0
	for _, v := range values {
		variance += math.Pow(v-mean, 2)
	}
	variance /= float64(len(values))
	return stats{min: minVal, max: maxVal, mean: mean, stdev: math.Sqrt(variance)}
}

func processSeries(wg *sync.WaitGroup, agg *aggregator, label string, values []float64) {
	defer wg.Done()
	for _, v := range values {
		agg.add(label, v)
	}
}

func main() {
	data := map[string][]float64{
		"temperature": {23.5, 24.0, 23.8, 25.1, 22.9},
		"pressure":    {1012.0, 1011.8, 1012.4, 1013.2},
		"humidity":    {45.0, 47.5, 50.1, 48.3},
	}

	agg := newAggregator()
	var wg sync.WaitGroup
	for label, series := range data {
		wg.Add(1)
		go processSeries(&wg, agg, label, series)
	}
	wg.Wait()

	readings, freq := agg.summary()
	fmt.Println("Collected readings (sorted):")
	for _, r := range readings {
		fmt.Printf("  %-12s -> %.2f\n", r.label, r.value)
	}
	fmt.Println("Frequency per series:")
	for label, count := range freq {
		fmt.Printf("  %-12s -> %d\n", label, count)
	}

	fmt.Println("Computed statistics:")
	for label, series := range data {
		s := computeStats(series)
		fmt.Printf("  %-12s -> min=%.2f max=%.2f mean=%.2f stdev=%.2f\n",
			label, s.min, s.max, s.mean, s.stdev)
	}
}
