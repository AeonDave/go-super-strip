package common

import "fmt"

type StepFunc func() (*OperationResult, error)

type Pipeline struct {
	steps []pipelineStep
}

type pipelineStep struct {
	name string
	fn   StepFunc
}

func NewPipeline() *Pipeline {
	return &Pipeline{
		steps: make([]pipelineStep, 0, 4),
	}
}

func (p *Pipeline) AddStep(name string, fn StepFunc) {
	p.steps = append(p.steps, pipelineStep{name: name, fn: fn})
}

func (p *Pipeline) Execute(aggregate *OperationResult) error {
	for _, step := range p.steps {
		res, err := step.fn()
		if err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		if aggregate == nil || res == nil {
			continue
		}
		if res.Applied {
			aggregate.Applied = true
			aggregate.Count += res.Count
			if res.Message != "" {
				aggregate.AddDetail(fmt.Sprintf("%s: %s", step.name, res.Message), res.Count, false)
			}
			for _, detail := range res.Details {
				aggregate.AddDetail(detail.Message, detail.Count, detail.IsRisky)
			}
		} else if res.Message != "" {
			aggregate.AddDetail(fmt.Sprintf("%s: %s", step.name, res.Message), 0, false)
		}
	}
	return nil
}
