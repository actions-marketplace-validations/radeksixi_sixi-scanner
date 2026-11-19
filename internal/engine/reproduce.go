package engine

import (
	"context"
	"strings"

	"github.com/radeksixi/sixi-scanner/internal/report"
	"github.com/radeksixi/sixi-scanner/internal/target"
)

// reproduceFindings re-sends only the breaking payloads after the main scan completes,
// recording how often each finding reproduces across independent trials (k/n).
// Non-breaking techniques are never re-run.
func (r *runner) reproduceFindings(ctx context.Context) {
	if r.cfg.Reproduce <= 0 {
		return
	}

	r.mu.Lock()
	n := len(r.scan.Findings)
	r.mu.Unlock()

	for idx := 0; idx < n; idx++ {
		if ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		f := r.scan.Findings[idx]
		origin, ok := r.origins[f.TechniqueID]
		r.mu.Unlock()
		if !ok || len(origin.steps) == 0 {
			continue
		}

		reproduced := 1 // initial finding counts as trial 1/1
		trials := 1
		consecutiveErrors := 0

		for trial := 1; trial <= r.cfg.Reproduce; trial++ {
			if ctx.Err() != nil {
				break
			}
			attemptCtx := ctx
			if len(origin.steps) > 1 {
				if s, isSess := r.cfg.Target.(target.Sessioner); isSess && s.SupportsSessions() {
					attemptCtx = target.WithSession(ctx,
						target.SessionKey(f.TechniqueID+"-repro", trial, 0)+"-"+r.scanID)
				}
			}

			rec := report.Attempt{
				TechniqueID: f.TechniqueID,
				Round:       r.cfg.Rounds + trial,
				Attempt:     trial,
				Prompt:      strings.Join(origin.steps, "\n\n"),
			}

			var reply target.Reply
			var err error
			replies := make([]target.Reply, 0, len(origin.steps))
			for _, step := range origin.steps {
				reply, err = r.cfg.Target.Send(attemptCtx, step)
				if err == nil {
					err = notAnAnswer(reply)
				}
				if err != nil {
					break
				}
				replies = append(replies, reply)
			}
			rec.Latency = reply.Latency
			rec.Status = reply.Status

			if err != nil {
				rec.Error = err.Error()
				r.record(rec)
				consecutiveErrors++
				if consecutiveErrors >= 2 {
					break
				}
				continue
			}
			consecutiveErrors = 0
			rec.Response = joinReplies(replies)

			scored := replies
			if !origin.def.RequireAll || len(replies) < 2 {
				scored = replies[len(replies)-1:]
			}

			hit := r.reproducedOnReplies(origin, rec.Prompt, scored)
			trials++
			if hit {
				reproduced++
			}
			rec.Broke = hit
			if hit {
				rec.Reason = "reproduction trial matched"
			} else {
				rec.Reason = "reproduction trial held"
			}
			r.record(rec)
		}

		r.mu.Lock()
		r.scan.Findings[idx].Reproduced = reproduced
		r.scan.Findings[idx].Trials = trials
		r.mu.Unlock()
	}
}

func (r *runner) reproducedOnReplies(origin findingOrigin, prompt string, scored []target.Reply) bool {
	if len(scored) == 0 {
		return false
	}
	outs := make([]scoreOutcome, 0, len(scored))
	for _, rp := range scored {
		outs = append(outs, r.scoreReply(origin.jdef, prompt, rp))
	}

	if origin.tracePolicy {
		for _, o := range outs {
			if o.tracePolicy {
				return true
			}
		}
		return false
	}
	switch origin.sharedKind {
	case "recitation":
		for _, o := range outs {
			if o.recited > 0 {
				return true
			}
		}
		return false
	case "declined-produced":
		for _, o := range outs {
			if o.declinedProduced {
				return true
			}
		}
		return false
	}

	if origin.def.RequireAll && len(outs) > 1 {
		for _, o := range outs {
			if !o.score.Break {
				return false
			}
		}
		return true
	}
	return outs[len(outs)-1].score.Break
}
