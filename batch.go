package proxykit

import (
	"context"
	"sync"
)

// CheckOutcome pairs an individual check result with its failure, if any.
type CheckOutcome struct {
	Result CheckResult
	Err    error
}

// BatchOptions controls target checks, connection setup and the worker limit.
type BatchOptions struct {
	Check CheckOptions
	Dial  DialOptions
	// Concurrency zero uses 16 workers; negative values are invalid.
	Concurrency int
}

// CheckAll checks proxies with a fixed worker pool and preserves input order.
// It returns partial results on cancellation. A failed item has its own Err;
// the returned error describes cancellation or invalid batch configuration.
func CheckAll(ctx context.Context, specs []Spec, opts BatchOptions) ([]CheckOutcome, error) {
	return checkAll(ctx, specs, opts.Check, opts.Concurrency, newDialerFactory(opts.Dial))
}

// checkAll uses a fixed worker pool, preserves input order and returns completed
// results on cancellation. Unstarted items have Err=context.Canceled or
// context.DeadlineExceeded. Concurrency zero uses 16; negative values are invalid.
// Callers must not mutate specs/options/TLSConfig until the operation returns.
func checkAll(ctx context.Context, specs []Spec, opts CheckOptions, concurrency int, factory dialerFactory) ([]CheckOutcome, error) {
	if factory == nil {
		return nil, invalid("nil batch dialer factory")
	}
	if concurrency < 0 {
		return nil, invalid("negative concurrency")
	}
	if concurrency == 0 {
		concurrency = 16
	}
	if concurrency > len(specs) {
		concurrency = len(specs)
	}
	out := make([]CheckOutcome, len(specs))
	if len(specs) == 0 {
		return out, ctx.Err()
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if e := ctx.Err(); e != nil {
					out[index] = CheckOutcome{Result: CheckResult{Proxy: specs[index]}, Err: e}
					continue
				}
				dialer, err := factory(specs[index])
				if err != nil {
					out[index] = CheckOutcome{Result: CheckResult{Proxy: specs[index]}, Err: err}
					continue
				}
				result, err := check(ctx, specs[index], dialer, opts)
				out[index] = CheckOutcome{result, err}
			}
		}()
	}
	for i := range specs {
		select {
		case jobs <- i:
		case <-ctx.Done():
			for j := i; j < len(specs); j++ {
				out[j] = CheckOutcome{Result: CheckResult{Proxy: specs[j]}, Err: ctx.Err()}
			}
			close(jobs)
			wg.Wait()
			return out, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return out, ctx.Err()
}
