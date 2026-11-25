package secureio

import "errors"

// StopError indicates a fail-closed safety condition that prevents continuing.
type StopError struct {
	Detail string
	Stage  string
	Reason string
}

func (e *StopError) Error() string {
	return e.Detail
}

func Stop(detail string) error {
	return &StopError{Detail: detail}
}

func StopWithReason(reason, detail string) error {
	return &StopError{Reason: reason, Detail: detail}
}

func ObservationStop(detail, stage, reason string) error {
	if reason == "" {
		reason = "CHECK_FAILED"
	}
	return &StopError{Detail: detail, Stage: stage, Reason: reason}
}

func AsStop(err error) (*StopError, bool) {
	var se *StopError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}
