package errors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// AppError creation
// ──────────────────────────────────────────────

func TestNew_CreatesAppError(t *testing.T) {
	err := New(ErrCodeNotFound, "resource missing")

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeNotFound, err.Code)
	assert.Equal(t, "resource missing", err.Message)
	assert.False(t, err.Timestamp.IsZero())
	assert.NotEmpty(t, err.StackTrace)
}

func TestNewf_FormatsMessage(t *testing.T) {
	err := Newf(ErrCodeInvalidInput, "bad value %q for %s", "foo", "bar")

	require.NotNil(t, err)
	assert.Equal(t, `bad value "foo" for bar`, err.Message)
}

func TestNew_SeverityAssigned(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		wantSev  Severity
	}{
		{ErrCodeValidation, SeverityLow},
		{ErrCodeInvalidInput, SeverityLow},
		{ErrCodeNotFound, SeverityMedium},
		{ErrCodeDatabase, SeverityHigh},
		{ErrCodeInternal, SeverityCritical},
		{ErrCodePanic, SeverityCritical},
	}

	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			err := New(tc.code, "msg")
			assert.Equal(t, tc.wantSev, err.Severity)
		})
	}
}

func TestNew_RetryableFlag(t *testing.T) {
	retryable := []ErrorCode{ErrCodeNetwork, ErrCodeTimeout, ErrCodeRateLimit, ErrCodeServiceUnavailable}
	for _, code := range retryable {
		t.Run(string(code)+"_is_retryable", func(t *testing.T) {
			err := New(code, "msg")
			assert.True(t, err.Retryable)
		})
	}

	notRetryable := []ErrorCode{ErrCodeValidation, ErrCodeNotFound, ErrCodeUnauthorized, ErrCodeForbidden}
	for _, code := range notRetryable {
		t.Run(string(code)+"_not_retryable", func(t *testing.T) {
			err := New(code, "msg")
			assert.False(t, err.Retryable)
		})
	}
}

// ──────────────────────────────────────────────
// Error wrapping
// ──────────────────────────────────────────────

func TestWrap_StoresCause(t *testing.T) {
	cause := fmt.Errorf("original error")
	wrapped := Wrap(cause, ErrCodeDatabase, "db failed")

	require.NotNil(t, wrapped)
	assert.Equal(t, cause, wrapped.Cause)
	assert.Equal(t, ErrCodeDatabase, wrapped.Code)
	assert.Equal(t, "db failed", wrapped.Message)
}

func TestWrapf_FormatsMessage(t *testing.T) {
	cause := fmt.Errorf("root")
	wrapped := Wrapf(cause, ErrCodeProcessing, "process %d failed", 42)

	assert.Equal(t, "process 42 failed", wrapped.Message)
	assert.Equal(t, cause, wrapped.Cause)
}

func TestUnwrap_ReturnsCause(t *testing.T) {
	cause := fmt.Errorf("inner")
	wrapped := Wrap(cause, ErrCodeInternal, "outer")

	assert.Equal(t, cause, errors.Unwrap(wrapped))
}

// ──────────────────────────────────────────────
// Error.Error() formatting
// ──────────────────────────────────────────────

func TestAppError_Error_WithoutCause(t *testing.T) {
	err := New(ErrCodeNotFound, "not found")
	msg := err.Error()

	assert.Contains(t, msg, string(ErrCodeNotFound))
	assert.Contains(t, msg, "not found")
}

func TestAppError_Error_WithCause(t *testing.T) {
	cause := fmt.Errorf("root cause")
	err := Wrap(cause, ErrCodeDatabase, "db error")
	msg := err.Error()

	assert.Contains(t, msg, "db error")
	assert.Contains(t, msg, "root cause")
}

// ──────────────────────────────────────────────
// Fluent builder methods on AppError
// ──────────────────────────────────────────────

func TestAppError_WithContext(t *testing.T) {
	err := New(ErrCodeNotFound, "missing")
	err.WithContext("resource", "user").WithContext("id", "123")

	assert.Equal(t, "user", err.Context["resource"])
	assert.Equal(t, "123", err.Context["id"])
}

func TestAppError_WithRequestID(t *testing.T) {
	err := New(ErrCodeInternal, "oops")
	err.WithRequestID("req-abc")

	assert.Equal(t, "req-abc", err.RequestID)
}

func TestAppError_WithUserID(t *testing.T) {
	err := New(ErrCodeForbidden, "denied")
	err.WithUserID("user-42")

	assert.Equal(t, "user-42", err.UserID)
}

// ──────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────

func TestIsAppError(t *testing.T) {
	appErr := New(ErrCodeInternal, "x")
	plainErr := fmt.Errorf("plain")

	assert.True(t, IsAppError(appErr))
	assert.False(t, IsAppError(plainErr))
}

func TestGetAppError(t *testing.T) {
	appErr := New(ErrCodeInternal, "x")
	extracted := GetAppError(appErr)
	assert.Equal(t, appErr, extracted)

	plain := fmt.Errorf("plain")
	assert.Nil(t, GetAppError(plain))
}

func TestHasCode(t *testing.T) {
	err := New(ErrCodeNotFound, "missing")

	assert.True(t, HasCode(err, ErrCodeNotFound))
	assert.False(t, HasCode(err, ErrCodeInternal))
	assert.False(t, HasCode(fmt.Errorf("plain"), ErrCodeNotFound))
}

func TestIsRetryable(t *testing.T) {
	retryableErr := New(ErrCodeTimeout, "timed out")
	notRetryable := New(ErrCodeNotFound, "missing")
	plain := fmt.Errorf("plain")

	assert.True(t, IsRetryable(retryableErr))
	assert.False(t, IsRetryable(notRetryable))
	assert.False(t, IsRetryable(plain))
}

func TestGetSeverity(t *testing.T) {
	err := New(ErrCodeInternal, "crash")
	assert.Equal(t, SeverityCritical, GetSeverity(err))

	plain := fmt.Errorf("plain")
	assert.Equal(t, SeverityMedium, GetSeverity(plain))
}

// ──────────────────────────────────────────────
// Typed constructors
// ──────────────────────────────────────────────

func TestNewValidationError(t *testing.T) {
	err := NewValidationError("field required")
	assert.Equal(t, ErrCodeValidation, err.Code)
}

func TestNewInvalidInputError(t *testing.T) {
	err := NewInvalidInputError("username", "bad!")
	assert.Equal(t, ErrCodeInvalidInput, err.Code)
	assert.Contains(t, err.Message, "username")
	assert.Contains(t, err.Message, "bad!")
}

func TestNewMissingRequiredError(t *testing.T) {
	err := NewMissingRequiredError("email")
	assert.Equal(t, ErrCodeMissingRequired, err.Code)
	assert.Contains(t, err.Message, "email")
}

func TestNewNetworkError(t *testing.T) {
	err := NewNetworkError("connection refused")
	assert.Equal(t, ErrCodeNetwork, err.Code)
}

func TestNewTimeoutError(t *testing.T) {
	err := NewTimeoutError("scan", 30*time.Second)
	assert.Equal(t, ErrCodeTimeout, err.Code)
	assert.Contains(t, err.Message, "scan")
	assert.Contains(t, err.Message, "30s")
}

func TestNewRateLimitError(t *testing.T) {
	err := NewRateLimitError(100, time.Minute)
	assert.Equal(t, ErrCodeRateLimit, err.Code)
	assert.Contains(t, err.Message, "100")
}

func TestNewNotFoundError(t *testing.T) {
	err := NewNotFoundError("Package", "lodash")
	assert.Equal(t, ErrCodeNotFound, err.Code)
	assert.Contains(t, err.Message, "Package")
	assert.Contains(t, err.Message, "lodash")
}

func TestNewAlreadyExistsError(t *testing.T) {
	err := NewAlreadyExistsError("User", "alice")
	assert.Equal(t, ErrCodeAlreadyExists, err.Code)
	assert.Contains(t, err.Message, "alice")
}

func TestNewDatabaseError(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	err := NewDatabaseError("insert", cause)
	assert.Equal(t, ErrCodeDatabase, err.Code)
	assert.Equal(t, cause, err.Cause)
}

func TestNewUnauthorizedError(t *testing.T) {
	err := NewUnauthorizedError("missing token")
	assert.Equal(t, ErrCodeUnauthorized, err.Code)
}

func TestNewForbiddenError(t *testing.T) {
	err := NewForbiddenError("/admin")
	assert.Equal(t, ErrCodeForbidden, err.Code)
	assert.Contains(t, err.Message, "/admin")
}

func TestNewConfigError(t *testing.T) {
	err := NewConfigError("database.host", "cannot be empty")
	assert.Equal(t, ErrCodeConfig, err.Code)
	assert.Contains(t, err.Message, "database.host")
}

func TestNewInternalError(t *testing.T) {
	err := NewInternalError("unexpected state")
	assert.Equal(t, ErrCodeInternal, err.Code)
}

func TestNewPanicError(t *testing.T) {
	err := NewPanicError("nil pointer dereference")
	assert.Equal(t, ErrCodePanic, err.Code)
	assert.Contains(t, err.Message, "nil pointer dereference")
}

func TestNewParsingError(t *testing.T) {
	err := NewParsingError("JSON", "unexpected token")
	assert.Equal(t, ErrCodeParsing, err.Code)
	assert.Contains(t, err.Message, "JSON")
}

func TestNewProcessingError(t *testing.T) {
	err := NewProcessingError("scan failed")
	assert.Equal(t, ErrCodeProcessing, err.Code)
}

// ──────────────────────────────────────────────
// ErrorList
// ──────────────────────────────────────────────

func TestErrorList_AddAndCount(t *testing.T) {
	el := NewErrorList()
	assert.False(t, el.HasErrors())
	assert.Equal(t, 0, el.Count())

	el.Add(New(ErrCodeNotFound, "a"))
	el.Add(New(ErrCodeInternal, "b"))

	assert.True(t, el.HasErrors())
	assert.Equal(t, 2, el.Count())
}

func TestErrorList_AddError_WithAppError(t *testing.T) {
	el := NewErrorList()
	appErr := New(ErrCodeForbidden, "no access")
	el.AddError(appErr)

	require.Equal(t, 1, el.Count())
	assert.Equal(t, ErrCodeForbidden, el.First().Code)
}

func TestErrorList_AddError_WithPlainError(t *testing.T) {
	el := NewErrorList()
	el.AddError(fmt.Errorf("plain error"))

	require.Equal(t, 1, el.Count())
	// Should be wrapped with ErrCodeUnknown
	assert.Equal(t, ErrCodeUnknown, el.First().Code)
}

func TestErrorList_First_Empty(t *testing.T) {
	el := NewErrorList()
	assert.Nil(t, el.First())
}

func TestErrorList_Clear(t *testing.T) {
	el := NewErrorList()
	el.Add(New(ErrCodeInternal, "x"))
	el.Clear()

	assert.Equal(t, 0, el.Count())
	assert.False(t, el.HasErrors())
}

func TestErrorList_Error_NoErrors(t *testing.T) {
	el := NewErrorList()
	assert.Equal(t, "no errors", el.Error())
}

func TestErrorList_Error_SingleError(t *testing.T) {
	el := NewErrorList()
	el.Add(New(ErrCodeNotFound, "not found"))
	assert.Contains(t, el.Error(), "NOT_FOUND")
}

func TestErrorList_Error_MultipleErrors(t *testing.T) {
	el := NewErrorList()
	el.Add(New(ErrCodeNotFound, "a"))
	el.Add(New(ErrCodeInternal, "b"))
	assert.Contains(t, el.Error(), "multiple errors")
}

// ──────────────────────────────────────────────
// HTTP status mapping
// ──────────────────────────────────────────────

func TestGetHTTPStatus(t *testing.T) {
	tests := []struct {
		code       ErrorCode
		wantStatus int
	}{
		{ErrCodeUnauthorized, http.StatusUnauthorized},
		{ErrCodeForbidden, http.StatusForbidden},
		{ErrCodeNotFound, http.StatusNotFound},
		{ErrCodeInvalidInput, http.StatusBadRequest},
		{ErrCodeValidation, http.StatusBadRequest},
		{ErrCodeRateLimit, http.StatusTooManyRequests},
		{ErrCodeInternal, http.StatusInternalServerError},
		{ErrCodeUnknown, http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			err := New(tc.code, "msg")
			assert.Equal(t, tc.wantStatus, GetHTTPStatus(err))
		})
	}
}

func TestGetHTTPStatus_PlainError_Returns500(t *testing.T) {
	err := fmt.Errorf("plain error")
	assert.Equal(t, http.StatusInternalServerError, GetHTTPStatus(err))
}

// ──────────────────────────────────────────────
// Is() method for error matching
// ──────────────────────────────────────────────

func TestAppError_Is(t *testing.T) {
	target := &AppError{Code: ErrCodeNotFound}
	err := New(ErrCodeNotFound, "not found")

	assert.True(t, err.Is(target))

	other := &AppError{Code: ErrCodeInternal}
	assert.False(t, err.Is(other))

	// Non-AppError target
	assert.False(t, err.Is(fmt.Errorf("plain")))
}

// ──────────────────────────────────────────────
// EnhancedError (enhanced_errors.go)
// ──────────────────────────────────────────────

func TestEnhancedError_Error(t *testing.T) {
	e := &EnhancedError{
		Message: "something went wrong",
	}
	assert.Equal(t, "something went wrong", e.Error())
}

func TestEnhancedError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("root cause")
	e := &EnhancedError{
		Message: "wrapped",
		Cause:   cause,
	}
	assert.Equal(t, cause, e.Unwrap())
}

func TestErrorBuilder_Build(t *testing.T) {
	e := NewError("TEST_CODE", "test message").
		Category(CategoryNetwork).
		Severity(ErrorSeverityHigh).
		UserMessage("Something failed").
		Explanation("Here is why").
		Suggestion("Try this").
		Suggestion("Or this").
		Documentation("https://docs.example.com").
		Example("falcn scan --fix").
		Component("scanner").
		Context("package", "lodash").
		Build()

	require.NotNil(t, e)
	assert.Equal(t, "TEST_CODE", e.Code)
	assert.Equal(t, "test message", e.Message)
	assert.Equal(t, CategoryNetwork, e.Category)
	assert.Equal(t, ErrorSeverityHigh, e.Severity)
	assert.Equal(t, "Something failed", e.UserMessage)
	assert.Equal(t, "Here is why", e.Explanation)
	assert.Len(t, e.Suggestions, 2)
	assert.Equal(t, "https://docs.example.com", e.Documentation)
	assert.Len(t, e.Examples, 1)
	assert.Equal(t, "scanner", e.Component)
	assert.Equal(t, "lodash", e.Context["package"])
}

func TestErrorBuilder_SuggestionsVariadic(t *testing.T) {
	e := NewError("X", "y").Suggestions("one", "two", "three").Build()
	assert.Len(t, e.Suggestions, 3)
}

func TestErrorBuilder_CauseSet(t *testing.T) {
	cause := fmt.Errorf("underlying")
	e := NewError("X", "msg").Cause(cause).Build()
	assert.Equal(t, cause, e.Cause)
	assert.Equal(t, cause, e.Unwrap())
}

func TestPredefinedErrors(t *testing.T) {
	t.Run("ErrConfigFileNotFound", func(t *testing.T) {
		e := ErrConfigFileNotFound("/etc/falcn/config.yaml")
		require.NotNil(t, e)
		assert.Equal(t, CategoryConfiguration, e.Category)
		assert.Contains(t, e.Context["path"], "/etc/falcn")
		assert.NotEmpty(t, e.Suggestions)
	})

	t.Run("ErrInvalidConfiguration", func(t *testing.T) {
		e := ErrInvalidConfiguration("database.port", -1)
		require.NotNil(t, e)
		assert.Equal(t, CategoryConfiguration, e.Category)
		assert.Equal(t, "database.port", e.Context["field"])
	})

	t.Run("ErrNetworkTimeout", func(t *testing.T) {
		e := ErrNetworkTimeout("https://registry.npmjs.org")
		require.NotNil(t, e)
		assert.Equal(t, CategoryNetwork, e.Category)
		assert.Contains(t, e.Context["url"], "npmjs")
	})

	t.Run("ErrPermissionDenied", func(t *testing.T) {
		e := ErrPermissionDenied("/var/log/falcn")
		require.NotNil(t, e)
		assert.Equal(t, CategoryPermission, e.Category)
		assert.Contains(t, e.Context["path"], "/var/log")
	})

	t.Run("ErrDependencyNotFound", func(t *testing.T) {
		e := ErrDependencyNotFound("git")
		require.NotNil(t, e)
		assert.Equal(t, CategoryDependency, e.Category)
		assert.Equal(t, "git", e.Context["dependency"])
	})
}

func TestHelperBuilders(t *testing.T) {
	tests := []struct {
		name     string
		builder  *ErrorBuilder
		wantCat  ErrorCategory
		wantSev  ErrorSeverity
	}{
		{"ConfigurationError", ConfigurationError("C", "m"), CategoryConfiguration, ErrorSeverityMedium},
		{"NetworkError", NetworkError("N", "m"), CategoryNetwork, ErrorSeverityHigh},
		{"PermissionError", PermissionError("P", "m"), CategoryPermission, ErrorSeverityHigh},
		{"DependencyError", DependencyError("D", "m"), CategoryDependency, ErrorSeverityMedium},
		{"ValidationError", ValidationError("V", "m"), CategoryValidation, ErrorSeverityMedium},
		{"UsageError", UsageError("U", "m"), CategoryUsage, ErrorSeverityLow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.builder.Build()
			assert.Equal(t, tc.wantCat, e.Category)
			assert.Equal(t, tc.wantSev, e.Severity)
		})
	}
}

func TestErrorFormatter_Format_NoColor(t *testing.T) {
	f := NewErrorFormatter(false, false)
	e := NewError("TEST", "test error").
		UserMessage("Something broke").
		Explanation("It broke because X").
		Suggestion("Fix it by doing Y").
		Build()

	output := f.Format(e)
	assert.Contains(t, output, "Something broke")
	assert.Contains(t, output, "It broke because X")
	assert.Contains(t, output, "Fix it by doing Y")
}

func TestErrorFormatter_Format_VerboseMode(t *testing.T) {
	f := NewErrorFormatter(false, true)
	e := NewError("VERBOSE_CODE", "verbose msg").
		Example("falcn scan .").
		Component("test-component").
		Context("key", "val").
		Build()

	output := f.Format(e)
	assert.Contains(t, output, "VERBOSE_CODE")
	assert.Contains(t, output, "test-component")
	assert.Contains(t, output, "falcn scan .")
}
