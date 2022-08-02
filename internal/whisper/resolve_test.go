package whisper

import (
	"strings"
	"testing"

	"github.com/busser/whisper/internal/clients/mock"
	"github.com/google/go-cmp/cmp"
)

func TestResolveAll(t *testing.T) {
	fooClient, _ := mock.New()
	barClient, _ := mock.New()

	// Replace whisper's clients with mocks for the duration of the test.
	originalClientFactories := ClientFactories
	defer func() { ClientFactories = originalClientFactories }()
	ClientFactories = map[string]ClientFactory{
		"foo": func() (Client, error) { return fooClient, nil },
		"bar": func() (Client, error) { return barClient, nil },
	}

	envVars := map[string]string{
		"NOT_A_SECRET":        "My app listens on port 3000",
		"NOT_A_SECRET_EITHER": "The cloud is awesome",
		"FIRST_SECRET":        "foo:database password",
		"SECOND_SECRET":       "foo:private key",
		"THIRD_SECRET":        "bar:api key",
		"LOOKS_LIKE_A_SECRET": "baz:but isn't a secret",
	}

	actual, err := ResolveAll(envVars)
	if err != nil {
		t.Fatalf("ResolveAll() returned an error: %v", err)
	}

	if len(fooClient.ResolvedRefs()) != 2 {
		t.Errorf("ResolveAll() called fooClient.Resolve() %d times, expected %d times",
			len(fooClient.ResolvedRefs()), 2)
	}

	if len(barClient.ResolvedRefs()) != 1 {
		t.Errorf("ResolveAll() called barClient.Resolve() %d times, expected %d times",
			len(barClient.ResolvedRefs()), 1)
	}

	want := map[string]string{
		"NOT_A_SECRET":        "My app listens on port 3000",
		"NOT_A_SECRET_EITHER": "The cloud is awesome",
		"FIRST_SECRET":        mock.ValueFor("database password"),
		"SECOND_SECRET":       mock.ValueFor("private key"),
		"THIRD_SECRET":        mock.ValueFor("api key"),
		"LOOKS_LIKE_A_SECRET": "baz:but isn't a secret",
	}

	if diff := cmp.Diff(want, actual); diff != "" {
		t.Errorf("ResolveAll() mismatch (-want +got):\n%s", diff)
	}
}

func TestResolveAllWithError(t *testing.T) {
	// Replace whisper's clients with mocks for the duration of the test.
	originalClientFactories := ClientFactories
	defer func() { ClientFactories = originalClientFactories }()
	ClientFactories = map[string]ClientFactory{
		"foo": func() (Client, error) { return mock.New() },
		"bar": func() (Client, error) { return mock.New() },
	}

	envVars := map[string]string{
		"NOT_A_SECRET":        "My app listens on port 3000",
		"OK_SECRET":           "foo:database password",
		"BROKEN_SECRET":       "foo:FAIL",
		"BUGGY_SECRET":        "bar:FAIL",
		"LOOKS_LIKE_A_SECRET": "baz:FAIL",
	}

	_, err := ResolveAll(envVars)
	if err == nil {
		t.Fatal("ResolveAll() returned no error but it should have")
	}

	errMsg := err.Error()

	errorShouldMention := []string{"BROKEN_SECRET", "BUGGY_SECRET"}
	for _, s := range errorShouldMention {
		if !strings.Contains(errMsg, s) {
			t.Errorf("Error message %q should mention %q", errMsg, s)
		}
	}

	errorShouldNotMention := []string{"NOT_A_SECRET", "OK_SECRET", "LOOKS_LIKE_A_SECRET"}
	for _, s := range errorShouldNotMention {
		if strings.Contains(errMsg, s) {
			t.Errorf("Error message %q should not mention %q", errMsg, s)
		}
	}
}