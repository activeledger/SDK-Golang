package activeledger_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/eckeys"
	"github.com/activeledger/SDK-Golang/pqkeys"
)

// Runs against a real 4-node Activeledger network.
//
// Everything else here checks the SDK against a published file. This checks
// it against a running ledger, which is the only thing that actually decides
// whether a signature is acceptable: the type string, the $sigs keying and
// the exact signed bytes are all invisible to a unit test.
//
// Start the network from an activeledger checkout:
//
//	npm run test:network:serve
//
// then run with the URLs it prints:
//
//	AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 go test -run TestLive ./...
//
// Skips when AL_NODES is unset, so `go test ./...` works with no ledger.

func nodes(t *testing.T) []string {
	t.Helper()
	raw := os.Getenv("AL_NODES")
	if raw == "" {
		t.Skip("AL_NODES not set - start 'npm run test:network:serve' in the ledger repo")
	}
	return strings.Split(raw, ",")
}

func storageURLs() []string {
	raw := os.Getenv("AL_STORAGE")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// storageRead reads a document straight from a node's storage service.
//
// Deliberately here in the test and NOT in the SDK: storage listens only on
// the node's own host, so a client cannot reach it. The SDK reads state
// through a transaction's $r instead. This suite runs against a local
// harness, where storage is reachable by definition, and uses it to assert
// what the ledger actually recorded rather than what a contract chose to
// return.
func storageRead(t *testing.T, index int, id string) map[string]interface{} {
	t.Helper()
	storage := storageURLs()
	if len(storage) <= index {
		t.Skip("AL_STORAGE not set - cannot verify what the ledger recorded")
	}
	endpoint := fmt.Sprintf("%s/activeledger/%s",
		strings.TrimRight(storage[index], "/"), url.QueryEscape(id))

	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("storage read: %v", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("storage returned non-JSON: %s", raw)
	}
	return doc
}

func unique(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()%100000000)
}

func TestLiveIdentityOnboardsAndIsRecordedCorrectly(t *testing.T) {
	urls := nodes(t)
	client := activeledger.NewClient(urls[0])
	ctx := context.Background()

	key, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := client.Onboard(ctx, key)
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if identity.StreamID == "" {
		t.Fatal("no stream id returned")
	}

	// Consensus is a majority, so the origin's reply means most nodes have
	// committed; the rest may still be writing.
	var authorities []interface{}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		meta := storageRead(t, 0, identity.StreamID+":stream")
		if a, ok := meta["authorities"].([]interface{}); ok && len(a) > 0 {
			authorities = a
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(authorities) == 0 {
		t.Fatal("identity meta never appeared")
	}

	authority := authorities[0].(map[string]interface{})
	if got := authority["type"]; got != "ml-dsa-65" {
		t.Errorf("authority type on the ledger was %v", got)
	}
	public, err := base64.StdEncoding.DecodeString(authority["public"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(public) != pqkeys.PublicKeySize {
		t.Errorf("public key on the ledger was %d bytes, want %d",
			len(public), pqkeys.PublicKeySize)
	}
}

// secp256k1 identities, in both public key forms.
//
// The ledger accepts either and tells them apart by length, so onboarding
// only ever with the compressed form would leave the other path unproven.
func TestLiveSecp256k1IdentityOnboardsAndIsRecordedCorrectly(t *testing.T) {
	urls := nodes(t)
	ctx := context.Background()

	for _, tc := range []struct {
		compressed    bool
		expectedChars int
	}{{true, 68}, {false, 132}} {
		client := activeledger.NewClient(urls[0])

		key, err := eckeys.GenerateWith(tc.compressed)
		if err != nil {
			t.Fatal(err)
		}

		identity, err := client.Onboard(ctx, key)
		if err != nil {
			t.Fatalf("onboard: %v", err)
		}

		var authorities []interface{}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			meta := storageRead(t, 0, identity.StreamID+":stream")
			if a, ok := meta["authorities"].([]interface{}); ok && len(a) > 0 {
				authorities = a
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if len(authorities) == 0 {
			t.Fatal("identity meta never appeared")
		}

		authority := authorities[0].(map[string]interface{})
		if got := authority["type"]; got != "secp256k1" {
			t.Errorf("authority type on the ledger was %v", got)
		}

		// Stored as 0x-prefixed hex, NOT base64. If this ever comes back
		// base64 the SDK has encoded it the post-quantum way, and every later
		// signature fails as 1220.
		stored, _ := authority["public"].(string)
		if !strings.HasPrefix(stored, "0x") {
			t.Errorf("the ledger stored %q, which is not 0x hex", stored)
		}
		if len(stored) != tc.expectedChars {
			t.Errorf("stored key is %d chars, expected %d", len(stored), tc.expectedChars)
		}
		if stored != key.PublicKey() {
			t.Errorf("the ledger stored a different key")
		}
	}
}

func TestLiveSecp256k1SignedTransactionIsAccepted(t *testing.T) {
	urls := nodes(t)
	client := activeledger.NewClient(urls[0])
	ctx := context.Background()

	key, err := eckeys.Generate()
	if err != nil {
		t.Fatal(err)
	}

	identity, err := client.Onboard(ctx, key)
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	tx, err := activeledger.NewBuilder().
		Namespace("default").
		Contract("namespace").
		Input(identity.StreamID, identity.Signer,
			activeledger.NewObject().Set("namespace", unique("goec"))).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	response, err := client.Submit(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Committed() {
		t.Fatalf("rejected: %s", response.Raw)
	}
}

func TestLiveTransactionSignedByThisSDKIsAccepted(t *testing.T) {
	urls := nodes(t)
	client := activeledger.NewClient(urls[0])
	ctx := context.Background()

	key, _ := pqkeys.Generate()
	identity, err := client.Onboard(ctx, key)
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	// Namespaces are claimed permanently, so a fixed name passes once and
	// fails every re-run against the same network - which reads exactly like
	// a regression and is not one.
	tx, err := activeledger.NewBuilder().
		Namespace("default").
		Contract("namespace").
		Input(identity.StreamID, identity.Signer,
			activeledger.NewObject().Set("namespace", unique("golang"))).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Submit(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Committed() {
		t.Fatalf("rejected: %s", response.Raw)
	}
}

// Without this the suite would pass against an implementation that accepted
// everything.
func TestLiveTamperedPayloadIsRejected(t *testing.T) {
	urls := nodes(t)
	client := activeledger.NewClient(urls[0])
	ctx := context.Background()

	key, _ := pqkeys.Generate()
	identity, err := client.Onboard(ctx, key)
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	honest, err := activeledger.NewBuilder().
		Namespace("default").
		Contract("namespace").
		Input(identity.StreamID, identity.Signer,
			activeledger.NewObject().Set("namespace", unique("gotamper"))).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	body, err := honest.JSON()
	if err != nil {
		t.Fatal(err)
	}

	// Same signature, different body - submitted raw, because the builder
	// would re-sign it into a valid transaction.
	tampered := strings.Replace(body, "gotamper", "gostolen", 1)
	response, err := client.SubmitRaw(ctx, tampered)
	if err != nil {
		t.Fatal(err)
	}
	if response.Committed() {
		t.Fatalf("a tampered payload was accepted: %s", response.Raw)
	}
}
