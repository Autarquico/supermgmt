package api

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/autarquico/supermgmt/internal/api/wire"
	"github.com/autarquico/supermgmt/internal/policy"
)

// These tests keep api/openapi.yaml (authoritative, spec §23) and the Go
// route table and wire DTOs from drifting apart (ADR-0012).

const (
	specPath      = "../../api/openapi.yaml"
	schemaRefBase = "#/components/schemas/"
	routeKey      = "x-supermgmt-route"
	transportsKey = "x-supermgmt-transports"
	actionPrefix  = "action:"
	idempotencyIn = "#/components/parameters/IdempotencyKey"
)

var httpMethods = []string{"get", "put", "post", "patch", "delete"}

// schemaTypes maps every schema that stands for a wire type to that type.
// A schema missing here, or a type whose fields differ, fails.
var schemaTypes = map[string]reflect.Type{
	"Envelope":         reflect.TypeFor[wire.Envelope[any]](),
	"Meta":             reflect.TypeFor[wire.Meta](),
	"ErrorEnvelope":    reflect.TypeFor[wire.ErrorEnvelope](),
	"Error":            reflect.TypeFor[wire.Error](),
	"Empty":            reflect.TypeFor[struct{}](),
	"Health":           reflect.TypeFor[wire.Health](),
	"Me":               reflect.TypeFor[wire.Me](),
	"SSHKey":           reflect.TypeFor[wire.SSHKey](),
	"Provider":         reflect.TypeFor[wire.Provider](),
	"Node":             reflect.TypeFor[wire.Node](),
	"Endpoint":         reflect.TypeFor[wire.Endpoint](),
	"Capability":       reflect.TypeFor[wire.Capability](),
	"Address":          reflect.TypeFor[wire.Address](),
	"Connection":       reflect.TypeFor[wire.Connection](),
	"Metrics":          reflect.TypeFor[wire.Metrics](),
	"Setup":            reflect.TypeFor[wire.Setup](),
	"UnitGrant":        reflect.TypeFor[wire.UnitGrant](),
	"HostKey":          reflect.TypeFor[wire.HostKey](),
	"ConnectInfo":      reflect.TypeFor[wire.ConnectInfo](),
	"Session":          reflect.TypeFor[wire.Session](),
	"SessionOpened":    reflect.TypeFor[wire.SessionOpened](),
	"Service":          reflect.TypeFor[wire.Service](),
	"LogChunk":         reflect.TypeFor[wire.LogChunk](),
	"ResourceRef":      reflect.TypeFor[wire.ResourceRef](),
	"Policy":           reflect.TypeFor[wire.Policy](),
	"CreatedPlan":      reflect.TypeFor[wire.CreatedPlan](),
	"Submission":       reflect.TypeFor[wire.Submission](),
	"Job":              reflect.TypeFor[wire.Job](),
	"Failure":          reflect.TypeFor[wire.Failure](),
	"JobDetail":        reflect.TypeFor[wire.JobDetail](),
	"Intent":           reflect.TypeFor[wire.Intent](),
	"Approval":         reflect.TypeFor[wire.Approval](),
	"Event":            reflect.TypeFor[wire.Event](),
	"Actor":            reflect.TypeFor[wire.Actor](),
	"OIDCStart":        reflect.TypeFor[wire.OIDCStart](),
	"LoginSession":     reflect.TypeFor[wire.LoginSession](),
	"DeviceStart":      reflect.TypeFor[wire.DeviceStart](),
	"DevicePoll":       reflect.TypeFor[wire.DevicePoll](),
	"Bootstrapped":     reflect.TypeFor[wire.Bootstrapped](),
	"Token":            reflect.TypeFor[wire.Token](),
	"TokenIssued":      reflect.TypeFor[wire.TokenIssued](),
	"MasterKeyRotated": reflect.TypeFor[wire.MasterKeyRotated](),
	"ExportedKey":      reflect.TypeFor[wire.ExportedKey](),
	"SecretVersion":    reflect.TypeFor[wire.SecretVersion](),
	"Backup":           reflect.TypeFor[wire.Backup](),
	"MasterKey":        reflect.TypeFor[wire.MasterKey](),
	"EnrollmentIssued": reflect.TypeFor[wire.EnrollmentIssued](),
	"Enrolled":         reflect.TypeFor[wire.Enrolled](),

	"CreateProviderRequest": reflect.TypeFor[wire.CreateProviderRequest](),
	"ScanHostKeyRequest":    reflect.TypeFor[wire.ScanHostKeyRequest](),
	"AddSSHNodeRequest":     reflect.TypeFor[wire.AddSSHNodeRequest](),
	"NodePatch":             reflect.TypeFor[wire.NodePatch](),
	"OpenSessionRequest":    reflect.TypeFor[wire.OpenSessionRequest](),
	"EndSessionRequest":     reflect.TypeFor[wire.EndSessionRequest](),
	"CreatePlanRequest":     reflect.TypeFor[wire.CreatePlanRequest](),
	"PlanHashRequest":       reflect.TypeFor[wire.PlanHashRequest](),
	"DecisionRequest":       reflect.TypeFor[wire.DecisionRequest](),
	"ResolveRequest":        reflect.TypeFor[wire.ResolveRequest](),
	"OIDCStartRequest":      reflect.TypeFor[wire.OIDCStartRequest](),
	"OIDCExchangeRequest":   reflect.TypeFor[wire.OIDCExchangeRequest](),
	"DevicePollRequest":     reflect.TypeFor[wire.DevicePollRequest](),
	"BootstrapRequest":      reflect.TypeFor[wire.BootstrapRequest](),
	"CreateTokenRequest":    reflect.TypeFor[wire.CreateTokenRequest](),
	"RetireKeyRequest":      reflect.TypeFor[wire.RetireKeyRequest](),
	"ExportKeyRequest":      reflect.TypeFor[wire.ExportKeyRequest](),
	"ImportSecretRequest":   reflect.TypeFor[wire.ImportSecretRequest](),
	"EnrollmentRequest":     reflect.TypeFor[wire.EnrollmentRequest](),
	"EnrollRequest":         reflect.TypeFor[wire.EnrollRequest](),

	"PageOfEvent":     reflect.TypeFor[wire.Page[wire.Event]](),
	"PageOfApproval":  reflect.TypeFor[wire.Page[wire.Approval]](),
	"PageOfJob":       reflect.TypeFor[wire.Page[wire.Job]](),
	"PageOfProvider":  reflect.TypeFor[wire.Page[wire.Provider]](),
	"PageOfNode":      reflect.TypeFor[wire.Page[wire.Node]](),
	"PageOfService":   reflect.TypeFor[wire.Page[wire.Service]](),
	"PageOfToken":     reflect.TypeFor[wire.Page[wire.Token]](),
	"PageOfBackup":    reflect.TypeFor[wire.Page[wire.Backup]](),
	"PageOfMasterKey": reflect.TypeFor[wire.Page[wire.MasterKey]](),

	"DirectOfProvider":         reflect.TypeFor[wire.Direct[wire.Provider]](),
	"DirectOfNode":             reflect.TypeFor[wire.Direct[wire.Node]](),
	"DirectOfSecretVersion":    reflect.TypeFor[wire.Direct[wire.SecretVersion]](),
	"DirectOfMasterKeyRotated": reflect.TypeFor[wire.Direct[wire.MasterKeyRotated]](),
	"DirectOfSSHKey":           reflect.TypeFor[wire.Direct[wire.SSHKey]](),
	"DirectOfExportedKey":      reflect.TypeFor[wire.Direct[wire.ExportedKey]](),
	"DirectOfEmpty":            reflect.TypeFor[wire.Direct[struct{}]](),
}

// scalarSchemas are shared primitives with no wire struct behind them.
var scalarSchemas = []string{"ID", "Timestamp"}

type object = map[string]any

func loadSpec(t *testing.T) object {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc object
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	if got := doc["openapi"]; got != "3.1.0" {
		t.Fatalf("openapi = %v, want 3.1.0", got)
	}
	return doc
}

func child(o object, keys ...string) object {
	for _, k := range keys {
		next, _ := o[k].(object)
		if next == nil {
			return object{}
		}
		o = next
	}
	return o
}

// specOperation is one method+path of the document.
type specOperation struct {
	key  string // "GET /api/v1/me"
	path string
	body object
}

func operationsOf(doc object) map[string]specOperation {
	out := map[string]specOperation{}
	for path, item := range child(doc, "paths") {
		for _, m := range httpMethods {
			if body, ok := item.(object)[m].(object); ok {
				key := strings.ToUpper(m) + " " + path
				out[key] = specOperation{key: key, path: path, body: body}
			}
		}
	}
	return out
}

func serverRoutes(t *testing.T) map[string]Route {
	t.Helper()
	out := map[string]Route{}
	for _, rt := range newHarness(t).server.Routes() {
		out[rt.Method+" "+rt.Pattern] = rt
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestOpenAPI_EveryRouteIsDocumentedAndNothingElse(t *testing.T) {
	ops, routes := operationsOf(loadSpec(t)), serverRoutes(t)
	for _, key := range sortedKeys(routes) {
		if _, ok := ops[key]; !ok {
			t.Errorf("route %s is not in %s", key, specPath)
		}
	}
	for _, key := range sortedKeys(ops) {
		if _, ok := routes[key]; !ok {
			t.Errorf("%s documents %s, which the server does not serve", specPath, key)
		}
	}
}

func TestOpenAPI_RouteMetadataMatchesTheRouteTable(t *testing.T) {
	ops, routes := operationsOf(loadSpec(t)), serverRoutes(t)
	for _, key := range sortedKeys(routes) {
		op, ok := ops[key]
		if !ok {
			continue // reported by the route-set test
		}
		marker, _ := op.body[routeKey].(string)
		if want := expectedMarker(routes[key]); marker != want {
			t.Errorf("%s: %s = %q, route table says %q", key, routeKey, marker, want)
		}
	}
}

func expectedMarker(rt Route) string {
	if strings.HasPrefix(rt.Action, "exempt:") {
		return rt.Action
	}
	return actionPrefix + rt.Action
}

func TestOpenAPI_MarkersAreExemptionsOrCatalogActions(t *testing.T) {
	exemptions := []string{ExemptAuth, ExemptHealth, ExemptSelf}
	for key, op := range operationsOf(loadSpec(t)) {
		marker, _ := op.body[routeKey].(string)
		if slices.Contains(exemptions, marker) {
			continue
		}
		id, isAction := strings.CutPrefix(marker, actionPrefix)
		if !isAction {
			t.Errorf("%s: %s = %q, want action:<id> or one of %v", key, routeKey, marker, exemptions)
			continue
		}
		if _, known := policy.Lookup(id); !known {
			t.Errorf("%s: %q is not a catalog action", key, id)
		}
	}
}

func TestOpenAPI_UnixOnlyRoutesCarryTheTransportExtension(t *testing.T) {
	ops, routes := operationsOf(loadSpec(t)), serverRoutes(t)
	for _, key := range sortedKeys(routes) {
		op, ok := ops[key]
		if !ok {
			continue
		}
		transports, declared := op.body[transportsKey]
		if routes[key].UnixOnly {
			if !reflect.DeepEqual(transports, []any{"unix"}) {
				t.Errorf("%s is served on the Unix socket only: %s = %v, want [unix]", key, transportsKey, transports)
			}
		} else if declared {
			t.Errorf("%s is served on both transports but declares %s", key, transportsKey)
		}
	}
}

func TestOpenAPI_IdempotencyKeyIsDeclaredOnKeyedRoutesOnly(t *testing.T) {
	ops, routes := operationsOf(loadSpec(t)), serverRoutes(t)
	for _, key := range sortedKeys(routes) {
		op, ok := ops[key]
		if !ok {
			continue
		}
		declared := slices.ContainsFunc(listOf(op.body["parameters"]), func(p any) bool {
			ref, _ := p.(object)["$ref"].(string)
			return ref == idempotencyIn
		})
		if declared != routes[key].Keyed {
			t.Errorf("%s: Idempotency-Key declared = %v, route Keyed = %v", key, declared, routes[key].Keyed)
		}
		if routes[key].Credential && declared {
			t.Errorf("%s issues a credential and must not accept an Idempotency-Key", key)
		}
	}
}

func listOf(v any) []any {
	list, _ := v.([]any)
	return list
}

func TestOpenAPI_PathParametersAreDeclared(t *testing.T) {
	doc := loadSpec(t)
	for key, op := range operationsOf(doc) {
		want := pathPlaceholders(op.path)
		var got []string
		for _, p := range listOf(op.body["parameters"]) {
			param := resolveParameter(doc, p.(object))
			if param["in"] == "path" {
				got = append(got, param["name"].(string))
			}
		}
		slices.Sort(got)
		if !slices.Equal(want, got) {
			t.Errorf("%s: path parameters %v, path has %v", key, got, want)
		}
	}
}

func pathPlaceholders(path string) []string {
	var names []string
	for _, segment := range strings.Split(path, "/") {
		if name, ok := strings.CutSuffix(strings.TrimPrefix(segment, "{"), "}"); ok && strings.HasPrefix(segment, "{") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func resolveParameter(doc, param object) object {
	ref, ok := param["$ref"].(string)
	if !ok {
		return param
	}
	return child(doc, "components", "parameters", strings.TrimPrefix(ref, "#/components/parameters/"))
}

func TestOpenAPI_AdminSocketRoutesAreOutsideTheDocument(t *testing.T) {
	doc := loadSpec(t)
	paths := child(doc, "paths")
	for _, rt := range AdminRoutes() {
		if _, found := paths[rt.Pattern]; found {
			t.Errorf("admin route %s %s must not be in %s (ADR-0012)", rt.Method, rt.Pattern, specPath)
		}
	}
	for path := range paths {
		if strings.HasPrefix(path, "/admin") {
			t.Errorf("%s is under /admin, which the OpenAPI document does not cover", path)
		}
	}
}

func TestOpenAPI_EverySchemaIsMappedToAWireTypeAndItsFieldsMatch(t *testing.T) {
	schemas := child(loadSpec(t), "components", "schemas")
	for _, name := range sortedKeys(schemas) {
		if slices.Contains(scalarSchemas, name) {
			continue
		}
		typ, mapped := schemaTypes[name]
		if !mapped {
			t.Errorf("schema %s has no entry in schemaTypes", name)
			continue
		}
		compareFields(t, name, schemas[name].(object), typ)
	}
	for _, name := range sortedKeys(schemaTypes) {
		if _, found := schemas[name]; !found {
			t.Errorf("schemaTypes maps %s but %s has no such schema", name, specPath)
		}
	}
}

func compareFields(t *testing.T, name string, schema object, typ reflect.Type) {
	t.Helper()
	wantProps, wantRequired := jsonFields(typ)
	gotProps := sortedKeys(child(schema, "properties"))
	if !slices.Equal(wantProps, gotProps) {
		t.Errorf("schema %s properties = %v, wire %s has %v", name, gotProps, typ, wantProps)
	}
	var gotRequired []string
	for _, r := range listOf(schema["required"]) {
		gotRequired = append(gotRequired, r.(string))
	}
	slices.Sort(gotRequired)
	if !slices.Equal(wantRequired, gotRequired) {
		t.Errorf("schema %s required = %v, wire %s always emits %v", name, gotRequired, typ, wantRequired)
	}
}

// jsonFields lists the JSON property names of a struct and those always
// emitted (no omitempty), both sorted.
func jsonFields(typ reflect.Type) (all, required []string) {
	for field := range typ.Fields() {
		tag, _ := field.Tag.Lookup("json")
		name, options, _ := strings.Cut(tag, ",")
		if !field.IsExported() || name == "-" || name == "" {
			continue
		}
		all = append(all, name)
		if !strings.Contains(options, "omitempty") {
			required = append(required, name)
		}
	}
	slices.Sort(all)
	slices.Sort(required)
	return all, required
}

func TestOpenAPI_PageAndDirectSchemasWrapTheirNamedItem(t *testing.T) {
	schemas := child(loadSpec(t), "components", "schemas")
	for name, schema := range schemas {
		if item, ok := strings.CutPrefix(name, "PageOf"); ok {
			items := child(schema.(object), "properties", "items", "items")
			if got := items["$ref"]; got != schemaRefBase+item {
				t.Errorf("%s items = %v, want %s", name, got, schemaRefBase+item)
			}
		}
		if item, ok := strings.CutPrefix(name, "DirectOf"); ok {
			applied := listOf(child(schema.(object), "properties", "applied")["oneOf"])
			if len(applied) == 0 || applied[0].(object)["$ref"] != schemaRefBase+item {
				t.Errorf("%s applied = %v, want a %s", name, applied, schemaRefBase+item)
			}
		}
	}
}

func TestOpenAPI_EveryReferenceResolvesAndEverySchemaIsUsed(t *testing.T) {
	doc := loadSpec(t)
	known := map[string]bool{}
	var refs []string
	collectRefs(doc, &refs)
	for _, section := range []string{"schemas", "parameters", "responses", "requestBodies"} {
		for name := range child(doc, "components", section) {
			known["#/components/"+section+"/"+name] = true
		}
	}
	used := map[string]bool{}
	for _, ref := range refs {
		if !known[ref] {
			t.Errorf("reference %s does not resolve", ref)
		}
		used[ref] = true
	}
	for ref := range known {
		if !used[ref] {
			t.Errorf("%s is defined but never referenced", ref)
		}
	}
}

func collectRefs(node any, refs *[]string) {
	switch v := node.(type) {
	case object:
		for key, value := range v {
			if ref, ok := value.(string); ok && key == "$ref" {
				*refs = append(*refs, ref)
				continue
			}
			collectRefs(value, refs)
		}
	case []any:
		for _, item := range v {
			collectRefs(item, refs)
		}
	}
}

func TestOpenAPI_OperationIDsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for key, op := range operationsOf(loadSpec(t)) {
		id, _ := op.body["operationId"].(string)
		if id == "" {
			t.Errorf("%s has no operationId", key)
		}
		if other, dup := seen[id]; dup {
			t.Errorf("operationId %q is used by %s and %s", id, other, key)
		}
		seen[id] = key
	}
}

func TestOpenAPI_JSONFieldsReadTagsAndOmitempty(t *testing.T) {
	type sample struct {
		Kept    string `json:"kept"`
		Maybe   string `json:"maybe,omitempty"`
		Skipped string `json:"-"`
		hidden  string
	}
	_ = sample{}.hidden
	all, required := jsonFields(reflect.TypeFor[sample]())
	if got, want := fmt.Sprint(all, required), fmt.Sprint([]string{"kept", "maybe"}, []string{"kept"}); got != want {
		t.Errorf("jsonFields = %s, want %s", got, want)
	}
}
