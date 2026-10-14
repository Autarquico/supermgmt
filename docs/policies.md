# Policies and approvals

Every change SuperMgmt makes starts as a plan. Policy decides whether you may submit that plan, and whether it must wait for someone to approve it first. An approval is bound to the exact plan it was given for: if anything in the plan changes, the approval no longer counts.

This page explains how a decision is made, what the built-in policy allows, and how to write your own policy file.

## How a request is decided

When a person, an automation or an AI agent asks for an action, SuperMgmt evaluates it in this order, for every target the plan touches:

1. **Known action.** The action must be in the catalog. Anything else is denied.
2. **Capability.** The target must support the action (for example, a service restart needs a node that was set up). If not, the answer is `capability_unavailable`, not a denial.
3. **Matching rules.** A rule matches when one of its subjects designates the caller, one of its resources matches the target, and one of its patterns matches the action.
4. **Deny wins.** If any matching rule denies the action, it is denied, whatever other rules allow.
5. **Default deny.** If no matching rule allows it, it is denied.
6. **Destructive gate.** A destructive action also needs an allowing rule with `allow_destructive: true`.
7. **Credential scopes.** An API token with scopes can only do what its scopes also cover. Scopes narrow; they never grant.
8. **Approval and quorum.** The action may need approval, and from how many people (see [When approval is required](#when-approval-is-required)).

A plan with several targets is denied if any target is denied. It needs approval if any target needs it, and its quorum is the largest among its targets.

Every denied request is written to the audit log, not only the accepted ones.

## Who is who

Rules name subjects:

| Subject | Matches |
|---|---|
| `role:<name>` | an identity bound to that role. The built-in roles are `viewer`, `operator`, `deployer` and `admin` |
| `type:<type>` | every identity of that type: `human`, `automation`, `mcp` |
| `identity:<id>` | one identity, by its ID |
| `*` | everyone |

In local mode, your OS user is a `human` identity bound to `admin` the first time the daemon starts. On a server, an administrator grants roles with `sm admin grant <identity-id> <role>`.

An MCP client is an identity of type `mcp` with **no roles**, even when an admin registered it. It can only do what a rule naming `type:mcp` allows. See [AI agents with MCP](mcp.md).

## The built-in policy

Without a policy file, SuperMgmt uses the built-in policy, [`internal/policy/default.yaml`](../internal/policy/default.yaml):

| Rule | Who | May |
|---|---|---|
| `builtin-read` | `viewer`, `operator`, `deployer`, `admin` | read everything (`*.read`), read service logs, open interactive sessions, create plans |
| `builtin-operator` | `operator`, `admin` | start, stop and restart services, probe and reboot nodes, power Proxmox guests, create Proxmox snapshots and backups, cancel and resolve jobs |
| `builtin-deployer` | `deployer`, `admin` | create and roll back deployments, cancel jobs, run the pre-deploy backup |
| `builtin-approver` | `operator`, `deployer`, `admin` | approve and reject plans |
| `builtin-admin` | `admin` | configuration, environments, providers, nodes, apps, identities and roles, MCP clients, tokens, enrollment, secrets, backups, node setup |
| `builtin-mcp-read` | `type:mcp` | read everything (`*.read`) and create plans. Nothing else: no logs, no sessions, no writes |

No built-in rule sets `allow_destructive`, so destructive actions (deleting a provider, removing a node, deleting a snapshot) are denied until your own policy allows them explicitly.

## When approval is required

An allowed action waits for approval when **any** of these holds:

- an allowing rule says `require_approval: true`;
- the action is high risk or destructive;
- the caller is an MCP client and the action is operational or riskier;
- the target is in an environment with `risk_level: production` and the action is operational or riskier, unless an allowing rule says `require_approval: false` and the caller is a human or an automation.

Reads, queries and governance actions (approving, rejecting, cancelling, resolving) never wait for approval. The high-risk rule and the MCP rule cannot be switched off by any policy.

Actions that issue credentials (`token.create`, `mcp_client.issue_token`, `enrollment.create`) cannot wait for approval. A rule with `require_approval: true` that covers one of them is rejected when the file is loaded; if anything else would make them wait, they are denied instead.

### How many approvals

The quorum is the largest of: 1, the environment's `approvals_required`, and the `approvals` of every allowing rule that matched. It is never more than 5.

Approvals count only when they come from distinct people who are still allowed to approve the plan. Each approval expires after `security.approval_ttl` (15 minutes by default). A single rejection is final.

### Approving your own plans

`security.allow_self_approval` decides whether the person who asked for a plan may approve it. It defaults to `true` in local mode, where you are usually the only user, and to `false` on a server. Only humans can approve their own plans. MCP clients and the system identity can never approve or reject anything.

### What an approval binds to

A plan lists every input that can change what runs, and is identified by the hash of those inputs. You approve that hash. Just before the job runs, SuperMgmt rebuilds the plan from the current state: if the hash differs, the job fails with `PLAN_STALE`; if the plan expired, with `PLAN_EXPIRED`. Credentials, policy and quorum are checked again at that moment.

## Approving from the CLI and the TUI

```sh
sm approvals                 # what is waiting, with the plan hash of each
sm approvals --plan          # the same, with every plan in full
sm jobs approve <job-id> --plan-hash <hash>
sm jobs reject <job-id> --plan-hash <hash> --reason "wrong maintenance window"
```

`--plan-hash` is required: it binds your decision to the plan you reviewed. In the TUI, open Approvals with `4`, read the plan, and press `A` to approve or `R` to reject ([Using the TUI](tui.md#approving-and-rejecting)).

## Write your own policy

Set `security.policy_file` in the [configuration](configuration.md) to the path of a YAML file. That file **replaces** the built-in policy entirely: any built-in rule you do not copy is gone, including the ones that let `admin` do anything at all.

So start from the built-in rules and add yours:

1. Copy [`internal/policy/default.yaml`](../internal/policy/default.yaml) to, for example, `~/.config/supermgmt/policies.yaml`.
2. Add your rules at the end.
3. Check the file:

   ```sh
   sm config validate --policy ~/.config/supermgmt/policies.yaml
   ```

   The `policy:` line says whether the file is valid and how many rules it has, then lists the rules you added, removed or changed compared with the built-in policy. The command also checks your configuration file: if you have none yet, the `config:` line says so and the command exits 2, but the policy is still checked.
4. Point `security.policy_file` at the file. The daemon reads the policy only when it starts, so the new rules apply from its next start.

### A worked example

These rules, added after the built-in ones, pass `sm config validate --policy`:

```yaml
  - name: production-two-approvers
    subjects: ["role:deployer", "role:admin"]
    resources: ["environment:production"]
    allow: ["deployment.create", "deployment.rollback"]
    require_approval: true
    approvals: 2
  - name: no-reboots-on-databases
    subjects: ["*"]
    resources: ["tag:database"]
    deny: ["node.reboot", "proxmox.vm.power"]
  - name: mcp-logs-staging
    subjects: ["type:mcp"]
    resources: ["environment:staging"]
    allow: ["service.logs"]
  - name: admins-may-remove-nodes
    subjects: ["role:admin"]
    allow: ["node.remove"]
    allow_destructive: true
```

- `production-two-approvers`: production deployments and rollbacks need two different approvers. With a single person and self-approval, they can never collect two, so this rule only makes sense with a second person.
- `no-reboots-on-databases`: nobody may reboot or power-cycle a node tagged `database`, whatever the other rules allow.
- `mcp-logs-staging`: MCP clients may read service logs in staging. Read [the redaction boundary](mcp.md#the-redaction-boundary) before you grant this: secrets under harmless names in logs reach the model.
- `admins-may-remove-nodes`: lets admins remove a node, which is destructive. Removal is still high risk, so it still waits for approval.

[`examples/policies.yaml`](../examples/policies.yaml) shows more rule shapes, including one for a CI automation identity. It is a set of examples, not a complete policy: on its own it grants nothing to `admin`.

## Rule reference

A policy file has `version: 1` and a list of `rules`. Decoding is strict: an unknown field, a duplicate key or a second YAML document is an error, and the error names the line.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Unique within the file |
| `subjects` | yes | Who the rule is about: `role:`, `type:`, `identity:` or `*` |
| `resources` | no | Which targets: `environment:`, `tag:`, `provider:`, `node:`, `app:` or `*`. Entries are alternatives; leaving the list out matches every target |
| `allow` | one of `allow`, `deny` | Action patterns the rule allows |
| `deny` | one of `allow`, `deny` | Action patterns the rule denies. A matching deny always wins |
| `require_approval` | no | `true` forces approval. `false` waives the production default for humans and automations; it cannot waive the high-risk or MCP rules |
| `approvals` | no | Minimum number of approvers, 1 to 5 |
| `allow_destructive` | no | Needed, on an allowing rule, for destructive actions |

**Action patterns** are dot-separated names such as `service.restart`. A `*` segment matches exactly one segment: `*.read` matches `node.read` and `deployment.read`, but not `service.logs` or `node.connect`. A bare `*` matches every action. An exact name must exist in the catalog, and a pattern with `*` must match at least one catalog action.

### Actions and their risk

The catalog is the complete list of actions a rule can name ([`internal/policy/catalog.go`](../internal/policy/catalog.go)). It also names actions for features that are not built yet; a rule may name them, but nothing asks for them.

| Risk | Actions |
|---|---|
| read | `node.read`, `service.read`, `service.logs`, `app.read`, `app_target.read`, `deployment.read`, `environment.read`, `provider.read`, `job.read`, `plan.read`, `event.read`, `config.read`, `identity.read`, `backup.read`, `node.connect`, `plan.create`, `node.probe` |
| operational | `service.start`, `service.stop`, `service.restart`, `proxmox.vm.power` (`stop` is high), `proxmox.snapshot.create`, `proxmox.backup.create`, `node.backup_template.run`, `deployment.create`, `deployment.rollback`, `backup.create`, `node.add`, `node.update`, `app.write`, `app_target.write`, `mcp_client.delete`, `token.revoke`, and the credential-issuing `token.create`, `mcp_client.issue_token`, `enrollment.create` |
| high | `node.reboot`, `node.shutdown`, `proxmox.snapshot.rollback`, `node.setup`, `sudoers.write`, `log_broker.install`, `provider.write`, `environment.write`, `config.write`, `secret.write`, `identity.write`, `role_binding.write`, `mcp_client.register` |
| destructive | `node.remove`, `provider.delete`, `proxmox.snapshot.delete` |
| governance | `approval.grant`, `approval.reject`, `job.cancel`, `job.resolve` |

## References

- Engine: `internal/policy/evaluate.go` (decision order and approval rules), `internal/policy/quorum.go` (counting approvals), `internal/policy/governance.go` (approving, rejecting, cancelling, resolving), `internal/policy/validate.go` and `internal/policy/parse.go` (the file format), `internal/policy/catalog.go` (actions and risk).
- Loading: `internal/daemon/assemble.go` (`security.policy_file`), `internal/cli/config.go` (`sm config validate --policy`), `internal/daemon/identity.go` (the local admin).
- Tests: `TestEvaluate_Step4_DenyOverrides`, `TestEvaluate_Step5_DefaultDeny`, `TestEvaluate_Step6_DestructiveGate`, `TestEvaluate_Step8_Approval`, `TestEvaluate_Step8_CredentialIssuingIsNeverApprovalGated`, `TestEvaluate_Step9_CompositePlans`, `TestEvaluate_DefaultPolicy_EndToEnd`, `TestEvaluateQuorum`, `TestEvaluateGovernance`, `TestPolicyProperty_NoAllowOverridesAMatchingDeny`, `TestPolicyProperty_AddingTargetsNeverRelaxesTheDecision`, `TestParse_Invalid`, `TestExamplePolicy_MatchesSpecBlockAndValidates`, `TestDiffPolicies_AgainstDefault`.
- Related pages: [Security](security.md), [Configuration](configuration.md#policy), [Deployments](deployments.md).
