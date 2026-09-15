# Systems Engineer / DevOps Take-Home

**Haidy Hossam** · September 2026

---

## Contents

- [Part 1 — The Multi-Tier Log Aggregator](#part-1--the-multi-tier-log-aggregator)
  - [1.1 Critical Analysis](#11-critical-analysis)
  - [1.2 Redesign](#12-redesign)
  - [1.3 AI Verification](#13-ai-verification)
- [Part 2 — Automation & Data Manipulation](#part-2--automation--data-manipulation)
  - [2.1 The Edge Case Break](#21-the-edge-case-break)
  - [2.2 The Modern Alternative](#22-the-modern-alternative)
- [Part 3 — Production Escalation](#part-3--production-escalation)
- [Part 4 — System Architecture Diagram](#part-4--system-architecture-diagram)
- [What's in this repository](#whats-in-this-repository)
- [Running this](#running-this)

---

# Running this

Nothing here needs AWS credentials or spends money.

**The tool and its tests** — no install, Python 3.8+ only:

```bash
python3 -m unittest discover -s tools -v     # expect: Ran 40 tests ... OK
./tools/demo_failure_modes.sh                # side-by-side failure reproduction
```

The demo needs GNU grep, because the script under review uses `grep -P`. On
macOS, BSD grep has no `-P` at all — which is failure mode #1 from Part 2,
demonstrating itself. The script detects this and tells you; `brew install grep`
provides GNU grep as `ggrep` and it will pick that up automatically.

**The infrastructure** — needs Terraform 1.13+:

```bash
cd terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test                                # mock provider: no credentials, no resources
```

`terraform test` runs the guardrail suite against a mocked provider, so it
completes in seconds and creates nothing.

Optional static analysis, if you have them: `tflint --recursive`,
`checkov -d . --framework terraform`, `trivy config .`

---

# Part 1 — The Multi-Tier Log Aggregator

## 1.1 Critical Analysis

The snippet has more than three problems, so rather than list twelve at equal
weight I've grouped them by what actually happens when you run it, and led with
the four that would keep me up at night.

### The four that matter most

**1. The security group is not "permissive". It is absent.**

```hcl
ingress {
  from_port = 0
  to_port   = 0
  protocol  = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
```

`protocol = "-1"` with ports `0-0` means *all protocols, all ports*, from the
entire internet. Not port 443, not "the app port and SSH" — everything. SSH,
the Kubernetes API if it were running, the debug endpoint someone left on 8080,
whatever the log agent binds to.

The scenario says this box processes **high-volume, real-time transaction
data**. So the exposure is not "an instance gets popped and we rebuild it". It
is an internet-reachable host holding transaction logs, which in almost any
regulated context is a reportable breach. It fails CIS 4.1/4.2, PCI-DSS 1.2.1
and SOC 2 CC6.1, and GuardDuty and Security Hub will both flag it within the
hour.

Worth stating plainly: this is not a tuning problem. There is no legitimate
production reason for an ingress rule shaped like this, which is why the
redesign has **zero ingress rules by default** rather than narrower ones.

**2. There is no IAM role, which forces a worse problem.**

No `iam_instance_profile` means this instance has no AWS identity. It needs to
write logs somewhere. So either it cannot do its job, or — far more likely —
somebody put static access keys in userdata, in an environment file, or baked
into the AMI.

That is how long-lived credentials end up committed to a repo. The absence of
an IAM role doesn't just miss a best practice; it actively creates pressure
toward the worst available alternative. Combined with flaw 1, an attacker who
reaches this host gets credentials that don't expire and aren't scoped.

**3. `security_groups` is the wrong argument, and the way it's wrong is subtle.**

```hcl
security_groups = ["allow_all_traffic"]
```

Two distinct bugs stacked on each other:

- `security_groups` on `aws_instance` is the **EC2-Classic** argument and takes
  group *names*. In a VPC you must use `vpc_security_group_ids` and pass IDs.
  In a non-default VPC this fails outright; where it does work it forces
  instance replacement on changes.
- It's a **hardcoded string**, not `aws_security_group.allow_all.name`. Terraform
  builds its dependency graph from references. With a literal string there is
  no edge between the instance and the security group, so Terraform is free to
  create them in parallel — and on a cold apply it frequently creates the
  instance first and fails, or attaches a stale group of the same name left
  over from a previous environment.

The second one is the more instructive bug. It looks like it works, it passes
review, and it fails intermittently on fresh applies — which is the worst
possible failure schedule.

**4. The security group has no `egress` block, which silently breaks the app.**

This one is my favourite because it is invisible.

AWS gives every new security group a default allow-all egress rule. Terraform's
`aws_security_group` resource is authoritative for its rules, and [deliberately
removes that default rule](https://github.com/hashicorp/terraform/pull/1765)
when you declare the resource without an `egress` block.

So the net effect of this configuration is: **the whole internet can reach the
log processor, and the log processor can reach nothing.** It cannot ship logs
to S3, call CloudWatch, or reach a downstream collector. The apply succeeds,
the instance boots, the dashboard is green, and no logs arrive.

You get the security posture of a public server with the functionality of an
air-gapped one — precisely backwards.

### The rest

**Availability and scaling**

5. **Single instance, single AZ, no self-healing.** One `aws_instance` is a
   single point of failure for the entire log pipeline. No ASG, no health check,
   no replacement. The instance dies at 2am and logging is down until a human
   notices — and the logs from that window are gone permanently, because logs
   are not a thing you can go back and collect.

6. **`t2.micro` is the wrong shape of instance, and it fails quietly.** T-family
   instances run on CPU credits. Sustained high-volume log parsing exhausts the
   credit balance within the hour, after which the instance is throttled to its
   baseline — 10% of one vCPU. It does not crash. It does not alarm. CPU
   utilisation *drops*, because there's no CPU left to utilise. Every dashboard
   says healthy while the pipeline falls further and further behind. A crash
   would be better; at least a crash pages someone.

7. **No buffering, so back-pressure has nowhere to go.** If the downstream sink
   slows down, the process buffers in memory until the OOM killer arrives.

**Durability**

8. **Logs are processed on ephemeral local storage.** Instance terminates,
   in-flight data is gone, and there is no way to enumerate what was lost, let
   alone replay it. For transaction logs this is usually the most expensive flaw
   on the list — it's the one that becomes an audit finding.

9. **No archive, no retention policy, no replay.** Nothing states how long logs
   are kept or where. That's a compliance question answered by accident.

**Terraform hygiene**

10. **Hardcoded AMI ID with a comment that can't be verified.**
    `ami-0c55b159cbfafe1f0` is region-scoped — it means nothing outside
    `us-east-1`. The comment says "Ubuntu LTS"; this particular ID circulates in
    old AWS tutorials where it's generally cited as an Amazon Linux image. I
    can't confirm either from the code, **and that's the actual point**: the
    configuration asserts something about the OS that nothing in the
    configuration can verify. It's also an unpatched, frozen dependency — pinned
    to whatever CVEs existed the day it was published. Use an SSM public
    parameter, or a golden AMI from Image Builder with an explicit version.

11. **Security group uses `name`, not `name_prefix`, with no
    `create_before_destroy`.** Any change forcing replacement fails twice over:
    AWS refuses the duplicate name, and the old group can't be deleted while
    ENIs still reference it. This is the classic way a security group change
    deadlocks an apply mid-incident.

12. **Tags are a single `Name`.** No Environment, Owner, CostCentre or
    DataClassification. Cost allocation is impossible, incident routing is
    manual, and "which of our resources hold regulated data" has no answer.

13. **No `required_version`, no provider constraints, no backend.** State is
    local, so there is no locking and no team workflow, and a provider upgrade
    can change resource behaviour under you without a diff. (Provider 6.57.0 was
    withdrawn earlier this year — pinning is not paranoia.)

---

## 1.2 Redesign

Full working configuration in [`terraform/`](terraform/). What follows is the
reasoning; the code carries the detail.

### The decision that shapes everything else

The snippet describes an instance that *receives* logs. I deleted that
requirement.

The rewritten pipeline is **pull-based**: producers write to a Kinesis stream,
and the processor fleet consumes from it.

![Log Aggregator Redesign Before and After](diagram/diagram2.svg)

```
producers ──▶ Kinesis Data Stream ──▶ processor fleet ──▶ Firehose ──▶ S3 (Parquet)
              (7-day replay)          (ASG, 3 AZ, Spot)              │
                                                                     └─▶ Athena
```

Three things follow from that one change, and they are the whole redesign:

- **The fleet needs no inbound ports at all.** Not narrower rules — none. You
  cannot misconfigure an ingress rule that doesn't exist.
- **The processors become stateless and disposable.** Losing one costs a shard
  lease handover, not data. That in turn makes Spot instances safe, which pays
  for most of the multi-AZ redundancy.
- **A bad deploy becomes recoverable.** With a 7-day retention window, a parser
  bug means: roll back, reset the KCL checkpoint, reprocess. Without the buffer,
  a bad parser silently destroys data you can never get back. This is the
  single most valuable property in the design and it's why the buffer comes
  before the compute in my priority order.

I've kept an optional internal NLB behind `enable_direct_ingest` for legacy
appliances that can only emit syslog over TCP, because "how do the old JVM
services get in" is the first honest objection to a pull-based design and I'd
rather answer it in code than hand-wave it.

### Security

| Concern | Approach |
|---|---|
| Network exposure | Private subnets, **no IGW or NAT route**. Everything reached over PrivateLink — 9 interface endpoints plus S3/DynamoDB gateway endpoints. A compromised parser has nowhere to exfiltrate to. |
| Ingress | Zero rules by default. The optional syslog rule is scoped to the VPC CIDR, never `0.0.0.0/0`. |
| Shell access | SSM Session Manager. No port 22, no key pair, no key material to rotate or lose. IAM-authorised, CloudTrail-logged. |
| Credential theft | IMDSv2 `required` with `hop_limit = 1`. This is the Capital One mitigation: an SSRF in the parser can't read the role credentials, because it can't make the victim send a PUT with the right header. |
| At rest | One customer-managed KMS key with rotation, covering EBS, Kinesis, S3, SNS and CloudWatch Logs. A CMK rather than the AWS-managed key so we can scope decrypt by principal, revoke access without deleting data, and get a CloudTrail record of every `Decrypt`. |
| In transit | Bucket policy denies `aws:SecureTransport = false` and denies writes under any other KMS key. |
| IAM | Every statement scoped to specific ARNs. The two that can't be (`PutMetricData`, `kms`) are constrained by `cloudwatch:namespace` and `kms:ViaService` conditions instead. The processor role has **no** `kinesis:PutRecord` — it consumes, it never produces, so a parser bug physically cannot write back into its own input stream. |
| Confused deputy | Firehose's assume-role policy requires `sts:ExternalId` and `aws:SourceAccount`. |

### Availability

Auto Scaling group across every AZ provided, `min_size` validated `>= 2`, health
checks, automatic replacement, and `instance_refresh` for rolling deploys with
checkpoints at 25/50/100% and `auto_rollback`.

A mixed-instances policy keeps an On-Demand floor and bursts on Spot using
`price-capacity-optimized` across three Graviton types. Spot is defensible here
*specifically because* of the pull-based design: a reclaimed worker drops its
lease, a peer picks up the shard, and processing resumes from the last
checkpoint. An `aws_autoscaling_lifecycle_hook` gives a terminating worker 120
seconds to finish its batch and checkpoint first, which shrinks the duplicate
window to near zero.

Two scaling policies, because they answer different questions:

- **CPU target tracking at 55%** — handles the normal daily curve.
- **Step scaling on `GetRecords.IteratorAgeMilliseconds`** — handles *falling
  behind*, which CPU alone will never detect. A fleet blocked on a slow
  downstream sits at 40% CPU while the backlog grows.

(The interaction between those two turned out to be the most interesting thing
the review pass found — see §1.3.)

There's also a `terraform_data` precondition that fails the plan if the supplied
subnets resolve to fewer than two AZs. "Three subnets, all in `eu-west-1a`"
passes code review every time and only reveals itself during an AZ event.

### Durability

Kinesis with 7-day retention is the replay window — long enough that an incident
starting on Friday evening is still recoverable on Monday. Firehose lands
Parquet in S3 with Hive-style date partitions, versioning, lifecycle tiering to
Glacier IR, a 7-year expiry driven by the retention policy rather than by
storage cost, and optional Object Lock for a tamper-evident audit archive.
Failed records go to an `errors/` prefix rather than being dropped.

### Observability

Alarms on iterator age, Firehose freshness, Parquet conversion failures, fleet
capacity, and producer throttling — wrapped in a composite alarm so an incident
pages once rather than six times.

The one I'd keep if I could only have one is **`no-records-processed`**, with
`treat_missing_data = "breaching"`. Every other alarm fires when something
breaks. That one fires when everything goes *quiet*, which on a log pipeline is
the failure that actually costs you: you cannot retroactively collect logs you
never ingested. An alarm that treats missing data as OK will sit green while the
pipeline is stone dead.

### Testing the guardrails

[`terraform/tests/guardrails.tftest.hcl`](terraform/tests/guardrails.tftest.hcl)
uses Terraform's native test framework with `mock_provider`, so it runs in
seconds with no AWS credentials and belongs in the PR pipeline.

Each test asserts one property that, if it regressed, would reintroduce exactly
the flaw the redesign exists to fix — no `0.0.0.0/0` ingress, no port 22, IMDSv2
required, no key pair, everything encrypted, `min_size >= 2`, no burstable
instance types, retention long enough to survive a weekend. Plus `expect_failures`
cases proving that single-AZ input and `min_size = 1` are rejected at plan time.

This is how "we fixed the open security group" becomes "the open security group
cannot come back."

---

## 1.3 AI Verification

I gave the rewritten module to Claude with the instruction to act as a hostile
reviewer and find things that would break in production rather than style
issues. I've picked three responses: one I accepted immediately, one I accepted
only after checking, and one I pushed back on.

### The critique I found most interesting

> **Your two scaling policies will fight each other, and they'll fight hardest in
> exactly the scenario you built the second one for.**
>
> The target-tracking policy on `ASGAverageCPUUtilization` has
> `disable_scale_in = false`, so it creates both a scale-out and a scale-in
> alarm and will remove capacity whenever average CPU sits below 55%.
>
> Now consider the case your step policy exists to handle: consumers blocked on
> a slow downstream. Iterator age climbs, so the step policy adds 50% capacity.
> The new instances come up and block on the same slow downstream, so they're
> idle too. Average CPU stays low — arguably drops, since you've diluted it
> across more instances. The CPU policy now sees a fleet well below target and
> starts scaling in, while the backlog keeps growing.
>
> ASG conflict resolution favours the larger capacity at any given instant, so
> you won't scale to zero, but the two policies' cooldowns interleave and you
> get sustained churn — instances launching and terminating, each one paying
> the lease-acquisition cost, while the actual backlog is unaddressed.

**I agree, completely, and I've changed the code.** `disable_scale_in = true` on
the target-tracking policy.

I like this critique because it's the kind of bug that doesn't exist in either
policy on its own. Read `aws_autoscaling_policy.cpu` in isolation: correct. Read
`aws_autoscaling_policy.backlog` in isolation: correct. The defect lives in the
interaction, under a specific load shape, and it would have presented in
production as "the ASG is being weird during incidents" — which is exactly the
kind of thing that gets explained away rather than diagnosed.

It also sharpened my thinking about *which signal owns which direction*. CPU
knows whether we're working hard. Only iterator age knows whether we're **done**.
So CPU may scale out; only the backlog policy may scale in. That's a cleaner
rule than the one I'd originally implemented, and I'd not have articulated it
without being pushed.

### The critique I accepted only after verifying it

> **Your Glue table will return zero rows in Athena.** Firehose writes to
> `raw/dt=YYYY-MM-DD/` as configured, but a Glue partition key is only
> queryable once the partition is *registered*, and Firehose doesn't register
> anything. You need a crawler, `MSCK REPAIR TABLE`, or partition projection.

I didn't take this on trust, because "your code silently returns nothing" is
both a serious claim and an easy thing for a model to assert confidently. I
checked it against AWS's own documentation, which has [a dedicated Athena page
for exactly this Firehose case](https://docs.aws.amazon.com/athena/latest/ug/partition-projection-kinesis-firehose-example.html).
The critique is correct.

Fixed with partition projection rather than a crawler: projection computes the
partition list from the query predicate, so there's nothing to register, nothing
to fall behind, and no per-partition metadata call. A crawler costs money, adds
minutes of lag and silently drifts; `MSCK REPAIR` gets slower every single day.

This one is worth flagging because of its failure signature. The apply succeeds.
The console looks perfect. Objects are visibly landing in S3. And the people who
actually need the data get an empty result set, which they'll assume means "no
matching logs" rather than "the table is broken."

### The critique I pushed back on

> **Drop `disable_api_termination` from the launch template — it will block
> Auto Scaling from terminating instances and break both scale-in and instance
> refresh.**

I checked this one too, and the reasoning as stated is **not quite right**: EC2
termination protection and ASG *instance scale-in protection* are distinct
mechanisms, and the ASG is not simply blocked by the former in the way the
critique implies.

**But I removed the setting anyway, for a different reason.** Putting
termination protection on an instance owned by an Auto Scaling group is fighting
the component whose entire job is terminating instances — scale-in, unhealthy
replacement and instance refresh all work by terminating. Even where the
behaviour is benign it's semantically confused, and confusion at that layer is
how you end up debugging a stalled instance refresh during an incident.

What I actually wanted was protection against a human running `terraform
destroy` against prod. That belongs at the Terraform and CI layer — plan review,
a protected workspace, a pipeline that refuses destroy plans on the prod branch
— not at the EC2 API. Right instinct, wrong layer.

### Two more it raised that I fixed without argument

- **The ASG used a fixed `name` with `create_before_destroy`** — the exact
  duplicate-name deadlock I'd written a comment warning about on the security
  group, twenty lines earlier, and then walked straight into. Switched to
  `name_prefix` and widened the corresponding IAM ARN.
- **`instance_refresh.triggers` listed `desired_capacity`, which is in
  `ignore_changes`** — a trigger that can never fire. Harmless, but it reads
  like intent and would mislead the next person.

### What I take from the exercise

The review was worth doing and it made the code better. Two observations about
*how* it was useful, though:

The valuable findings were all about **interactions** — two policies, a
Firehose prefix and a Glue table, a lifecycle rule and a resource name. Those
are exactly the defects that survive human review, because we read resources one
at a time. That's a real complement to how I work, not a substitute for it.

The failure mode runs the other way. The `disable_api_termination` critique was
confidently argued and mechanically wrong, and the Glue one was confidently
argued and right — and they were indistinguishable in tone. Both needed
verification against primary sources before I'd act on either. I'd apply the
same rule to a very senior human reviewer, so this isn't a complaint about AI
specifically; it's just that the volume and fluency of the output makes it much
easier to skip the verification step, and the cost of skipping it is a
plausible-sounding change to production infrastructure.

---

# Part 2 — Automation & Data Manipulation

```bash
#!/bin/bash
grep "Failed login" app.log | grep -oP "Username=\[\K[^\]]+" | sort |
uniq -c | sort -nr | head -n 5
```

## 2.1 The Edge Case Break

The script is fine as something you type once while watching the output. The
problem is what happens when nobody's watching — and the single sentence that
captures it is:

> **Every one of its failure modes produces empty output and exit status 0.**

To cron, systemd or a CI job, "the log format changed six weeks ago" is
indistinguishable from "no failed logins today". It doesn't break loudly; it
starts lying quietly.

[`tools/demo_failure_modes.sh`](tools/demo_failure_modes.sh) reproduces each of
these side by side against real fixtures. Actual output:

| Scenario | Original | Exit | Replacement | Exit |
|---|---|---|---|---|
| Standard format | `2 alice`, `1 bob` | 0 | `2 alice`, `1 bob` | 0 |
| App migrated to JSON logging | *(nothing)* | **0** | `2 alice`, `1 mallory` | 0 |
| Input file missing | *(nothing)* | **0** | refuses to report | **4** |
| Log injection via forged bracket | `3 eve`, **`3 admin`** | 0 | `3 eve` | 0 |
| Mixed-case event markers | `1 dave` *(missed 2 of 3)* | 0 | `3 dave` | 0 |

### The scenario I'd actually bet on: structured logging

The most likely thing to break this script is not load or a weird character. It
is a routine, well-intentioned migration to JSON logging:

```json
{"timestamp":"2026-09-14T11:00:01Z","event":"Failed login","username":"alice"}
```

Nothing errors. `grep "Failed login"` still matches the line — the phrase is
right there in the JSON. But `Username=[...]` doesn't exist any more, so the
second grep yields nothing, and the pipeline prints nothing and exits 0.

The security dashboard reads zero failed logins. Forever. Nobody investigates
zero.

This is worse than a crash in a specific, important way: a crash gets fixed in
an hour. This gets discovered during an incident review six months later, when
someone asks why there's no record of the credential-stuffing campaign.

### The rest, by category

**Silent tooling failures**

`grep -P` requires PCRE support compiled in. On Alpine/BusyBox, on macOS with
BSD grep, and on any minimal container image, `-P` either isn't supported or
isn't compiled in. The error goes to stderr, the pipeline continues, output is
empty, exit status 0. Moving this script into a slim container image breaks it
without a single line changing.

**Exit codes that mean the opposite of what you'd think**

- Missing `app.log`: `grep` writes to stderr and exits 2, but the pipeline's
  status is `head`'s, which is 0. **Cron records a successful run over a file
  that doesn't exist.**
- Add `set -o pipefail` to harden it and you get the reverse problem:
  `head -n 5` closes the pipe, `sort` dies on SIGPIPE, and the pipeline returns
  **141** on a completely successful run. I verified this — `seq 1 200000 | sort
  -nr | head -n 1` under `pipefail` exits 141. So the unhardened version fails
  open and the hardened version fails closed at random. Neither is monitorable.

**Log rotation**

The script reads exactly one static path. Under logrotate:

- with `create`: `app.log` is a brand new empty file. Every count resets at
  rotation time, and everything in `app.log.1` and `app.log.2.gz` is invisible.
- with `copytruncate`: there's a window where the file is being copied and
  truncated mid-read, and you get a partial result with no indication.

Either way the numbers reset on a schedule nobody correlates with the graph.

**Volume**

`sort` on a multi-GB extraction spills to `/tmp`. On a host with a small `/tmp`
you get `sort: write failed: No space left on device` — partial output, exit 0 —
or you fill the disk and take the application down with the monitoring tool.
Algorithmically it's O(n log n) time and O(n) disk to answer a question that's
O(n) time and O(distinct) memory with a hash map.

There's also no incremental read: every run rescans the entire file from byte
zero, so cost grows linearly with file age and every event is counted again on
every run.

**Correctness**

- **Case sensitivity.** `grep "Failed login"` misses `failed login`,
  `FAILED LOGIN` and `Failed_Login`. In the demo above it caught 1 of 3 real
  events.
- **Log injection.** `[^\]]+` trusts a delimiter an attacker controls. A user
  who registers as `eve] Username=[admin` causes the script to report failed
  logins against `admin` that never happened — verified in the demo, which shows
  the original inventing `3 admin` out of nothing. An attacker can steer your
  security dashboard.
- **Nondeterministic tie-breaking.** `sort -nr | head -n 5` breaks count ties by
  whatever order the previous sort produced. Two runs over identical data can
  disagree about who's fifth, which makes the output undiffable.
- **False positives.** A Java stack trace containing the phrase "Failed login",
  or a request URL with it in a query parameter, counts as an event.

**The analytical flaw underneath all of it**

Even when it works perfectly, it counts **all of history**. There's no time
window. So a brute-force incident from three months ago permanently dominates
the top 5, and the tool reports the same five names every day regardless of what
is happening right now.

That makes it a historical trivia query wearing the costume of a monitoring
tool. Every other issue on this list is a bug; this one is a category error.

**Hanging**

Pointed at a FIFO or a named pipe, `grep` blocks forever — in a cron job,
holding whatever lock it holds, with no output and no timeout. Same on a stale
NFS mount.

---

## 2.2 The Modern Alternative

[`tools/log_analyzer.py`](tools/log_analyzer.py) — Python 3.8+, **standard
library only**, with a [40-test suite](tools/test_log_analyzer.py) that passes.

```
$ python3 -m unittest discover -s tools
Ran 40 tests in 3.3s
OK
```

### Why stdlib-only

This is a deliberate constraint, not laziness. A monitoring tool that needs
`pip install` cannot run on the legacy hosts it exists to monitor — the ones
with no network egress, an old system Python, and a change freeze. Zero
dependencies means it also can't break because of a transitive dependency
update, and the same file runs identically on a 2015 VM and in a distroless
container.

### The core design principle

> A monitoring tool that can't distinguish "nothing bad happened" from "I am
> broken" is worse than no monitoring tool, because it manufactures confidence.

Every feature below exists to make that distinction impossible to miss.

### What it does

**Fails loudly instead of quietly.** Six documented exit codes — `0` OK,
`2` threshold breached, `3` format drift, `4` no input, `5` cardinality guard,
`1` internal error. Missing input is an *error*, not an empty result:

```
$ log_analyzer.py --path /var/log/absent.log
no readable files matched '/var/log/absent.log'. Refusing to report zero
failures from zero files: that is indistinguishable from a healthy system.
$ echo $?
4
```

**Detects its own obsolescence.** It tracks lines *recognised* separately from
events *matched*. If it reads a meaningful number of lines and understands
almost none of them, the schema has moved and every number it could print is a
lie — so it exits 3 instead. Crucially, a healthy log full of `INFO Successful
login` lines is **not** drift, and there's a test asserting exactly that,
because a drift detector that cries wolf gets disabled within a week.

**Parses both formats.** Legacy `Username=[...]` and JSON, with case-insensitive
event matching and several common key spellings. The JSON migration that kills
the original is a non-event here.

**Windows by time.** `--window 15m` turns the all-time trivia query into an
operational signal.

**Resists log injection.** Extracted usernames are validated against a charset;
anything outside it is counted under a `<invalid-username>` sentinel and
reported separately, never echoed into a dashboard or an alert body. The forged
bracket that makes the original invent `3 admin` produces `3 eve` here.

**Streams in constant memory.** One line at a time, a hash map for counts, and
`heapq.nsmallest` for the top N. There's a `tracemalloc` test asserting that 30×
the input volume doesn't increase peak memory — `sort | uniq -c` fails that test
by construction.

**Guards cardinality explicitly.** A credential-stuffing run against generated
usernames produces unbounded distinct keys. Rather than being OOM-killed during
the incident it was built to detect, it stops counting at a configurable
threshold and reports the condition — which is itself a strong attack signal.

**Checkpoints correctly across rotation.** State is keyed by `(device, inode)`,
not path, so `create` rotation starts cleanly at the new inode and
`copytruncate` is detected (offset > size) and restarted rather than seeking
past EOF and reading nothing forever. Checkpoint writes are atomic via
`os.replace`. Rotated `.gz` files are read once and marked consumed.

**Won't hang.** FIFOs and character devices are refused at discovery.
`--max-seconds` enforces a wall-clock budget, checkpointing progress before it
exits so the next run resumes rather than restarting and timing out at the same
place forever.

**Emits machine-readable output by default** — JSON, Prometheus exposition, or
CloudWatch EMF. EMF means CloudWatch extracts real metrics from stdout with no
`PutMetricData` call, no extra IAM permission and no API latency in the hot path.

### Deployment

Same binary, two schedulers:

- [`tools/deploy/failed-login-monitor.{service,timer}`](tools/deploy/) —
  systemd, for the legacy hosts. `Type=oneshot` with a hard `TimeoutStartSec` so
  a slow run can't overlap the next one and corrupt the checkpoint; `MemoryMax`
  and `CPUQuota` so the monitor can never be the cause of the incident;
  `ProtectSystem=strict` with a read-only log path; and `RandomizedDelaySec` on
  the timer so the whole fleet doesn't hit the same downstream at `:00` — the
  same thundering-herd shape that shows up in Part 3.
- [`tools/deploy/cronjob.yaml`](tools/deploy/cronjob.yaml) — Kubernetes
  CronJob with `concurrencyPolicy: Forbid`, `readOnlyRootFilesystem`, dropped
  capabilities and a memory limit sized so that the cardinality guard trips
  *before* the OOM killer does.

### The honest caveat

At Smartology's scale this script is the *portable fallback*, not the
destination. The real answer is the Part 1 pipeline: emit structured JSON at
source, land it in the log lake, and answer "top 5 failed logins in the last 15
minutes" with an Athena query or a CloudWatch Logs Insights query over indexed
Parquet — no host-local file parsing at all.

Two reasons this tool still earns its place:

1. **Legacy hosts that will never emit to Kinesis.** There are always some, and
   they're usually the ones you most want visibility into.
2. **It's an independent check on the pipeline.** Running it against a host's
   local logs and comparing the count to what the lake reports is a genuine
   end-to-end test of the ingestion path. When those two numbers diverge, you've
   found a real bug — and you found it with something that has no shared failure
   modes with the pipeline it's checking.

---

# Part 3 — Production Escalation

**Situation:** blue-green cutover completes, load balancer shifts traffic to
green, database CPU immediately hits 100% on a wave of reads, web tier starts
dropping client connections.

## First principle: the rollback is the diagnosis

Blue is still running, still warm, still at full capacity. That is the entire
reason we paid for blue-green.

**So the first decision is not "what's wrong" — it's "shift traffic back to
blue."** Target 60–90 seconds. Diagnose afterwards, with the site up, on a green
environment I can take my time with.

I want to be precise about why, because "just roll back" can sound like avoiding
the question. Under this specific failure the database is saturated, so *blue is
degrading too* — it shares the database. Every minute spent diagnosing is a
minute of customer-visible errors, and a saturated database makes diagnosis
harder anyway: everything is slow, so everything looks like the cause.

**The one check before rolling back**, which takes about fifteen seconds: did
this release run a schema migration? If green applied a migration that blue's
code can't read — a dropped column, a renamed table, a changed type — rolling
back trades a performance incident for a correctness incident, and correctness
incidents corrupt data. If a migration ran and isn't backward-compatible, I fix
forward under a maintenance page instead.

(This is also the argument for expand-contract migrations as policy: it's what
keeps the rollback lever safe to pull, which is what makes the fast decision
possible.)

**Capture evidence before the rollback erases it.** Rolling back destroys the
state that explains the incident, so while traffic is shifting:

- Performance Insights screenshot — DB load by wait event, top SQL, last 15 min
- `pg_stat_statements` snapshot: `SELECT * FROM pg_stat_statements ORDER BY
  total_exec_time DESC LIMIT 20;`
- `pg_stat_activity` dump of currently running queries
- One thread dump / `py-spy dump` from a green instance
- ALB access logs for the cutover window

Thirty seconds of capture saves a week of "we never found out what happened."

---

## 3.1 What I check first, in order

The goal of the first five minutes is **not** to find the root cause. It's to
answer one question: *is the database doing more work, or the same work more
slowly?* Everything downstream of that is a different investigation.

### Minute 0–1 — Is it actually the database?

**CloudWatch, one dashboard, four metrics side by side:**

| Metric | Question it answers |
|---|---|
| RDS `CPUUtilization` + `DatabaseConnections` | Confirms the database is the constraint |
| RDS `ReadIOPS` / `ReadThroughput` | Is it CPU-bound (compute) or IO-bound (reads)? |
| ALB `TargetResponseTime`, `HTTPCode_Target_5XX`, `RejectedConnectionCount` | Confirms the impact and the shape |
| ASG/ECS `GroupInServiceInstances` / running task count | Did green come up with a different instance count than blue? |

**The highest-value thirty seconds in the whole incident:** compare
`DatabaseConnections` immediately before and after the cutover.

A **step change** in connection count — blue was 200, green is 600 — is a
connection-storm signature, and it points at configuration, not code. Every
green instance opens a full pool on startup, and if green has more instances, or
a larger `max_pool_size`, or the pool warms eagerly, you've multiplied your
connection count without changing a line of application logic. On PostgreSQL,
each connection is a backend process, and past a few hundred you're burning CPU
on context switching and lock contention rather than on queries.

If connections are flat and CPU is at 100%, it's query work. Different branch.

### Minute 1–3 — RDS Performance Insights

This is the tool that answers the question, and it's why Performance Insights
should be enabled on every production database *before* you need it.

**Database load by wait event** tells you the shape of the problem immediately:

| Dominant wait | Reading |
|---|---|
| `CPU` | Genuine compute — sequential scans, sorts, or an enormous volume of cheap queries |
| `IO:DataFileRead` | Reading from disk, so the working set no longer fits in the buffer cache — the classic missing-index or lost-plan signature |
| `Lock:*` / `LWLock` | Contention, not throughput. Long transactions or lock escalation |
| `Client:ClientRead` | The database is *waiting on the application* — the bottleneck is upstream |

**Top SQL, sorted by average active sessions**, gives the offending statement.

### Minute 3–5 — The discriminator

Take the top query and compare its `calls` and `mean_exec_time` against the
same query on the pre-deploy baseline.

---

## 3.2 Application code loop vs database limitation

This is the crux of the question, and there's a clean way to separate them.

> **One query running 50,000 times instead of 50 is an application problem.
> One query taking 4 seconds instead of 40ms is a database problem.**

Both present as "database CPU at 100%". They have almost nothing else in common.

```sql
-- On the green environment, after rollback. The `calls` column is the answer.
SELECT
  substring(query, 1, 100)          AS query,
  calls,
  round(mean_exec_time::numeric, 2) AS mean_ms,
  round(total_exec_time::numeric)   AS total_ms,
  rows / GREATEST(calls, 1)         AS rows_per_call
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 20;
```

### The decision table

| Signal | Application loop | Database limitation |
|---|---|---|
| `calls` for the top query | **Exploded** (10–1000×) | Roughly unchanged |
| `mean_exec_time` | Unchanged — each query is still fast | **Exploded** |
| `rows_per_call` | Often 1 — the N+1 signature | Unchanged or very large |
| Dominant wait event | `CPU`, many short queries | `IO:DataFileRead` |
| `EXPLAIN` plan vs baseline | Identical | **Changed** — seq scan where there was an index scan |
| Did the query text change? | Often unchanged — the *caller* changed | Often unchanged — the *plan* changed |
| Application CPU | Also elevated (it's issuing the calls) | Low — threads blocked waiting |
| Redis / cache hit rate | **Collapsed** | Unchanged |
| Behaviour under reduced traffic | Scales down linearly | Stays slow even when idle |

The last row is the cheapest decisive test. Shift 5% of traffic to green. If the
database calms down proportionally, it's volume — an application loop. If a
single query is still slow with almost no load on it, it's the query — an
indexing or plan problem.

### The four causes I'd check by name

In roughly descending order of how often I've actually seen each one cause this
exact symptom on a blue-green cutover:

**1. Green is reading from the writer instead of the reader endpoint.**

Far and away the most common blue-green database incident, and it matches the
symptom description *precisely*: "a massive wave of read requests."

The reader endpoint is usually configured per-environment, and green is a new
environment. A copy-pasted config, a missing environment variable falling back
to a default, a Terraform output wired to the wrong attribute — and suddenly
100% of read traffic that used to be spread over three replicas lands on the
primary.

**Thirty-second check:** compare `CPUUtilization` on the writer against the
readers. Writer pinned at 100% while the readers sit at 5% is conclusive. No
further investigation needed.

**2. Cold cache → stampede.**

If green points at a fresh ElastiCache cluster, or the deploy flushed the cache,
or cache keys are versioned by release, then every request is a miss and every
miss goes to the database. Worse, concurrent identical misses all issue the same
query — a cache stampede.

**Check:** ElastiCache `CacheHits`/`CacheMisses` ratio and `Evictions` across
the cutover. A hit rate that fell off a cliff at the exact cutover timestamp is
the answer.

This one is nasty because it's *self-inflicted by the deployment strategy*:
blue-green with a per-environment cache guarantees a cold start every release.

**3. An N+1 introduced by an ORM change.**

A new `include`/`select_related` that was removed, a lazy-loaded association
inside a loop, a serializer that now touches a relation. Signature: `calls` up
by orders of magnitude, `mean_exec_time` flat, `rows_per_call` = 1.

**Check:** one APM trace of a single slow request. If the waterfall shows 400
near-identical 2ms queries, that's your answer and the trace is the bug report.

**4. A plan regression.**

The migration added or dropped an index, or statistics are stale on a table that
grew, and the planner flipped from an index scan to a sequential scan.
Signature: `calls` flat, `mean_exec_time` exploded, waits dominated by
`IO:DataFileRead`.

**Check:** `EXPLAIN (ANALYZE, BUFFERS)` on the top query, compared to the same
plan from blue. A `Seq Scan` on a large table where blue had an `Index Scan` is
conclusive. Sometimes the fix is just `ANALYZE <table>`.

---

## 3.3 Mitigation

**Immediate**

1. Traffic back to blue (already done in the first 90 seconds).
2. If blue is still struggling because the database hasn't recovered:
   `pg_terminate_backend()` on the runaway queries. Targeted, by `pid` from
   `pg_stat_activity`, not a blanket kill.
3. If it's a genuine read-capacity problem, add an Aurora replica — a couple of
   minutes, and it's reversible.

**Same day**

- Fix the actual cause, with the evidence captured before the rollback.
- If it was an N+1 or a plan regression: add the index
  `CREATE INDEX CONCURRENTLY` so the fix doesn't cause a second incident, or fix
  the query.
- Re-deploy to green with **5% canary traffic first**, and watch `calls` on the
  top queries rather than only latency and error rate.

**Structural — the actual lesson**

The interesting question isn't "what broke", it's "why did a big-bang cutover
seem acceptable for a change of this kind."

- **Canary, not big bang.** Route 1% → 5% → 25% → 100% with automated rollback
  on error rate and database CPU. Nearly every failure mode above is visible at
  1% and harmless there. Big-bang cutover is a fine strategy for stateless
  services that share nothing; it's a poor fit the moment green and blue share a
  database, because the shared dependency means the blast radius isn't contained
  by the deployment strategy at all.
- **RDS Proxy or PgBouncer.** Decouples application instance count from database
  connection count and removes the connection-storm failure mode as a class.
- **Query budgets in CI.** Assert in integration tests that a checkout request
  issues fewer than N queries. Catches N+1s at PR time, where they're cheap. This
  is the highest-leverage item on the list.
- **Cache warming as a deploy step**, or a shared cache across blue and green,
  so the strategy stops manufacturing cold starts.
- **Expand-contract migrations as policy**, so rollback is always safe and the
  60-second decision at the top of this document never needs a caveat.
- **Load-test green against production-scale data before cutover.** Most of
  these are invisible against a 10k-row test database and obvious against 10M.

---

# Part 4 — System Architecture Diagram

![Orbit System Architecture](diagram/diagram1.svg)

**Orbit** is a multi-region e-commerce order and fulfilment platform on AWS:
event-driven microservices on EKS, polyglot persistence, GitOps delivery with
progressive rollout. I've drawn it at the level where the interesting arguments
live — the request path, the consistency boundaries, and the places where the
design is knowingly imperfect.

> **What this is, stated plainly.** Orbit is a composite reference architecture,
> not a system I personally built. I've drawn it to make the design discussion
> concrete, and I'd rather say so up front than have it surface as a surprise
> under questioning.
>
> The individual pieces are things I have worked with in production: AWS
> infrastructure deployed and managed end-to-end with Terraform, CloudWatch and
> CloudTrail for monitoring and audit, Prometheus and Grafana for dashboards,
> Route 53 for DNS, Ansible for configuration management across remote servers,
> and MySQL running inside a Kubernetes environment. I led an infrastructure
> project at Etihad Airways and worked on the Banque Misr mobile app in
> production.
>
> I'm happy to drop this diagram entirely and walk through one of those instead
> — that's a better conversation, and I'll take it in whichever direction is
> more useful to you.

## Component view

**Edge** — Route 53 latency routing → CloudFront → AWS WAF → ALB across three
AZs. TLS terminates at the ALB; CloudFront caches static assets and a small set
of cacheable API responses.

**Compute** — EKS across three AZs, Karpenter for node provisioning, a service
mesh providing mTLS, retries and circuit breaking. Services: BFF/API gateway,
order, payment, inventory, search, notification.

**Data (polyglot by design)**

| Store | Holds | Why this one |
|---|---|---|
| Aurora PostgreSQL (writer + 2 readers, behind RDS Proxy) | Orders, customers | Transactional integrity is non-negotiable for money |
| DynamoDB (on-demand) | Carts, sessions, idempotency keys | Single-digit-ms, spiky, no joins needed |
| ElastiCache Redis (cluster mode) | Read-through cache, rate limits, inventory reservations | Latency |
| OpenSearch | Product search and faceting | Relevance ranking is not a SQL problem |
| S3 | Assets, exports, the log lake from Part 1 | Durability per pound |

**Async** — order-service writes domain events to an outbox table in the same
transaction as the order, a relay publishes to EventBridge, EventBridge fans out
to per-consumer SQS queues each with a DLQ. The outbox is what makes
"order committed" and "event published" atomic without a distributed transaction.

**Delivery** — GitHub Actions → ECR → Argo CD (GitOps) → Argo Rollouts canary
with automated analysis and rollback.

**Observability** — OpenTelemetry collector → managed Prometheus/Grafana for
metrics, distributed tracing for the request path, and application logs into the
Part 1 pipeline.

## The checkout path

The eight-hop path is numbered on the diagram. The part worth discussing is the
split: **payment authorisation is synchronous** (the customer must be told yes
or no) while **everything after it is asynchronous** (fulfilment, email,
analytics, search reindex). Getting that boundary in the right place is most of
what makes the system feel fast, and moving it is the main lever available when
p99 degrades.

## Limitations — where I'd steer the conversation

I'd rather present these than be asked for them:

1. **Single-region writes.** Aurora Global Database gives roughly a one-second
   RPO, but promotion is operator-initiated and realistically 1–2 minutes of
   RTO. Active-active would demand conflict resolution on order state, and we
   deliberately declined that complexity. It's a real ceiling on the availability
   SLO and it's a conscious trade, not an oversight.

2. **The external payment provider's p99 is our p99.** Authorisation can't be
   made async. Circuit breakers and a queued-capture fallback bound the damage,
   but a PSP degradation is visible to customers, and no amount of internal
   architecture fixes that.

3. **At-least-once delivery everywhere.** The outbox pattern guarantees
   *at least* once, never exactly once, so every consumer must be idempotent. We
   enforce that with an idempotency-key table in DynamoDB — which becomes a hot
   partition during flash sales, so the mechanism that protects correctness is
   itself a scaling constraint. That trade is stated explicitly rather than
   discovered.

4. **Inventory reservations live in Redis.** Fast, and it's the reason the
   product page is quick. But a Redis failover with a cold replica opens a
   window where we can oversell. Mitigated with a TTL-based reservation ledger in
   DynamoDB as the durable record; the window is narrowed, not closed. This is
   the design decision I'd most want challenged.

5. **Search is eventually consistent.** Seconds behind the write path. "I just
   ordered it and it's not in my history" is expected behaviour, which means it's
   a support-training problem as much as an engineering one.

6. **The EKS control plane is a shared failure domain.** A bad admission webhook
   or CRD can wedge deploys cluster-wide. Separate clusters per domain would
   contain that, at a significant cost in operational overhead — currently judged
   not worth it, and that judgement is worth revisiting as the team grows.

7. **Cost.** The two largest line items are NAT gateway egress and cross-AZ mesh
   traffic. We accept cross-AZ chatter because the alternative is AZ-pinned
   services, and availability wins. NAT cost we attack with VPC endpoints — the
   same pattern as Part 1.

---

# What's in this repository

```
.
├── ANSWERS.md                     # this document
├── terraform/                     # Part 1 — the redesign
│   ├── versions.tf                #   provider pinning, remote state
│   ├── variables.tf               #   typed + validated inputs
│   ├── main.tf                    #   locals, data sources, KMS
│   ├── network.tf                 #   security groups, VPC endpoints
│   ├── iam.tf                     #   least-privilege roles
│   ├── ingest.tf                  #   Kinesis, S3 lake, Glue, Firehose
│   ├── compute.tf                 #   launch template, ASG, scaling, NLB
│   ├── observability.tf           #   alarms, composite alarm, SNS
│   ├── outputs.tf
│   ├── user_data.sh.tftpl
│   ├── tests/guardrails.tftest.hcl#   native tests, mock provider
│   ├── Makefile                   #   fmt / validate / lint / security / test
│   └── .tflint.hcl
├── tools/                         # Part 2 — the replacement
│   ├── log_analyzer.py            #   stdlib-only, streaming, fail-loud
│   ├── test_log_analyzer.py       #   40 tests, all passing
│   ├── demo_failure_modes.sh      #   side-by-side proof of each failure
│   └── deploy/                    #   systemd units + k8s CronJob
└── diagram/                       # Part 4
    └── orbit-architecture.html
```

**Verification performed**

Everything below was executed on macOS against the AWS provider v6.64.0.

| Check | Result |
|---|---|
| `python3 -m unittest discover -s tools` | 40 passed |
| `terraform fmt -check -recursive` | clean |
| `terraform validate` | Success, no warnings |
| `terraform test` | **12 passed, 0 failed** |
| `tools/demo_failure_modes.sh` | every Part 2.1 claim reproduced against real fixtures |

Provider-specific details were checked against current documentation rather than
recall: provider 6.x attribute deprecations (`aws_region.name` → `region`), S3
native state locking (`use_lockfile`, Terraform 1.11+), KCL 3.x DynamoDB
metadata tables, Terraform's default-egress-rule removal behaviour, and the
Firehose/Athena partition-projection requirement.

### What running it actually caught

I wrote this module carefully and reviewed it twice, including the adversarial
pass in §1.3. Executing it still surfaced four defects that no amount of reading
had found:

1. **`mock_provider` mocks `aws_iam_policy_document`.** It is nominally a data
   source, though it makes no API call — so the mock returned a random string for
   its rendered `json`, every IAM and KMS resource rejected it, and all twelve
   tests failed at plan time on an error that had nothing to do with what was
   being tested.

2. **`instance_refresh.triggers = ["launch_template"]` was redundant.**
   `terraform validate` pointed out that a launch template change always triggers
   a refresh. I had already trimmed `desired_capacity` from that list for being
   dead config — and had left an entry that was dead for a different reason.

3. **My `terraform fmt` checker had a bug.** I had replicated fmt's alignment
   rule but missed one case: an attribute whose value *opens* a multi-line list
   (`values = [`) leaves the alignment group and takes a single space. My checker
   handled `{` but not `[`, so it actively mis-formatted two files.

4. **`ebs.encrypted` is a string, not a boolean.** The launch template schema
   types it as a string because the EC2 API does, so the planned value is
   `"true"` and `"true" == true` is false. The assertion failed against a volume
   that was correctly encrypted — a false alarm in a security guardrail, which is
   the kind that gets muted, after which the guardrail protects nothing. Fixed
   with `tobool()` so it survives a future schema change either way.

Three of those four are the same species as the interaction bugs in §1.3, and
one of them is a bug in my own verification tooling. Which is the point: static
review, human or AI, has a ceiling, and the only thing that reliably finds what
is under it is running the thing.
