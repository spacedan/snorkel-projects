This doc outlines the critical criteria required for evaluating the quality of a Terminus 3 task. This will highlight key areas that require human review and/or must pass for a task to be acceptable. This list is subject to change and should be updated as new criteria are discovered.

This is the verbose version of the list that outlines all of our requirements. Many of these should already be blocked by in-platform evals and thus are not relevant to the review. See condensed version for one that is more reviewer friendly (coming soon)

Criteria and severities evolve. Criteria may be added or removed, and severities adjusted, as the edition progresses — check this page rather than relying on a cached copy.

The automated quality panel is separate from the checklist severities below. It reviews five axes before difficulty measurement. Treat its findings as evidence to verify, not as a substitute for reviewing the task; see the Quality Panel Judge Guide.

Severity Guidance
Each criterion is marked with a different severity level (high, medium, or low). Here is how to interpret each criterion when doing a review:

High: If any criterion marked ‘high’ is not met, the task should not be accepted. High severity criteria must always pass for every single task.
Medium: One failed Medium criterion means the task must be sent to revision.
Low: If a task fails only ‘low’ criteria, it is ok to be accepted. These are typically ‘nice to have’, but should not block a submission from being accepted. If a task is to be sent to revision regardless, i.e. failures of ‘high’ or ‘medium’ severity, please include in the revision notes to correct those low severity issues as well.
Rubrics are the exception: the Rubrics section carries no severities. Every rubric issue is fixed in place by the reviewer, and only an empty rubric — blank or never generated — goes back for revision — see that section.
Instruction Prompt
Task Instruction is concise	Instructions should be as concise as the task allows. Around 2 short paragraphs, or a list of up to 20 bullets, is a good guide; more complex tasks may need more room to be well specified.

Flag length that comes from listing steps or restating requirements, rather than from the problem itself.

Tasks should not be long running with many different instructions/requirements to follow.

The goal is to create tasks that represent genuinely challenging coding problems, not ones that challenge instruction following.

Task instructions should generally read like how a human would prompt a coding agent. This means no emojis, not a lot of markdown styling, and no longer running prompts.	Medium
Task Instruction is well specified	While task instructions should be concise, they still must be well specified. This means that the goal of a task is clear and obvious to the human/agent.

The main criteria to look for here is tasks with a larger number of edge cases and requirements. If a task is primarily hard due to a large number of edge cases/requirements that are not handled well, it should be rejected.	High
Task Instruction is interesting	The task instruction should not be obscure or irrelevant to the point that no group of developers or users would find them interesting.

Every task must be interesting or useful in some way.	High
Task instruction does not provide hints on how to solve the problem	Conceptually, we are going for tasks that represent one shot tasks from a user to a terminal agent. If tasks contain significant hints or rubrics in the instruction.md for how to solve the task, it is not representative of the style of task we are looking for. Requirements can be included, but hints or stepwise instructions should not be.	High
Task environment does not contain hidden instructions or hints	The task environment (including all files, comments, README, config files, scripts, TODOs) must not contain step-by-step walkthroughs, hints, or prescriptive guidance that would give the agent the solution approach. This includes README files with "how-to" sections, commented code walkthroughs, or configuration examples that reveal the answer.	High
Environment spec/doc files are realistic and do not bypass instruction rules	Environment documentation files (such as spec.md, README.md, or architecture docs) must (1) define only what the requirements, schemas, or protocols are — not step-by-step solution guides; (2) never be used to split a task's logical instructions out of instruction.md to artificially shorten it — all prompts and goals must remain in instruction.md; and (3) read like realistic engineering documents (API contracts, DB schemas, business-logic specs), not overly polished, hyper-structured LLM-style prompt extensions. See Prompt Styling for the full rules.	High
Task instruction is unique to previously submitted tasks and open source tasks	The task must be noticeably unique to any task in Terminal-Bench 2.1, Terminal-Bench 3.0, or Snorkel's prior Terminus editions. Similarity search eval results are provided to help make this determination. Generally, the logic for too similar tasks is:

1. Are the initial state/instructions different in a way that is non trivial
OR
2. Is the expected output different in a way that is non trivial	High
Instruction must use absolute paths.	Any referenced path in the instruction must be an absolute reference.	High
Instruction.md does not contain the task name	The task name should not appear in the instruction.md. (Context: Many tasks have a comment in the first line with the task name or some variant)	Medium
Environment
Dockerfile or build scripts do not grab content from the web (other than packages).	The environment should not rely on any content from the internet, other than package dependencies. Any content that needs to be downloaded from the internet should be stored locally in the environment.	High
network_mode is set per phase and matches the task's actual needs.	[environment].network_mode must be "public" on every task. All three phases must declare the key. For a single-container task, [agent] and [verifier] may be "public" or "no-network" according to what the task needs. When a Compose file is present, all three phases must be "public"; the runner cannot apply separate phase policies to Compose environments. Do not flag public agent or verifier networking on a Compose task. "allowlist" is not supported.	High
All dependencies use pinned versions	Any dependencies installed must use pinned versions. This is only high severity for packages (excluding apt).	High
Does not use context from outside of the environment/ directory.	All content in the environment should be contained within the environment directory. Environments should not capture context outside of this directory, for example by using a docker-compose.yaml and setting context to ../	High
Environment does not contain solution of ground truth answers.	The environment must not contain any files that provide the oracle solution or ground truth used in the unit tests. All scripts related to the oracle solution should be stored only in the solution directory, and all files needed to verify the task should only be included in the tests/ directory.	High
Dockerfile does not execute any dangerous operations.	The Dockerfile should not require any dangerous operations like:

running in --privileged mode
using SYS_ADMIN, NET_ADMIN, SYS_MODULE, or similar capabilities
mounting /var/run/docker.sock
High
Docker compose alters any key volume mounts that conflict with default harbor mounts.	It is preferred that the docker compose does not use volume mounts at all unless needed. Specifically, the following mounts are reserved for harbor:

/logs/artifacts/
/logs/verifier/
/tests/
/solution/
High
No AI-framework scaffolding filenames	Filenames like CLAUDE.md, skills.md, or similar AI-generated framework names should not appear in the task environment. These indicate incomplete cleanup and raise questions about task authenticity. All files in the environment should be task-specific and professionally named.	High
Every Docker base image is digest-pinned	Every FROM line, and any pulled image: in docker-compose.yaml, must include @sha256:<digest>. Tags may remain for readability, but tag-only images are no longer acceptable.	High
Base image(s) are canonical for the task's language, or the non-canonical justification is present and credible	The final runtime stage should use a canonical Terminal-Bench base image from the published list when one matches the task's language. Non-canonical images are allowed only when a brief, credible justification is present (as a comment in the Dockerfile) — for example, "the canonical Java image is JDK-only; this task needs full JRE + system libraries," or "targeting a runtime not yet in the canonical list."

Outcome matrix:
• Canonical image → ✅ passes
• Non-canonical + present, credible justification → ✅ passes; surface to reviewer for judgment
• Non-canonical + missing, vague, or boilerplate justification → ❌ blocked

Reject if the stated justification matches an existing canonical entry (i.e., a canonical image would have worked fine).	High
Build context stays small	The environment/ build context must be at most 100 MiB total, with no single file over 50 MiB. Large optional datasets should not be baked into the image.	High
Known environment defects block acceptance	A task must be able to run as configured. If the environment carries a known defect — a required dependency missing from the image, an environment that cannot build or start, or a task that needs network access at runtime while set to no-network — send it back for revision, whether or not that defect produced a visible failure during the difficulty run.

A handful of trials against two agents is a sample, not proof. A defect that no agent happened to hit can still break production runs with different agents, seeds, or timing. Acceptance judges the task as shipped, not as sampled.

This is separate from judging whether agents reasoned fairly to failure. A clean difficulty run does not clear a known environment defect — the two questions are independent, and both must pass. See Dockerfile Requirements for the required dependencies.	High
Apt usage is clean and reproducible	Use a single apt-get update && apt-get install -y --no-install-recommends ... && rm -rf /var/lib/apt/lists/* transaction per stage, avoid apt-get upgrade, and do not pin apt package versions — CI blocks pinned apt installs	Medium
Non-trivial environment includes .dockerignore	Exclude build-context clutter and secrets such as .git, __pycache__/, *.pyc, node_modules/, .env, solution/, and tests/.	Low
Avoids using heredocs in Dockerfile	It is preferred that Dockerfiles do not use heredocs format like:
cat << EOF
RUN cat > /app/script <<'EOF'
Low
Do not request extra Dockerfile nits already gated by preflight	COPY --from= image refs that mix a tag with a digest are blocked by static preflight. If a task reached you, that pattern already passed. Do not send back for a named --chown= value (the cloud image builder now resolves names), for FROM image:tag@sha256: (that pin form is required), for COPY --from=builder stage names, or for RUN chown. See Cloud Image Builder Syntax.	Low
Do not request extra Compose networking already gated by preflight	A top-level networks: block, a per-service networks: list, a per-service network_mode:, and non-public [agent] / [verifier] phases are blocked by check_compose_networks. If a task reached you, those rules already passed. Do not send back to add named networks or Compose isolation, or to close agent/verifier networking. If the task truly must run offline, it must use a single container. See Compose networking.	Low
Oracle Solution
Oracle passes consistently and contains no behavior that would lead to flaky passing.	Oracle solutions should avoid having any behavior that would result in not passing on every run. This can include:
Randomization in the oracle or tests
Latency based operations that will fail on different hardware
Flakey tests that are affected by the same criteria as above
High
Oracle's internet use matches [agent].network_mode	When [agent].network_mode = "no-network", the oracle solution must not have any actions that require accessing the internet, including downloading packages — any dependencies required for the solution must be installed in the environment. When network_mode = "public", the oracle may access the internet where the task genuinely requires it.	High
Oracle is reflective of what is described in the instruction.md	The oracle solution must actually solve the problem outlined in the instruction.md. This should cover every requirement outlined in the instructions, not just those that are tested. It is also crucial that the solution is an actual implementation, not a hardcoded answer to pass the tests.	High
Verifiers
Verifier cannot exit before reward is assigned	The test.sh file should always assign a reward to reward.txt on both success and failure, to avoid triggering a RewardNotFoundError. However, exiting before assigning a reward is acceptable in cases where continuing would unfairly penalize the agent for factors outside its control. In most cases, the template from the task skeleton should be acceptable.

Do not flag a missing trailing exit: The if [ $? -eq 0 ] ... fi reward block is the canonical end of test.sh. No trailing exit is required or desired. Harbor reads /logs/verifier/reward.txt to determine pass/fail, not the script's exit code, so a failing pytest run correctly records a failure via the else branch. The check_test_sh static gate enforces this canonical shape — adding exit $? after fi will fail CI. A missing trailing exit must not be raised as a defect.	High
Verifiers use the exact same logic for oracle and agent runs.	The verifiers must not contain any conditional logic that causes the oracle solution to be validated differently than the agent’s solution. This ensures that the oracle and agent are validated equivalently and fairly.	High
Verifier files' internet use matches [verifier].network_mode	When [verifier].network_mode = "no-network", test.sh and other verifier files must not rely on any content from the internet, and all verifier dependencies must be baked into the Dockerfile (not downloaded at runtime). When network_mode = "public", verifier network use is allowed only where the task genuinely requires it, and grading must still be deterministic; see the deterministic-execution guidance.	High
Verifier must only apply binary rewards (0/1)	The unit test verifiers must only apply a score of 0 or 1 to the reward.txt. The verifier must not apply a partial reward, for example by applying a score based on the number of passed unit tests.	High
Verifiers must be aligned with instructions.	All unit tests must be aligned to the task that was outlined in the instructions. The verifiers must not test requirements that are not explicitly or implicitly defined in the instructions.	High
Required output paths and names match verifier expectations.	Every required output path and filename in instruction.md must match the artifact the verifier reads. Send the task back if a correct implementation following the documented path or name would fail because the verifier checks a different location or artifact. This is the opposite direction from an undocumented verifier requirement: both the contract and the check must point to the same deliverable.	High
Verifiers check for correctness, not just format.	The verifier must validate every stated core requirement and the actual content of every required output — not just file presence, parseability, a row count, or a partial sample. Required fields, rows, files, values, ordering, uniqueness, data types, and formatting must be checked when the contract requires them. Do not create a separate finding for each missing assertion when they are one coverage gap; report the uncovered requirement and the passing wrong solution it permits.	High
Solution logic is not reimplemented in tests/.	No function in tests/ may map task inputs to the complete expected artifact except by running the agent's own program. End-to-end solution generation belongs in solution/ (never present in the agent environment). Legitimate and not flagged: running the agent's binary/CLI, parsing the agent's output, precomputed golden fixtures/hashes, spec-derived invariants (floors/budgets/ceilings), and sealed held-out truth. Rule of thumb: if deleting solution/ would still let the test compute the expected answer, trim the solver logic.	High
Config-claimed values are read dynamically, not hardcoded.	Applies only when the instruction says the agent must read a config/input file that can vary. Then the verifier must read those values from the config at runtime rather than re-declaring them as literals, so an agent that ignores the config and hardcodes the parameters cannot pass. Not a general ban on hardcoded values: hardcoding the expected result — exact numeric/ML targets (with tolerance), byte-exact outputs, format constants — is fine and often required. Confirm config dependence by mutating the config and re-running.	High
The verifier rejects a wrong solution, not just accepts a right one.	A passing oracle only shows the task runs. Satisfy yourself that a deliberately wrong, incomplete, or lazy solution would fail — that is the question the verifier exists to answer. One mutant of the shipped buggy code is not enough if several stated rules have no isolating case: for each named domain rule, a fixture should exist whose outcome would change if that rule alone were inverted. Tests must also include meaningful variation across the stated input domain so a solution cannot pass by hardcoding the shipped sizes, values, ordering, paths, formats, or business rule. This does not require combinatorial coverage of conditions the contract does not promise.

Held-out that exists to check generalization must not be the only enforcement of any stated rule. Hidden test inputs are fine; hidden requirements are not — the instruction plus that input must determine the output; a hidden corpus must not be the only source of an unstated mapping, threshold, or label. When the contract states lifecycle or resilience behavior — restart/recovery, idempotency, invalid-input handling, concurrency, existing-output handling, or reset behavior — the verifier must exercise that behavior, not only the happy path. Do not require lifecycle cases the task never claims to support.

Check the ways this breaks down: the answer is reachable (held-out input beside its expected output, ground truth derived from agent-writable paths, a sealed directory the graded process can still read, prior output left at a predictable path to replay, or goldens readable by agent code the verifier execs — separate mode protects the verifier from the agent environment, not from that process; drop uid before the exec, and probe it); the checks are hollow (asserting a count, a first element, a field's presence but not its value, an expected result recomputed from an input the agent controls, or staging agent trees by hand so symlinks expose verifier goldens); or a documented behavior is never exercised (a command or mode the tests reference but never run; a named rule that only fails when bundled with other violations or only inside mixed held-out data; a parametric model whose driving parameter is read back rather than changed and rebuilt — reading a stored value proves a number exists, not that the output depends on it, and a solution that hardcodes the result stores the same number). Goldens belong in the verifier image (Terminus requires explicit [verifier].environment_mode = "separate", fixtures baked into tests/Dockerfile) — not in paths the agent can edit or symlink to. See What Makes a Good Task, Writing Tests, and Dockerfile §8; for geometry tasks, CAD Task Guidelines.	High
Source is rebuilt, and the required delivered artifact is validated.	If the verifier runs an artifact the agent delivered without rebuilding it from submitted source and varying the input, a hardcoded binary that emits the fixed answer can pass without implementing anything. Rebuilding source does not by itself validate a required delivered binary, package, report, or file: when the contract requires that artifact, the verifier must also inspect or execute the artifact itself and confirm it corresponds to the submitted source. Where correctness depends on two artifacts the agent controls both sides of — a simulated and synthesized build, or a library and its consumer — grade their equivalence rather than accepting each side independently.	High
The oracle is correct, not just passing.	Tests and oracle are written together and tuned until the oracle passes, so a green oracle does not establish that the reference is right. Where correctness turns on a rule the fixtures don't stress, spot-check the oracle's logic against the spec. A wrong oracle is worse than a broken one: the tests encode its output as the answer key, so a correct agent solution fails and difficulty is measured against a bad truth. See Writing Oracle Solution.	High
Instruction tolerances match verifier tolerances.	When instruction.md states a numeric error band, tests must enforce that band — not a tighter precision the agent was never told about. Send back when a conforming implementation that meets the written spec would fail the verifier. See Writing Tests → Instruction Tolerance Must Match Verifier Tolerance.	High
The tested objective matches the specified one.	When the spec defines an optimization objective, ordering rule, or tie-break, tests must reject feasible plans that optimize the wrong quantity or ignore the tie-break — not just check that some valid output exists. Spot-check the oracle on a case where two feasible answers differ on the primary objective or tie-break. See Writing Tests → Optimization Objectives and Tie-Breaks Must Be Tested.	High
Trial Analysis
The difficulty check ends with a trial analysis section. Each criterion returns PASS, FAIL, or NOT_APPLICABLE — a criterion is flagged when it returns FAIL. NOT_APPLICABLE is not a defect: it means there was not enough evidence to judge, or the agent hit an infrastructure error before engaging with the task.

task_specification and reward_hacking are definite issues. If either is flagged, send the task back.

The other four require you to examine the flag and decide whether its reason holds up:

The reason is valid — the flag identifies a real problem. Send the task back for revision.
The reason is invalid — the flag is a false positive. Write a description explaining why, then accept.
Judge each flag on its own merits. A dismissed false positive is not a failed Medium. A single valid flag is still grounds for revision. What is never acceptable is passing over a flag without examining it.

Trial analysis: task_specification not flagged	The instructions must be sufficient for an agent to succeed. Flagged when tests expect parameter names, file formats, or return values that instruction.md never specifies; when tests check behaviour the agent had to guess at; or when tests match exact strings or data structures that are undocumented. A flag here means the task is under-specified — not that the agent was weak. Send back for revision.	High
Trial analysis: reward_hacking not flagged	The agent must earn its reward legitimately. Flagged when the trajectory shows edits to tests/test.sh or tests/test_*.py, writes to /logs/verifier/reward.txt or reward.json, reads or copies from solution/, or any manipulation of the grading harness. Solving an easy task correctly is not a hack. Send back for revision.	High
Trial analysis: difficulty_crux examined	Compares why the agent actually failed against the author's [metadata].difficulty_explanation. Flagged when the agent failed for an unrelated reason — wrong file format, misread instructions, an environment issue, an incidental bug. That points to unintended difficulty or a specification problem. Send back if the reason holds up; otherwise record why you are accepting it.	Medium
Trial analysis: near_miss examined	Flagged when the agent produced a substantively working solution that fell just short. Look at which tests fail across the runs. If the runs keep failing the same one or few tests, look at those tests and the instructions — a check that every capable agent fails is usually the source of the error rather than real difficulty. If the runs fail different tests each time, the agent is genuinely close but slipping in different places, which is a more acceptable near-miss and closer to real difficulty. In neither case should the difficulty be raised only because near-complete runs count as failures, and do not simply ask the author to make the task harder.

Keep this criterion about difficulty: if the failing check enforces something the instruction never states, that belongs under task_specification. Send back if the reason holds up; otherwise record why you are accepting it.	Medium
Trial analysis: refusals examined	Flagged when the agent aborted on a content or safety policy rather than engaging — explicit refusal language, a policy cited as the reason for stopping, or a very short trajectory that exits before meaningful tool use. Distinct from a provider refusal during stb harbor check (see the FAQ). Send back if the reason holds up; otherwise record why you are accepting it.	Medium
Trial analysis: low_timeout examined	Flagged when the agent was still making meaningful progress at the timeout, or finished within a couple of minutes of it while still working productively. The fix is normally to raise [agent].timeout_sec so the difficulty comes from the problem rather than time pressure. Send back if the reason holds up; otherwise record why you are accepting it.	Medium
Rubrics
Rubric issues are fixed by the reviewer, not sent back. The rubric is generated by the platform, so a formatting or content defect in it is not the author's error to correct. The criteria below define a correct rubric — treat them as your edit checklist: fix the rubric in place and note what you changed in your acceptance comments. Severity does not apply in this section; the one-Medium rule does not apply here.

The only rubric defect that goes back for revision is a rubric that is empty — blank, or never generated. Record every fix you make — recurring format defects are evidence the generator needs work.

Rubric is present.	An empty rubric — blank, or never generated — is the only rubric defect that goes back for revision. Generation should run before a task reaches you, so treat this as a backstop and report it if it recurs.	Revision
Rubrics must not reference testing logic.	Criteria in the rubric should not reference running or checking the results from tests in the /tests/ directory. These tests are run after the agents attempt, so are not relevant to grading the agent trace.	Fix
Rubrics must not reference metadata or instructions items.	The agent does not have context from the task.toml, and does not know of the existence of the instruction.md file. These items should not be referenced in any rubric criteria.	Fix
Rubric scores are integers from −5 to +5, never 0.	Any integer from −5 to +5 is valid except 0. Positive scores must carry the leading + (see the criterion below). The Terminus 2 rule excluding ±4 is retired.	Fix
Positive rubric scores include an explicit + sign	Every positive score must be written with a leading + (e.g., +1, +2, +3, +5) — not a bare number like 3. Add the sign yourself.	Fix
Rubric block must be correctly formatted, with new lines separating each criterion.	Each criterion must be a single line, start with 'Agent', and end with a comma, a space, and the score (e.g. Agent compiles the project with no warnings, +2). Positive scores must carry an explicit +. Use a flat list of criterion lines. See Rubrics.	Fix
Rubric criteria are detailed and precise.	Each criterion in the rubric must be detailed and precise enough to describe the specific action they are meant to grade. Vague criteria or ones that should not always apply given the task should not be included.	Fix
Include at least one negative criterion.	The rubric must have a minimum of one negative criterion.	Fix
Rubric scores must be correctly mapped to level of importance.	Critical criteria must be associated with the most extreme scores (5, -5), while Major or Minor criteria should be associated with less extreme scores.	Fix
Rubric criteria should always include positive language.	The criteria should always be phrased positively not negatively. A negatively phrased criterion can be rephrased into a positively phrased criterion with a negative reward.

I.e.:

Bad:
Agent does not access the /app/secret/ directory, +1

Good:
Agent accesses the /app/secret/ directory, -1	Fix
Rubric does not mention oracle/NOP runs.	The agent does not have context about the oracle/NOP runs. The rubric should never mention something like "oracle passes consistently."	Fix
Point range: 10–40 points.	The rubric's maximum cumulative score should be between 10 and 40 points.	Fix
Task Structure
Every task should contain required files.	Required files: task.toml, instruction.md, environment/Dockerfile, solution/solve.sh, tests/Dockerfile, tests/test.sh, tests/test_outputs.py. rubrics.txt and README.md are added by Snorkel at packaging and are not expected in the submitted ZIP.	High
Tasks should not contain unnecessary files in the parent directory.	Additional files that are not used in the parent directory should be cleaned up. This includes:

jobs/: leftover job logs
data/: all environment data should be stored in the environment
Low
Task Metadata
Not revision triggers. The difficulty value — the measured tier is already final when the task reaches you and is what gets recorded, so a declared value that doesn't match it is the author's estimate, not a defect. Don't send a task back to change it and don't spend time on it (only a retired tier name is a valid flag). A new submission normally needs at least 3 failures across its 8 runs before it reaches you; do not reapply that gate to a task grandfathered on the platform by the morning of Sep 11, including its later revisions. A subcategory you would have chosen differently is not a revision reason when a reasonable reading of the task supports the declared one — note it in the acceptance comments. The static check only confirms the value exists in the taxonomy, not that it fits; only a category that does not fit the task at all fails the metadata row. And a task.toml "structure" complaint from Agent Review should be confirmed against the actual static-check result before flagging — CI runs the structure check on every submission, and a task only reaches you once CI is passing. See Review Guidelines → Don't request changes for these.

Task.toml must contain all required metadata fields.	Required metadata fields in the task.toml include:

artifacts     (TOP-LEVEL - nesting under [verifier] silently drops it)
name          (top level or under [metadata])
[metadata]
author_name   (may be "anonymous")
author_email  (may be "anonymous")
category
subcategory
tags          (3-6)
languages
difficulty    (frontier | advanced | core | base)
expert_time_estimate_hours
difficulty_explanation
solution_explanation
verification_explanation
relevant_experience
[verifier]
timeout_sec
environment_mode = "separate"
[agent]
timeout_sec   (minimum 1800)
[environment]
network_mode  (MUST be "public")
[agent]
network_mode  ("public" | "no-network"; Compose MUST be "public")
[verifier]
network_mode  ("public" | "no-network"; Compose MUST be "public")
build_timeout_sec
cpus
memory_mb
storage_mb

Descriptive fields must sit under [metadata] — the structure check no longer counts top-level copies. artifacts stays top-level.	High
Task.toml must correctly flag multi container and custom docker compose tasks.	If a task runs a multi-container system, it must be tagged in task.toml with is_multi_container = true under [metadata]. The field is optional and only needed when it is true — do not flag its absence on a single-container task. The harness detects environment/docker-compose.yaml on its own; when present, all three phases must set network_mode = "public".	High
difficulty uses a current Terminus 3 tier.	Only frontier, advanced, core, and base are valid. The Terminus 2nd Edition names — easy, medium, hard — were retired and must be sent back for correction. The author-declared tier is an estimate; do not send a task back because it differs from the platform's measured tier.	High
Tags, languages, category, and subcategory must be applicable to the task.	Any assigned tag, language, category, or subcategory must be aligned with the actual content of the task. The definitions for categories and subcategories can be found in our documentation.	Medium
Do not reject a task for omitted or blank optional resource fields.	The gpus, gpu_types, and docker_flags fields in [environment] are valid but optional Harbor resource fields. Since Terminus 3 tasks must not require GPU, do not send a task back for revision solely because these fields are omitted or left blank. A task is equally valid with the full block (including gpus/gpu_types/docker_flags) or the minimal block (without them). gpu_types only matters when a task requests GPUs (gpus > 0).