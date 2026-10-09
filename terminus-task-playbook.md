# Terminus 3 task playbook

Lessons from building and revising `redact-cluster-support-bundle` (Sept–Oct 2026). Read this before starting or revising a Terminus task. The program's own PDFs in this project are the source of truth; this is what they cost us to learn in practice.

## 1. What gets a task through

A task has to clear four things in this order, and each one failed us at least once.

1. **Quality gates** (pre-difficulty, automated): structure, hygiene, instruction–test alignment.
2. **Quality panel** (adversarial review of the verifier and the reference; see section 5). Our first pass through it came back with 31 blocking findings.
3. **Difficulty gate**: at least 3 genuine failures in 8 platform runs (4 Opus, 4 GPT). No more than 5 passes.
4. **Solvability**: every individual unit test must pass in at least one agent run.

The mistake to avoid: fixing quality findings by spelling out more rules. That passes the quality gates and then fails difficulty, because frontier models implement any rule that is written down.

## 2. Difficulty: what worked and what didn't

**Did not work**

- A complete rule list in the instruction. Versions with every rule listed were solved by GPT in about 4 minutes and by Opus whenever it finished.
- Adding more listed rules (address forms, then encoded payloads). Each was implemented correctly once stated. The guidance calls this "length, not difficulty".
- Relying on timeouts or crashes. The platform flags these (`low_timeout`, "accuracy is not a difficulty signal") and does not count them as genuine failures.

**Worked** (per `Difficulty-guidance.md`)

- Take the rule list out of the instruction. Ship example inputs with their correct outputs in the environment and say they are the reference. Keep exact parameter lists (ranges, suffixes, name hints) as config constants in the starting code.
- Hold out the data and the combinations: grade on freshly generated inputs that combine rules in ways the examples show only separately.
- Result on the same tests: 0 passes in 4 runs, all for genuine reasons.

**How agents failed once they had to infer** (useful for designing held-out cases)

- Hard-coded names seen in the samples instead of deriving them from the input.
- Keyed a rule on the sample's surrounding wording ("token X", "cached X") instead of on the value.
- Built a lookup of values seen in one form, so a value appearing only in another form leaked.
- Re-encoded content that should have been returned untouched.
- Missed a composition of two rules each shown separately.

**Fairness rules for an inference design**

- Every tested behaviour must appear in at least one shipped example. Audit this line by line and say so in `verification_explanation`.
- If an example supports two reasonable readings, either add an example that separates them or make the held-out data consistent with both. (Our pull-secret example did this; fixed by aligning the held-out data.)
- Give two examples in different contexts for any rule that could be mistaken for a wording pattern.
- State the plumbing explicitly: output schema, field names, which fields may change, ordering, determinism. It costs no difficulty and is what `structured_data_schema` and `behavior_in_task_description` look for.
- Add one sentence naming the categories the examples cover, without giving the rules.
- Whenever a test is added, add the matching evidence to an example in the same change, then regenerate the example outputs from the reference and confirm the reference reproduces them.

## 3. Instruction rules

- Danny writes the final wording. Drafts are for re-voicing; `instruction.md` and `solve.sh` are screened for AI-written text.
- Aim for 150–250 words, plain paragraphs, absolute paths, no headings or bold labels, no step-by-step guidance.
- Either make a promise true or stop promising it. Removing scope resolves a finding as fully as fixing it. Cut breadth, keep the hard thing.
- Every boundary needs its counting rule or it should not be tested. ("Nested deeper than 64 levels" without saying how levels are counted produced three unfair failures.)
- After any change to the instruction, re-run `stb harbor check`.
- The local check's judge is more literal than the platform's. Passing locally is the safer target.

## 4. Tests and verifier

- Generate graded inputs at grade time from fixed seeds. Replay nothing the agent can see.
- Plant each value where only one rule can catch it, or a missing rule goes unnoticed.
- Mutation-test: write one plausible wrong solution per rule and confirm the tests reject each. We ended with 132, all rejected.
- When output format is the agent's choice, compare whole probe lines and derive expected text from the agent's own placeholder; never assume a format.
- Determinism tests need more than a second between requests, or clock-dependent output (a gzip header timestamp) slips through.
- Split broad tests by class. One "nothing leaks" test failed in every run for different reasons, which would have tripped the solvability rule; eight class-level tests each passed in at least two of four runs.
- Do not let a test for one behaviour depend on an unrelated rule (our payload test originally failed whenever the node-name rule did).
- Verifier: separate mode, declared artifacts only, landing directory pre-created in `tests/Dockerfile`, same pinned base digest as the environment, pinned pytest and pytest-json-ctrf, `test.sh` without `-e` that always writes the reward, CTRF output, binary reward.
- Run submitted code as an unprivileged user under `python -I -S` in a private temp directory, with `/tests` mode 700.

## 5. The quality panel: what it attacks and how to get ahead of it

The panel scores five axes: Sound Verifier, Correct Reference Solution, Protected Ground Truth, Deterministic Execution, Coherent Contract. Its method is concrete: it edits the reference solution into something wrong and checks whether the tests still pass, and it feeds the reference awkward but contract-valid inputs and checks the output. Assume every gap will be found. Do this before submitting.

**Verifier gaps it found (each was a wrong solution our tests accepted)**

- A configured parameter only partly exercised. Our generator used one /16 of a /14, so narrowing the range passed. Exercise the whole of every range, every entry of every list (each env-name hint, each DNS suffix), and plant decoys just outside each boundary that must survive.
- Fields the solution may rewrite, checked only for "no leak" and "still contains X". Stripping whitespace, truncating, or appending text passed. For every such field compare positionally: the text between the planted values must equal the original exactly. Plant leading and trailing spaces, tabs and a trailing newline so the comparison has something to bite on.
- Partial replacement. Keeping part of a value (a MAC's vendor half, three octets of an address, an account's domain, a token's last characters) passed because only the whole string was checked. Also check the ends and halves of each value, minus any piece that legitimately occurs elsewhere in the input.
- Consistency checked within one field type only. Separate placeholder maps for items and for log lines passed. Check the same value across every field it can appear in.
- Injectivity checked for some classes only. Cover every class, including all credentials at once.
- Replay across process restarts. A cache in `/tmp` made a non-deterministic solution pass the restart test. Give every test its own process, and before and after each run kill every process and delete every file and System V IPC object owned by the service account. Confirm the fix by writing the replay mutants (file cache, shared memory, detached helper process) and checking that they pass with the cleanup disabled and fail with it enabled.
- Verifier packages importable by submitted code. Install them with `pip install --target` into a root-only directory, point only the test runner at it with `PYTHONPATH`, and remove pip and `ensurepip` from the verifier image.
- Starter code that contradicts the contract (ours walked the whole bundle for anything with a `resource_id`). Agents inherit starter code; all four earlier submissions kept that walker. Remove it, and plant the case that would expose it.

**Reference defects it found**

- Sequential replacement passes: a later pass rewrote text inside an earlier placeholder, and the result depended on set order. Collect every candidate span over the original text first, resolve overlaps by a fixed rule (leftmost, longest, rule order), replace once.
- Placeholders that could contain the value they replace, or collide. Draw from an alphabet that excludes the value's characters and re-draw on collision.
- Patterns that take too much or too little: a token rule that swallowed the following punctuation, a hostname rule that matched a suffix in the middle of a public name, a prefix literal matching inside a longer sibling name.
- Case: the same MAC or hostname in a different case got a different placeholder.

**Working method for a panel round**

- Group the findings by root cause before fixing anything; 31 findings were about ten causes.
- For each verifier finding write the mutant first, watch it survive, then fix the tests.
- When a new mutant survives, ask what else of the same shape would. "Keeps the first four characters" led to a whole family.
- After tightening, regrade earlier agent submissions. A fair tightening changes nothing for them except where they were already wrong. Neutralise anything they inherited from old starter code before reading the matrix.
- Emulate the verifier image locally: a pip-less venv, the packages in a root-only directory, the tests in a mode-700 directory, the service account present. Otherwise isolation tests pass or fail for local reasons.
- Decide and write down what the tests deliberately do not constrain (ours: the placeholder text, and how much of a URL a placeholder covers), so a surviving variant is a decision rather than an oversight.

## 6. Hygiene items that failed a gate

- Leftover `tests/fixtures/` from an earlier design (`no_extraneous_files`, blocking). Also remove `jobs/`, `.DS_Store`, stray data folders.
- A large heredoc in `solve.sh` (`solution_quality`). Keep the solution as real files under `solution/` and have a short `solve.sh` call them, resolving paths relative to the script.
- `task.toml` explanations that describe an older scope. Rewrite all three whenever scope changes.
- Stale comments that mention removed features.

Before every submission, list every file (`find <task> -type f | sort`) and account for each one.

## 7. Running and reading agent trials

- Create tasks with `stb init NAME -p PROJECT_ID` (not `stb tasks create`). Submit only with `stb submissions create/update`; never `harbor upload`.
- Model strings need the prefix: `@anthropic/claude-opus-5`, `@openai/gpt-5.6`.
- Run models one after the other. Run Opus one trial at a time (`-k 1`); concurrent Opus trials caused API errors.
- Keys: $10, 30 days, and the CLI cannot report what is left. Sum `grep -H '"cost_usd"' jobs/*/result.json`. Typical cost here: GPT $0.30–0.75 per trial, Opus $1.50–2.30.
- After copying files into the task folder, verify with a grep count per file before spending runs. A stale `instruction.md` wasted several. From v6 on, changed files ship with an apply script that copies them into Danny's layout (`environment/app/data/`), keeps his pinned digest, `instruction.md`, `solve.sh` and `task.toml` values, and prints the counts.
- Always read why a run failed, not just the score:
  - genuine: got the task's actual work wrong;
  - unfair: failed something the instruction or examples never established (fix the task);
  - self-inflicted: GPT kills its own terminal with `set -e` or `|| exit` in the live shell; Opus loses time to truncated responses (`grep -c "Output length exceeded" job.log`).
- To see what a crashed or timed-out run was worth, grade its collected artifact locally with the tests.
- Build the per-test pass matrix across runs to check solvability before submitting.
- Agent timeout: minimum 1800 s, ceiling 18000 s, typical 60–90 minutes. We use 9000 s because Opus needs the headroom.

## 8. Pre-submission checklist

1. File listing is clean and every file is used.
2. Oracle passes, repeatedly, with the expected test count.
3. No-op agent scores 0.
4. Mutants all rejected, including one per configured parameter value, one per rewritable field, the partial-replacement family and the replay family.
5. The reference reproduces every shipped example output.
6. Instruction is in Danny's words; `stb harbor check` passes on that exact text.
7. `task.toml`: explanations match current scope, hours and experience are his, timeout set.
8. Two trials per model read and classified; at least a few genuine failures; every test passes in some run.
9. `stb submissions update` with a note mapping each prior finding to "fixed" or "removed from scope".

## 9. Stop rule

Agree a limit before rebuilding. Ours: if a deepening round still shows one genuine failure or fewer in four runs, park the task rather than rebuild again.
