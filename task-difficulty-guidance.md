## Your Single Action Item

Make the core challenge harder. The most effective lever, based on your specific task:

- Remove some of the fully-specified rules from the docs and instead provide example inputs/outputs the agent must reverse-engineer the rules from
- Create scenarios where rules conflict or interact non-obviously — e.g., a mount that is simultaneously shadowed, uid-mapped, and capability-restricted in a way that requires reasoning through the interaction
- Add subtle C scorer bugs that don't follow a pattern the model can recognize from training data — novel memory-safety issues specific to your scorer's logic
- Use held-out test data that exercises rare combinations the agent's first-pass implementation will get wrong

Test locally with -k 4 for both models, targeting at least 3 failures out of 8 before resubmitting.

## HOW TO RESPOND TO A 100% PASS RATE (PERFECT-ACCURACY GATE FAILURE)

Read this before your next revision

### Short Version
When every agent run passes, the fix is to deepen the core challenge — not to add more rules, more tests, or more surface area.

---

### WHAT HAPPENED
Both frontier models (GPT-5.6 and Claude Opus 5) solved your task 8/8 times. Even grandfathered submissions are blocked at 100%. New submissions need at least 3 failures out of 8.

### WHY IT HAPPENED
Frontier models already possess the domain knowledge your task tests. They read your specs, derived every rule, and implemented correctly in one shot — typically in under 10 minutes against a multi-hour estimate.

A fully specified recipe that can be followed step-by-step is not difficult for these models, no matter how complex it looks to a human.

---

### THE QUESTION TO ASK YOURSELF

"Can an agent solve this by reading and applying my docs line by line — or does it have to reason, infer, and make judgment calls to get the answer?"



If the answer is the first, the task is too easy for frontier models regardless of how much domain expertise it represents.

---

### WHAT ACTUALLY MAKES TASKS HARDER

:white_check_mark: 1. Require inference, not just application
- Don't fully specify every rule — provide examples, evidence, or partial specs the agent must generalize from
- Force the agent to discover requirements from the environment, config, or domain conventions
- The goal should be clear, but not everything needed to satisfy it should be spelled out

:white_check_mark: 2. Add interacting constraints
- Rules that affect each other are far harder than independent rules
- A naive per-rule implementation should produce a plausible-but-wrong result
- Example: a uid mapping that changes how a capability check should behave, which changes how a mount is evaluated

:white_check_mark: 3. Include edge cases that require domain judgment
- Ambiguous or conflicting inputs where the "right answer" requires understanding why a rule exists
- Scenarios where the obvious implementation gets a subtle case wrong

:white_check_mark: 4. Verify against hidden variations
- Held-out test inputs that exercise the same rules under different, harder conditions
- Cases where multiple defects or rules compound in non-obvious ways

:white_check_mark: 5. Make the specification itself part of the challenge
- Instead of handing the agent a complete spec, provide domain artifacts (logs, examples, partial docs) it must interpret
- The agent should need to build a mental model before it can write code

---

### WHAT DOES NOT WORK

:x: Adding more independent rules — that's length, not difficulty
:x: Tightening numeric thresholds — shows up as near_miss, not real difficulty
:x: Making instructions vague or ambiguous — that's a broken task, not a hard one
:x: Adding obscure trivia — difficulty should come from reasoning
:x: Adding more tests on the same logic — more checks on easy work is still easy work
:x: Reducing the timeout — difficulty should come from the problem, not time pressure

---

### PRACTICAL STEPS

1. Review agent traces — understand exactly how they solved it. Where did they spend zero time thinking? That's where it's too easy

2. Identify what can be inferred instead of stated — which spec details can become examples or evidence the agent must interpret?

3. Find the interaction points — where do your rules touch each other? Build test cases around those intersections

4. Build a "plausible wrong" solution — what would a naive first-pass implementation get wrong? If the answer is "nothing," the task is too easy

5. Revise and test locally:stb harbor run -m @openai/gpt-5.6 -p ./your-task -k 4
stb harbor run -m @anthropic/claude-opus-5 -p ./your-task -k 4

6. Target: at least 3 failures out of 8 runs. If agents are still passing 6+ runs, the core challenge hasn't changed enough