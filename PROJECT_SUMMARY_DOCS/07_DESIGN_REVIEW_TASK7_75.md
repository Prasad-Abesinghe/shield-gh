# Task 7.75 — "Is Anything Actually Broken?" — Plain English

## The question the supervisor asked

*"If any of your results look really bad, figure out whether the design itself
is flawed and needs fixing. If nothing needs fixing, tell me that too."*

This was a self-audit — we went looking for our own weak points on purpose.

## The short answer

**Nothing about the detection or mitigation design is broken.** We found
exactly **one** number that looks bad on the surface, but it turned out to be
caused by an unrealistic test *scenario*, not a flaw in how SHIELD-GH works.

## The one "bad-looking" number

In our small 5-car test scenario, after we successfully detect and isolate the
attacker, the **overall network delivery rate (PDR)** — the percentage of
messages that successfully get through — kept **going down** instead of
recovering, ending up around 50%. That's the opposite of what we expected and
what the report currently claims should happen.

Importantly: this happened even though **the detection itself was perfect**
(100% accurate, zero false alarms) in the exact same test run. So the
*detector* wasn't the problem — something else was.

## Why this happened (the real cause)

Our small test setup uses just **5 cars in a single-file line**, with only
**one** message route active — like a single-lane road with no alternate
route. When we correctly detect and block the attacker car, if that attacker
happens to be sitting *on* that one-and-only route, blocking it **also blocks
all the good traffic**, because there's no other path around it.

It's like closing one lane on a single-lane road because a driver is breaking
the law — of course, all traffic stops, even though shutting that driver down
was the *correct* decision. The problem isn't the enforcement; it's that there
was no alternate lane.

We even tried an obvious potential fix (moving the attacker to a different
position in the line so it wasn't blocking the only path) — but that made
things *worse*, not better, confirming the issue really is "this toy topology
has no redundancy," not something we can patch around with a quick code
change.

There's also a smaller, secondary factor: the delivery-rate number we report
is a **running average over the whole simulation**, so once it dips, the
average stays dragged down for the rest of the run even if things are actually
fine again — making the problem look a bit worse on paper than it really is
moment-to-moment.

## Is this a flaw in SHIELD-GH's design?

**No.** Every other measurement we have proves the actual detection/mitigation
logic is solid:
- Perfect detection accuracy across all 6 attack types.
- The AI catches the hardest cases the rules miss (see [04_AI_LLM_FL.md](04_AI_LLM_FL.md)).
- The poison-detection in Federated Learning works (blocks bad updates 5/5 times).
- The full-mode AI integration inside the live simulation is perfect (Task 8).
- All cryptography and blockchain tests pass.

The delivery-rate dip is a property of **testing on a road with no alternate
route**, not of how well SHIELD-GH detects or isolates attackers.

## What we recommended fixing (not the algorithms — the test setup)

1. **Use a bigger, more realistic road network** (with multiple possible routes) when measuring "does delivery rate recover after we block an attacker" — the tiny 5-car single-lane test is fine for proving detection accuracy, but structurally can't show recovery, no matter how good the detector is.
2. **Report delivery rate as a short time-window snapshot**, not just one running average for the whole simulation, so a temporary dip doesn't visually drag down the whole result.
3. **Soften the report's current wording** that currently over-promises delivery-rate recovery, until we've actually tested it on a road network capable of showing that recovery.

**No code changes were made to the detection/mitigation logic** — this is
purely something to account for when we design the bigger experiments coming
up in Tasks 8.5 and 10.

## In short

We went looking for weaknesses on purpose. We found one — but it's a "we
tested on a road with no alternate lane" issue, not a "our attacker-catching
logic is broken" issue. The fix is choosing a better test road network for the
big experiments ahead, not rewriting any algorithms.
