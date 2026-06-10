# docs/design-partner/program.md

**Kaname Design Partner Program — Charter & Operations**

v1.0 · 2026-04-18 · Approved by EPM + Founder

The Design Partner Program (DPP) is Kaname's Phase 1 go-to-market strategy. Modeled on Apple's closed developer preview and enterprise pilot programs, it gives us 10 hand-picked organizations a heavily-subsidized, tightly-supported entry into Kaname — in exchange for depth of feedback we could not get from open-market customers.

---

## Why a DPP and not an open beta

Open betas are a trap for security products. They produce:

- Wide but shallow feedback (crashes on startup, broken icons)
- No insight into workflow-level integration issues
- Liability exposure (someone's mail gets lost; reputation dies)
- Press leaks before the narrative is ready

A DPP does the opposite:

- 10 partners × weekly deep-dive = 40 hours of real feedback per week
- NDA-protected runway to fix embarrassing things before they're public
- Case-study material from customers who actually used the product in production
- Word-of-mouth from exactly the buyer persona we target

---

## Partner selection criteria

We select for **coverage**, not prestige. The 10 partners must together represent:

| Axis | Must include |
|---|---|
| Industry | 2× financial services, 2× manufacturing, 1× professional services, 1× government/defense, 1× healthcare, 1× tech, 2× flexible |
| Size | 2× 50-200 employees, 4× 200-2000, 3× 2000-10000, 1× 10000+ |
| Geography | 6× Japan, 2× North America, 2× EU |
| Migration source | 4× from Exchange, 3× from Gmail, 2× from Notes, 1× greenfield |
| Leadership role | At least 1 partner per industry has a CISO who will publicly speak |
| Compliance | At least 2 under strict regulation (PCI-DSS, HIPAA, GDPR+) |

Reject if: unwilling to commit named executive sponsor, wants public credit before DVT complete, refuses NDA, pushing back on PQC/MLS (means they don't understand the value prop).

---

## What each partner commits

1. **Named executive sponsor** (CIO, CISO, or VP-level) — signs off on program participation
2. **Named operational DRI** (usually a senior IT engineer or security architect) — available for weekly 60-min check-ins
3. **Deploy to 10-50 mailboxes** during beta, representing a real team (not IT self-serving)
4. **Commit to 12 weeks** — not 4, not 8. Full DVT cycle.
5. **NDA covering product roadmap, security findings, and source**
6. **Case study cooperation** post-GA (we write, they approve, we both publish)
7. **Candid bug reporting** — including UX nit-level issues

---

## What Kaname commits

1. **Dedicated slack/chat channel** with Kaname engineering
2. **Weekly 60-min video call** with assigned Kaname DRI
3. **Custom deployment assistance** (migration scripts, SSO integration)
4. **24h response on critical issues** (defined as "production blocker for partner")
5. **Named engineering contact** (usually the EPM, for escalation)
6. **50% lifetime discount** on Business tier (not Pro/Enterprise)
7. **Early access** to v1.x features ahead of GA
8. **One on-site visit** within the 12 weeks if requested
9. **First 30 days entirely free** — pricing kicks in at week 5

---

## Timeline (12 weeks)

```
Week 0:  Contract signed, kickoff call, NDA exchanged
Week 1:  Environment provisioned, 10 pilot users onboarded
Week 2-3: Shadow period — users try Kaname alongside their existing mail
Week 4:  First feedback call; prioritized issue list
Week 5:  Migration starts for pilot team; pricing activates
Week 6-9: Daily active use; weekly calls; biweekly face-to-face if local
Week 10: Broader rollout eligibility assessment
Week 11: Case study draft, exec interview recorded
Week 12: Wrap-up call; decision on post-DPP expansion
```

---

## Operational rhythms

### Weekly call agenda (60 min hard)

- (5) What surprised you this week? (both positive and negative)
- (15) Issue triage — walk through their ticket list
- (15) Our roadmap update — what landed in their build this week
- (10) Their workflow observations — how Kaname fits (or doesn't) their process
- (10) Security/compliance questions from their team
- (5) Action items, next week's focus

### Feedback pipeline

1. Partner files ticket in shared tracker
2. Triaged within 4 business hours (severity classification)
3. Assigned to Kaname engineer with partner context
4. Status updates posted to shared channel
5. Resolution verified by partner before closing
6. Pattern detection: if 3+ partners report similar issue → roadmap entry

### Incident response

- Partner hits production issue → Slack escalation channel
- Kaname acknowledges within 1 hour during business hours, 4 hours off-hours
- Workaround within 24h, fix deployed within 72h for critical
- Post-incident write-up shared with partner within 1 week (and anonymized, with all partners quarterly)

---

## Deliverables from Kaname to partner

By end of DPP, each partner receives:

- Deployed Kaname for up to 50 users (continues with contract)
- Written security assessment of their deployment
- Migration documentation tailored to their source system
- Integration handbook for their specific SSO / MDM / SIEM
- Co-authored case study (their approval required before publish)
- Direct line to Kaname engineering for 12 months post-DPP

---

## Post-DPP path

Week 12 decision is binary:

- **EXPAND**: Partner commits to rolling out to wider organization under standard Business/Pro contract with 50% lifetime DPP discount on original seats, standard rates on new seats
- **EXIT**: Partner exits gracefully; Kaname provides 90-day continuation so they can migrate; no penalty

No partner has been "dropped" by Kaname to date (program hasn't launched). Historical reference only.

---

## Why this specifically helps Kaname succeed

This is a tool for making a good product, not a sales program. The commitments are asymmetric: partner gives us information, we give them software + attention. Both sides need to value the other side's contribution. In the hierarchy of what Kaname gets out of the DPP:

1. Depth feedback on real workflows (priceless)
2. Reference logos post-GA (significant for enterprise sales)
3. Case study content (marketing raw material)
4. Revenue (minor; pricing is subsidized)

What Kaname must resist:

- Accepting partners who won't give depth feedback just for logo value
- Spreading thin — 10 is the cap, not the target
- Over-promising — if a partner asks for something not on roadmap, we say no
- Letting partner feedback drive us off-keynote — the keynote is the filter
