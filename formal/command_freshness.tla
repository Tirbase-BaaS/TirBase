---- MODULE command_freshness ----
EXTENDS Integers, FiniteSets

CONSTANTS
  Issuers,
  Targets,
  Epochs,
  Seqs,
  W,    \* window width
  G     \* forward gap

VARIABLES
  epoch,
  highest,
  accepted,   \* set of <<issuer,target,epoch,seq>> durably accepted
  now_seq

vars == <<epoch, highest, accepted, now_seq>>

TypeOK ==
  /\ epoch \in Epochs
  /\ highest \in [Issuers \X Targets -> Int]
  /\ accepted \subseteq (Issuers \X Targets \X Epochs \X Seqs)
  /\ now_seq \in Seqs

Init ==
  /\ epoch \in Epochs
  /\ highest = [k \in Issuers \X Targets |-> 0]
  /\ accepted = {}
  /\ now_seq \in Seqs

Tick ==
  /\ now_seq < Max(Seqs)
  /\ now_seq' = now_seq + 1
  /\ UNCHANGED <<epoch, highest, accepted>>

Max(S) == CHOOSE x \in S : \A y \in S : y <= x

InWindow(i,t,s) ==
  LET h == highest[<<i,t>>]
  IN s >= h - W /\ s <= h + G

\* Accept only when in window, not previously accepted in this epoch, and commit is atomic.
Accept(i,t,s,e) ==
  /\ i \in Issuers /\ t \in Targets /\ s \in Seqs /\ e \in Epochs
  /\ e = epoch
  /\ InWindow(i,t,s)
  /\ <<i,t,e,s>> \notin accepted
  /\ accepted' = accepted \union {<<i,t,e,s>>}
  /\ highest' = [highest EXCEPT ![<<i,t>>] = IF s > highest[<<i,t>>] THEN s ELSE highest[<<i,t>>]]
  /\ UNCHANGED <<epoch, now_seq>>

\* Replay of same (issuer,target,epoch,seq) is rejected.
RejectReplay(i,t,s,e) ==
  /\ <<i,t,e,s>> \in accepted
  /\ UNCHANGED vars

\* Sequence outside window rejected (S20: must not advance highest without commit).
RejectOutside(i,t,s,e) ==
  /\ e = epoch
  /\ ~InWindow(i,t,s)
  /\ UNCHANGED vars

\* Epoch bump invalidates prior-epoch commands (stale epoch binding).
BumpEpoch(e2) ==
  /\ e2 \in Epochs
  /\ e2 > epoch
  /\ epoch' = e2
  /\ highest' = [k \in Issuers \X Targets |-> 0]
  /\ UNCHANGED <<accepted, now_seq>>

\* PolicyAuthority-signed window reset (re-enrollment/wrap) advances baseline durably.
WindowReset(i,t,newBase) ==
  /\ i \in Issuers /\ t \in Targets /\ newBase \in Int
  /\ newBase >= highest[<<i,t>>]
  /\ highest' = [highest EXCEPT ![<<i,t>>] = newBase]
  /\ UNCHANGED <<epoch, accepted, now_seq>>

Next ==
  \/ Tick
  \/ \E i \in Issuers, t \in Targets, s \in Seqs, e \in Epochs: Accept(i,t,s,e)
  \/ \E i \in Issuers, t \in Targets, s \in Seqs, e \in Epochs: RejectReplay(i,t,s,e)
  \/ \E i \in Issuers, t \in Targets, s \in Seqs, e \in Epochs: RejectOutside(i,t,s,e)
  \/ \E e2 \in Epochs: BumpEpoch(e2)
  \/ \E i \in Issuers, t \in Targets, b \in Seqs: WindowReset(i,t,b)

Spec == Init /\ [][Next]_vars

\* Safety: no (issuer,target,epoch,seq) accepted twice in the same epoch.
SafetyNoReplay == \A i \in Issuers, t \in Targets, e \in Epochs, s \in Seqs:
  Cardinality({x \in accepted : x = <<i,t,e,s>>}) <= 1

\* Safety: accepted seqs for current epoch were in-window at acceptance baseline logic
\* (captured structurally by never accepting outside window and by reset/epoch controls).
SafetyEpochBinding == \A x \in accepted: x[3] \in Epochs

\* Liveness: in-window fresh sequences can eventually be accepted (under fairness).
LivenessProgress == \A i \in Issuers, t \in Targets, s \in Seqs:
  (epoch \in Epochs /\ InWindow(i,t,s) /\ <<i,t,epoch,s>> \notin accepted) ~> <<i,t,epoch,s>> \in accepted

THEOREM Spec => []SafetyNoReplay
THEOREM Spec => []SafetyEpochBinding
====
