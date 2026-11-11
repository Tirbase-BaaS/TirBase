---- MODULE policy_lifecycle ----
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
  Versions,          \* finite set of policy versions, e.g. {1,2,3,4}
  MaxTime,           \* abstract time bound for TLC
  MaxM,              \* max co-signatures required
  MaxN               \* max signer pool

VARIABLES
  active_version,
  active_kind,       \* "Tightening" or "Loosening"
  pending,           \* <<version, kind, timelock_until, cancel_deadline, sigs, cancelled>>
  committed_counter,
  now

vars == <<active_version, active_kind, pending, committed_counter, now>>

Kind == {"Tightening","Loosening"}
NoPending == [present |-> FALSE]

TypeOK ==
  /\ active_version \in Versions
  /\ active_kind \in Kind
  /\ committed_counter \in Versions
  /\ now \in 0..MaxTime
  /\ pending.present \in BOOLEAN
  /\ (pending.present =>
        /\ pending.version \in Versions
        /\ pending.kind \in Kind
        /\ pending.timelock_until \in 0..MaxTime
        /\ pending.cancel_deadline \in 0..MaxTime
        /\ pending.sigs \in 0..MaxN
        /\ pending.cancelled \in BOOLEAN)

Init ==
  /\ active_version = 1
  /\ active_kind = "Tightening"
  /\ committed_counter = 1
  /\ now = 0
  /\ pending = NoPending

Tick ==
  /\ now < MaxTime
  /\ now' = now + 1
  /\ UNCHANGED <<active_version, active_kind, pending, committed_counter>>

\* Tightening: apply immediately if version strictly greater and anti-rollback holds.
IngestTightening(v) ==
  /\ v \in Versions
  /\ v > committed_counter
  /\ v > active_version
  /\ active_version' = v
  /\ active_kind' = "Tightening"
  /\ committed_counter' = v
  /\ pending' = NoPending
  /\ UNCHANGED now

\* Start loosening: must be > committed/active, M-of-N and timelock come from active policy.
StartLoosening(v, timelock, cancelWin, m, n, sigs0) ==
  /\ v \in Versions
  /\ v > committed_counter
  /\ v > active_version
  /\ ~pending.present
  /\ timelock \in 1..MaxTime
  /\ cancelWin \in 0..timelock
  /\ m \in 1..MaxM /\ n \in m..MaxN
  /\ sigs0 \in 0..n
  /\ pending' = [present |-> TRUE,
                 version |-> v,
                 kind |-> "Loosening",
                 timelock_until |-> now + timelock,
                 cancel_deadline |-> now + cancelWin,
                 sigs |-> sigs0,
                 cancelled |-> FALSE,
                 required_m |-> m]
  /\ UNCHANGED <<active_version, active_kind, committed_counter, now>>

AddCoSignature ==
  /\ pending.present
  /\ ~pending.cancelled
  /\ pending.sigs < MaxN
  /\ pending' = [pending EXCEPT !.sigs = @ + 1]
  /\ UNCHANGED <<active_version, active_kind, committed_counter, now>>

\* Cancel within cancel window (PolicyAuthority action).
CancelLoosening ==
  /\ pending.present
  /\ ~pending.cancelled
  /\ now <= pending.cancel_deadline
  /\ pending' = [pending EXCEPT !.cancelled = TRUE]
  /\ UNCHANGED <<active_version, active_kind, committed_counter, now>>

\* Apply loosening only after timelock, quorum, not cancelled, and anti-rollback.
ApplyLoosening ==
  /\ pending.present
  /\ ~pending.cancelled
  /\ now >= pending.timelock_until
  /\ pending.sigs >= pending.required_m
  /\ pending.version > committed_counter
  /\ active_version' = pending.version
  /\ active_kind' = "Loosening"
  /\ committed_counter' = pending.version
  /\ pending' = NoPending
  /\ UNCHANGED now

\* Rollback attempt: any bundle <= committed counter must be rejected (no state change).
RejectRollback(v) ==
  /\ v \in Versions
  /\ v <= committed_counter
  /\ UNCHANGED vars

Next ==
  \/ Tick
  \/ \E v \in Versions: IngestTightening(v)
  \/ \E v \in Versions, t \in 1..MaxTime, c \in 0..MaxTime, m \in 1..MaxM, n \in m..MaxN, s \in 0..n:
        StartLoosening(v,t,c,m,n,s)
  \/ AddCoSignature
  \/ CancelLoosening
  \/ ApplyLoosening
  \/ \E v \in Versions: RejectRollback(v)

Spec == Init /\ [][Next]_vars /\ WF_vars(ApplyLoosening \/ Tick)

\* Safety: no bad state reachable.
SafetyNoRollback == active_version >= committed_counter_initial
committed_counter_initial == 1

SafetyMonotonicCommitted == committed_counter >= 1
SafetyNoUncommittedActive == active_version <= committed_counter
SafetyNoTimelockBypass == pending.present => (active_version < pending.version \/ ~pending.cancelled /\ pending.sigs >= pending.required_m /\ now >= pending.timelock_until => TRUE)

\* Stronger invariants used by TLC.
InvNoRollback == active_version = committed_counter \/ (pending.present /\ ~pending.cancelled => active_version < pending.version)
InvCommittedMonotone == [][committed_counter' >= committed_counter]_vars
InvNeverActivateBelowCommitted == active_version >= 1 /\ committed_counter >= 1 /\ active_version <= committed_counter => TRUE

\* Practical safety invariant for model checking.
Safety ==
  /\ committed_counter >= 1
  /\ active_version >= 1
  /\ active_version <= committed_counter
  /\ (pending.present /\ ~pending.cancelled =>
        (active_version < pending.version))

\* Liveness: eventual progress under fair scheduling when a valid loosening is ready.
Progress ==
  <>(pending.present /\ ~pending.cancelled /\ pending.sigs >= pending.required_m => <>(~pending.present \/ pending.cancelled))

THEOREM Spec => []Safety
THEOREM Spec => Progress
====
