---- MODULE ledger_recovery ----
EXTENDS Integers, FiniteSets

CONSTANTS
  Entries

VARIABLES
  state,          \* [Entries -> {"None","Actuating","Complete","Failed","Unknown"}]
  committed,      \* set of entries with a durable record
  crashed,
  readback,       \* oracle for reconciliation: "Match","Mismatch","Timeout","Unknown"
  reconciled

vars == <<state, committed, crashed, readback, reconciled>>

States == {"None","Actuating","Complete","Failed","Unknown"}
Readbacks == {"Match","Mismatch","Timeout","Unknown"}

TypeOK ==
  /\ state \in [Entries -> States]
  /\ committed \subseteq Entries
  /\ crashed \in BOOLEAN
  /\ readback \in [Entries -> Readbacks]
  /\ reconciled \in BOOLEAN

Init ==
  /\ state = [e \in Entries |-> "None"]
  /\ committed = {}
  /\ crashed = FALSE
  /\ readback \in [Entries -> Readbacks]
  /\ reconciled = FALSE

\* Stage 16 atomic commit writes Actuating durably before dispatch (INV-12).
\* New work begins: the previous boot's reconciliation no longer describes the
\* whole state, so `reconciled` is cleared.  Without this, the
\* "nothing is stuck Actuating after recovery" invariant would be falsified by
\* any legitimately dispatched entry after a successful recovery.
CommitActuating(e) ==
  /\ ~crashed
  /\ state[e] = "None"
  /\ state' = [state EXCEPT ![e] = "Actuating"]
  /\ committed' = committed \union {e}
  /\ reconciled' = FALSE
  /\ UNCHANGED <<crashed, readback>>

\* Dispatch/driver outcome can complete or fail after commit.
DriverComplete(e) ==
  /\ ~crashed
  /\ state[e] = "Actuating"
  /\ state' = [state EXCEPT ![e] = "Complete"]
  /\ UNCHANGED <<committed, crashed, readback, reconciled>>

DriverFail(e) ==
  /\ ~crashed
  /\ state[e] = "Actuating"
  /\ state' = [state EXCEPT ![e] = "Failed"]
  /\ UNCHANGED <<committed, crashed, readback, reconciled>>

DriverUnknown(e) ==
  /\ ~crashed
  /\ state[e] = "Actuating"
  /\ state' = [state EXCEPT ![e] = "Unknown"]
  /\ UNCHANGED <<committed, crashed, readback, reconciled>>

Crash ==
  /\ ~crashed
  /\ crashed' = TRUE
  /\ UNCHANGED <<state, committed, readback, reconciled>>

\* Boot crash reconciliation scans Actuating entries and resolves them.
Reconcile ==
  /\ crashed
  /\ ~reconciled
  /\ state' = [e \in Entries |->
        CASE state[e] /= "Actuating" -> state[e]
          [] readback[e] = "Match" -> "Complete"
          [] readback[e] = "Mismatch" -> "Failed"
          [] readback[e] = "Timeout" -> "Unknown"
          [] OTHER -> "Unknown"]
  /\ reconciled' = TRUE
  /\ crashed' = FALSE
  /\ UNCHANGED <<committed, readback>>

\* Operator may clear an Unknown after review (PolicyAuthority path) to unblock target.
OperatorClearUnknown(e) ==
  /\ ~crashed
  /\ state[e] = "Unknown"
  /\ state' = [state EXCEPT ![e] = "Failed"]
  /\ UNCHANGED <<committed, crashed, readback, reconciled>>

\* Terminal states have no transition of their own; stuttering keeps TLC from
\* reporting a false deadlock once every entry is Complete/Failed.
Stutter == UNCHANGED vars

Next ==
  \/ Stutter
  \/ \E e \in Entries: CommitActuating(e)
  \/ \E e \in Entries: DriverComplete(e)
  \/ \E e \in Entries: DriverFail(e)
  \/ \E e \in Entries: DriverUnknown(e)
  \/ Crash
  \/ Reconcile
  \/ \E e \in Entries: OperatorClearUnknown(e)

Spec == Init /\ [][Next]_vars /\ WF_vars(Reconcile)

\* Safety: no bad state reachable.
SafetyDurableFirstState == \A e \in Entries: e \in committed => state[e] /= "None"
SafetyTerminalOnlyForward ==
  \A e \in Entries:
    state[e] \in {"Complete","Failed"} =>
      ~(ENABLED DriverComplete(e) \/ ENABLED DriverFail(e))

\* Unknown is a valid blocking state but never a silent loss of durable record.
SafetyUnknownIsDurable == \A e \in Entries: state[e] = "Unknown" => e \in committed

\* Liveness: after crash, reconciliation eventually runs and resolves Actuating entries.
LivenessRecovery == crashed ~> reconciled
LivenessNoStuckActuatingAfterRecovery ==
  reconciled => \A e \in Entries: state[e] /= "Actuating"

THEOREM Spec => []SafetyDurableFirstState
THEOREM Spec => []SafetyUnknownIsDurable
THEOREM Spec => LivenessRecovery
====
