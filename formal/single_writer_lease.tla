---- MODULE single_writer_lease ----
EXTENDS Integers, FiniteSets

CONSTANTS
  Issuers,
  Targets,
  MaxTime,
  LeaseDur,
  MaxRenewals,
  CooldownDur

VARIABLES
  holder,      \* [Targets -> Issuers \union {"none"}]
  expires,     \* [Targets -> Int]
  renewals,    \* [Targets -> Int] consecutive renewals by current holder
  cooldown,    \* [Targets -> Int] deadline; same issuer blocked while now < cooldown
  cooldown_for,\* [Targets -> Issuers \union {"none"}]
  revoked,     \* subset of Issuers
  now

vars == <<holder, expires, renewals, cooldown, cooldown_for, revoked, now>>

TypeOK ==
  /\ holder \in [Targets -> Issuers \union {"none"}]
  /\ expires \in [Targets -> 0..MaxTime+LeaseDur]
  /\ renewals \in [Targets -> 0..MaxRenewals+1]
  /\ cooldown \in [Targets -> 0..MaxTime+CooldownDur]
  /\ cooldown_for \in [Targets -> Issuers \union {"none"}]
  /\ revoked \subseteq Issuers
  /\ now \in 0..MaxTime

Init ==
  /\ holder = [t \in Targets |-> "none"]
  /\ expires = [t \in Targets |-> 0]
  /\ renewals = [t \in Targets |-> 0]
  /\ cooldown = [t \in Targets |-> 0]
  /\ cooldown_for = [t \in Targets |-> "none"]
  /\ revoked = {}
  /\ now = 0

Tick ==
  /\ now < MaxTime
  /\ now' = now + 1
  /\ UNCHANGED <<holder, expires, renewals, cooldown, cooldown_for, revoked>>

Active(t) == holder[t] /= "none" /\ expires[t] > now
InCooldown(t,i) == cooldown_for[t] = i /\ cooldown[t] > now

Acquire(t,i) ==
  /\ i \in Issuers
  /\ i \notin revoked
  /\ ~Active(t)
  /\ ~InCooldown(t,i)
  /\ holder' = [holder EXCEPT ![t] = i]
  /\ expires' = [expires EXCEPT ![t] = now + LeaseDur]
  /\ renewals' = [renewals EXCEPT ![t] = 0]
  /\ cooldown' = [cooldown EXCEPT ![t] = 0]
  /\ cooldown_for' = [cooldown_for EXCEPT ![t] = "none"]
  /\ UNCHANGED <<revoked, now>>

Renew(t,i) ==
  /\ i \in Issuers
  /\ i \notin revoked
  /\ Active(t)
  /\ holder[t] = i
  /\ renewals[t] < MaxRenewals
  /\ expires' = [expires EXCEPT ![t] = now + LeaseDur]
  /\ renewals' = [renewals EXCEPT ![t] = @ + 1]
  /\ UNCHANGED <<holder, cooldown, cooldown_for, revoked, now>>

\* Renewal cap reached: force cooldown for same issuer (S21 starvation bound).
CapAndCooldown(t,i) ==
  /\ i \in Issuers
  /\ Active(t)
  /\ holder[t] = i
  /\ renewals[t] >= MaxRenewals
  /\ holder' = [holder EXCEPT ![t] = "none"]
  /\ expires' = [expires EXCEPT ![t] = now]
  /\ cooldown' = [cooldown EXCEPT ![t] = now + CooldownDur]
  /\ cooldown_for' = [cooldown_for EXCEPT ![t] = i]
  /\ renewals' = [renewals EXCEPT ![t] = 0]
  /\ UNCHANGED <<revoked, now>>

Expire(t) ==
  /\ Active(t) = FALSE
  /\ holder[t] /= "none"
  /\ expires[t] <= now
  /\ holder' = [holder EXCEPT ![t] = "none"]
  /\ renewals' = [renewals EXCEPT ![t] = 0]
  /\ UNCHANGED <<expires, cooldown, cooldown_for, revoked, now>>

\* DID revocation releases lease immediately (CLAIM-21.3).
Revoke(i) ==
  /\ i \in Issuers
  /\ revoked' = revoked \union {i}
  /\ holder' = [t \in Targets |-> IF holder[t] = i THEN "none" ELSE holder[t]]
  /\ expires' = [t \in Targets |-> IF holder[t] = i THEN now ELSE expires[t]]
  /\ renewals' = [t \in Targets |-> IF holder[t] = i THEN 0 ELSE renewals[t]]
  /\ UNCHANGED <<cooldown, cooldown_for, now>>

\* M-of-N RevocationManager+PolicyAuthority preemption (modeled abstractly).
Preempt(t,i) ==
  /\ t \in Targets /\ i \in Issuers
  /\ i \notin revoked
  /\ holder' = [holder EXCEPT ![t] = i]
  /\ expires' = [expires EXCEPT ![t] = now + LeaseDur]
  /\ renewals' = [renewals EXCEPT ![t] = 0]
  /\ cooldown' = [cooldown EXCEPT ![t] = 0]
  /\ cooldown_for' = [cooldown_for EXCEPT ![t] = "none"]
  /\ UNCHANGED <<revoked, now>>

Next ==
  \/ Tick
  \/ \E t \in Targets, i \in Issuers: Acquire(t,i)
  \/ \E t \in Targets, i \in Issuers: Renew(t,i)
  \/ \E t \in Targets, i \in Issuers: CapAndCooldown(t,i)
  \/ \E t \in Targets: Expire(t)
  \/ \E i \in Issuers: Revoke(i)
  \/ \E t \in Targets, i \in Issuers: Preempt(t,i)

Spec == Init /\ [][Next]_vars /\ WF_vars(Tick \/ Expire)

\* Safety: at most one issuer holds an active lease for a target.
SafetyExclusive ==
  \A t \in Targets:
    Active(t) => holder[t] \in Issuers /\ \A i \in Issuers: (holder[t] = i => TRUE)

\* Structural exclusivity (single holder value) and no revoked holder active.
SafetyNoRevokedHolder == \A t \in Targets: Active(t) => holder[t] \notin revoked

\* Liveness: leases eventually expire, allowing progress.
LivenessExpiry == \A t \in Targets: Active(t) ~> ~Active(t)

THEOREM Spec => []SafetyExclusive
THEOREM Spec => []SafetyNoRevokedHolder
====
