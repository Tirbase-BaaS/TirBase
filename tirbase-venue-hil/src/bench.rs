// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic HIL bench: controller + reader + turnstile + power supply.
//!
//! The bench keeps the production [`GateController`] and ST-03
//! [`AccessController`] decision path intact. Its physical models add the
//! pieces a lab bench has but the controller does not own:
//!
//! * a reader with its own power and back-office link;
//! * a turnstile whose drive coil has a bounded hold and springs to the
//!   configured safe state when the controller stops heartbeating;
//! * a 24 V supply with shallow and deep brownout behaviour;
//! * a monotonic safety clock: wall-clock jumps are recorded but never become
//!   the gate's decision time.
//!
//! All time is supplied explicitly, so runs are byte-for-byte reproducible.

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tirbase_venue::{
    AccessPolicy, AccessPolicyId, AccessPolicyRegistry, AntiPassbackMode, EffectiveWindow, Gate,
    GateId, PassbackPolicy, ReEntryPolicy, Reader, ReaderId, SpaceModel, TicketClass,
    TicketSelector, TicketType, TicketTypeId, TimeWindow, TopologyVersion, Venue, Zone, ZoneId,
};
use tirbase_venue_access::{
    AccessController, CredentialRegistry, CredentialSource, PresentedCredential,
};
use tirbase_venue_gate::{
    DriveCommand, FailMode, GateConfig, GateController, GateDecision, GateEvent, GatePosition,
    GateTimings, PositionFeedback, Presentation, SafeState,
};

/// Bench time zero (microseconds, Unix-epoch compatible).
pub const T0: i64 = 1_700_000_000_000_000;
/// Nominal 24 V supply.
pub const NOMINAL_MV: u32 = 24_000;
/// Below this rail the controller and reader reset to their safe state.
pub const CONTROLLER_BROWNOUT_MV: u32 = 19_000;
/// The turnstile actuator loses drive below this rail.
pub const TURNSTILE_BROWNOUT_MV: u32 = 18_000;
/// Hardware watchdog: no fresh drive command for this long and the turnstile
/// returns to the configured safe state. This is deliberately longer than the
/// controller's 5 s open hold, so normal operation never trips it.
pub const TURNSTILE_MAX_DRIVE_US: i64 = 12_000_000;
/// Maximum credential fixtures on the bench.
pub const MAX_BENCH_CARDS: usize = 1_024;

const DAY_US: i64 = 86_400_000_000;

/// Where the power was cut in the gate's operating sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossStage {
    /// No credential presented.
    Idle,
    /// The reader saw a card but the controller had not yet decided.
    ReaderTap,
    /// The controller authorised and queued an unlock, not yet driven.
    PermitArmed,
    /// The turnstile received the unlock command but had not reported it.
    Actuating,
    /// A person passed; the lane is open.
    Passage,
    /// The open hold elapsed and the controller queued a re-lock.
    Reclosing,
}

impl LossStage {
    /// Stable evidence identifier.
    pub fn code(self) -> &'static str {
        match self {
            LossStage::Idle => "idle",
            LossStage::ReaderTap => "reader_tap",
            LossStage::PermitArmed => "permit_armed",
            LossStage::Actuating => "actuating",
            LossStage::Passage => "passage",
            LossStage::Reclosing => "reclosing",
        }
    }

    /// Every stage in execution order.
    pub fn all() -> [LossStage; 6] {
        [
            LossStage::Idle,
            LossStage::ReaderTap,
            LossStage::PermitArmed,
            LossStage::Actuating,
            LossStage::Passage,
            LossStage::Reclosing,
        ]
    }
}

/// One recorded power cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerLossRecord {
    /// Operational stage.
    pub stage: LossStage,
    /// Configured fail mode.
    pub fail_mode: FailMode,
    /// Configured safe state.
    pub safe_state: SafeState,
    /// Controller position after the cut.
    pub controller_position: GatePosition,
    /// Turnstile position after the cut.
    pub turnstile_position: GatePosition,
    /// Safe-state drive command emitted by the controller.
    pub safe_command: Option<DriveCommand>,
    /// Supply rail before the cut.
    pub voltage_before_mv: u32,
    /// Reader was powered after the cut.
    pub reader_powered: bool,
}

impl PowerLossRecord {
    /// True when both the controller and the physical lane are safe.
    pub fn safe(&self) -> bool {
        self.controller_position == self.safe_state.position()
            && self.turnstile_position == self.safe_state.position()
            && !self.reader_powered
            && self.safe_command == Some(self.safe_state.drive_command())
    }
}

/// Monotonic safety clock. Wall time can jump; the gate never sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyClock {
    mono_us: i64,
    wall_us: i64,
    wall_jumps: u32,
    largest_jump_us: i64,
}

impl SafetyClock {
    /// Start at [`T0`].
    pub fn new() -> Self {
        Self {
            mono_us: T0,
            wall_us: T0,
            wall_jumps: 0,
            largest_jump_us: 0,
        }
    }

    /// Gate decision time: monotonic and unaffected by wall-clock poisoning.
    pub fn gate_time_us(&self) -> i64 {
        self.mono_us
    }

    /// Wall time, for logs only.
    pub fn wall_time_us(&self) -> i64 {
        self.wall_us
    }

    /// Recorded wall-clock jumps.
    pub fn wall_jumps(&self) -> u32 {
        self.wall_jumps
    }

    /// Largest absolute wall jump.
    pub fn largest_jump_us(&self) -> i64 {
        self.largest_jump_us
    }

    /// Advance both domains.
    pub fn advance(&mut self, micros: i64) {
        if micros <= 0 {
            return;
        }
        self.mono_us = self.mono_us.saturating_add(micros);
        self.wall_us = self.wall_us.saturating_add(micros);
    }

    /// Jump wall time only. The gate's monotonic time does not move.
    pub fn jump_wall(&mut self, micros: i64) {
        self.wall_jumps = self.wall_jumps.saturating_add(1);
        self.largest_jump_us = self.largest_jump_us.max(micros.abs());
        self.wall_us = self.wall_us.saturating_add(micros);
    }
}

impl Default for SafetyClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Reader-side bench model: power, back-office link and card reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchReader {
    reader_id: ReaderId,
    powered: bool,
    backoffice_link: bool,
    reads: u64,
    brownouts: u32,
}

impl BenchReader {
    pub fn powered(&self) -> bool {
        self.powered
    }

    pub fn backoffice_link(&self) -> bool {
        self.backoffice_link
    }

    pub fn reads(&self) -> u64 {
        self.reads
    }

    pub fn brownouts(&self) -> u32 {
        self.brownouts
    }

    fn power_off(&mut self) {
        self.powered = false;
        self.backoffice_link = false;
    }

    fn power_restore(&mut self) {
        self.powered = true;
        self.backoffice_link = true;
    }

    fn read(&mut self) -> Result<(), String> {
        if !self.powered {
            return Err("reader has no power".to_string());
        }
        self.reads = self.reads.saturating_add(1);
        Ok(())
    }

    fn brownout(&mut self) {
        self.brownouts = self.brownouts.saturating_add(1);
        self.backoffice_link = false;
    }
}

/// Physical turnstile/barrier model.
///
/// The drive has a bounded hold. If software stops refreshing it, a
/// fail-secure lane springs locked; a fail-safe lane is released by design.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Turnstile {
    fail_mode: FailMode,
    powered: bool,
    position: GatePosition,
    hold_until_us: Option<i64>,
    stuck_locked: bool,
    stuck_open: bool,
    max_drive_us: i64,
}

impl Turnstile {
    pub fn new(fail_mode: FailMode) -> Self {
        Self {
            fail_mode,
            powered: true,
            position: GatePosition::Locked,
            hold_until_us: None,
            stuck_locked: false,
            stuck_open: false,
            max_drive_us: TURNSTILE_MAX_DRIVE_US,
        }
    }

    pub fn position(&self) -> GatePosition {
        self.position
    }

    pub fn powered(&self) -> bool {
        self.powered
    }

    pub fn hold_until_us(&self) -> Option<i64> {
        self.hold_until_us
    }

    pub fn fail_mode(&self) -> FailMode {
        self.fail_mode
    }

    /// Inject a mechanism fault. `stuck_open` is a physical fault; a power cut
    /// must still recover the fail-secure safe state.
    pub fn with_stuck_open(mut self) -> Self {
        self.stuck_open = true;
        self
    }

    pub fn with_stuck_locked(mut self) -> Self {
        self.stuck_locked = true;
        self
    }

    /// Set a stuck-open physical fault in place.
    pub fn set_stuck_open(&mut self, stuck_open: bool) {
        self.stuck_open = stuck_open;
    }

    /// Apply a drive command at `at_utc_us`.
    pub fn apply(&mut self, command: DriveCommand, at_utc_us: i64) {
        if !self.powered {
            return;
        }
        match command {
            DriveCommand::Unlock => {
                if !self.stuck_locked {
                    self.position = GatePosition::Unlocked;
                    self.hold_until_us = Some(at_utc_us.saturating_add(self.max_drive_us));
                }
            }
            DriveCommand::Lock => {
                self.hold_until_us = None;
                self.position = if self.stuck_open {
                    GatePosition::Unlocked
                } else {
                    GatePosition::Locked
                };
            }
            DriveCommand::Release => {
                if !self.stuck_locked {
                    self.position = GatePosition::Open;
                    self.hold_until_us = Some(at_utc_us.saturating_add(self.max_drive_us));
                }
            }
        }
    }

    /// Record a physical passage.
    pub fn passage(&mut self, at_utc_us: i64) -> bool {
        if !self.powered || !self.position.is_passable() {
            return false;
        }
        self.position = GatePosition::Open;
        self.hold_until_us = Some(at_utc_us.saturating_add(self.max_drive_us));
        true
    }

    /// Independent hardware watchdog: no refreshed drive past the hold and the
    /// mechanism returns to its fail-mode safe state.
    pub fn tick(&mut self, at_utc_us: i64) {
        let Some(until) = self.hold_until_us else {
            return;
        };
        if at_utc_us < until {
            return;
        }
        self.hold_until_us = None;
        self.position = match self.fail_mode {
            FailMode::FailSecure if !self.stuck_open => GatePosition::Locked,
            FailMode::FailSecure => GatePosition::Unlocked,
            FailMode::FailSafe => GatePosition::Unlocked,
        };
    }

    /// Feedback to the controller.
    pub fn feedback(&self) -> PositionFeedback {
        PositionFeedback::new(self.position)
    }

    /// De-energised: the actuator falls to the configured safe position.
    pub fn power_cut(&mut self) {
        self.powered = false;
        self.hold_until_us = None;
        self.position = self.fail_mode.safe_state().position();
    }

    /// Power restored: position is unknown until the controller drives it.
    pub fn power_restore(&mut self) {
        self.powered = true;
        self.hold_until_us = None;
        self.position = GatePosition::Unknown;
    }
}

/// Scriptable 24 V supply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowerSupply {
    voltage_mv: u32,
    powered: bool,
    cuts: u32,
    brownouts: u32,
}

impl PowerSupply {
    pub fn new() -> Self {
        Self {
            voltage_mv: NOMINAL_MV,
            powered: true,
            cuts: 0,
            brownouts: 0,
        }
    }

    pub fn voltage_mv(&self) -> u32 {
        self.voltage_mv
    }

    pub fn is_powered(&self) -> bool {
        self.powered
    }

    pub fn cuts(&self) -> u32 {
        self.cuts
    }

    pub fn brownouts(&self) -> u32 {
        self.brownouts
    }

    fn brownout(&mut self, millivolts: u32) {
        self.brownouts = self.brownouts.saturating_add(1);
        self.voltage_mv = millivolts.min(NOMINAL_MV);
    }

    fn cut(&mut self) {
        if self.powered {
            self.cuts = self.cuts.saturating_add(1);
        }
        self.powered = false;
        self.voltage_mv = 0;
    }

    fn restore(&mut self) {
        self.powered = true;
        self.voltage_mv = NOMINAL_MV;
    }
}

impl Default for PowerSupply {
    fn default() -> Self {
        Self::new()
    }
}

/// The composed HIL bench.
pub struct HilBench {
    clock: SafetyClock,
    controller: GateController,
    reader: BenchReader,
    turnstile: Turnstile,
    power: PowerSupply,
    gate_id: GateId,
    cards: Vec<PresentedCredential>,
    next_nonce: u64,
}

impl HilBench {
    /// Build a one-card bench.
    pub fn new(fail_mode: FailMode) -> Result<Self, String> {
        Self::with_options(fail_mode, 1, 1024, 512)
    }

    /// Build a bench with `card_count` rotating credentials and explicit
    /// bounded audit/event capacities.
    pub fn with_options(
        fail_mode: FailMode,
        card_count: usize,
        audit_capacity: usize,
        event_capacity: usize,
    ) -> Result<Self, String> {
        let card_count = card_count.clamp(1, MAX_BENCH_CARDS);
        let (access, cards) = access_fixture(card_count);
        let config = bench_config(fail_mode, audit_capacity, event_capacity)?;
        let controller =
            GateController::new(config, access).map_err(|error| format!("controller: {error}"))?;
        Ok(Self {
            clock: SafetyClock::new(),
            controller,
            reader: BenchReader {
                reader_id: reader_id(),
                powered: true,
                backoffice_link: true,
                reads: 0,
                brownouts: 0,
            },
            turnstile: Turnstile::new(fail_mode),
            power: PowerSupply::new(),
            gate_id: gate_id(),
            cards,
            next_nonce: 1,
        })
    }

    pub fn clock(&self) -> &SafetyClock {
        &self.clock
    }

    pub fn clock_mut(&mut self) -> &mut SafetyClock {
        &mut self.clock
    }

    pub fn controller(&self) -> &GateController {
        &self.controller
    }

    pub fn controller_mut(&mut self) -> &mut GateController {
        &mut self.controller
    }

    pub fn reader(&self) -> &BenchReader {
        &self.reader
    }

    pub fn turnstile(&self) -> &Turnstile {
        &self.turnstile
    }

    pub fn turnstile_mut(&mut self) -> &mut Turnstile {
        &mut self.turnstile
    }

    pub fn power(&self) -> &PowerSupply {
        &self.power
    }

    pub fn card_count(&self) -> usize {
        self.cards.len()
    }

    pub fn now_us(&self) -> i64 {
        self.clock.gate_time_us()
    }

    pub fn position(&self) -> GatePosition {
        self.controller.position()
    }

    pub fn safe_state(&self) -> SafeState {
        self.controller.safe_state()
    }

    pub fn fail_mode(&self) -> FailMode {
        self.controller.fail_mode()
    }

    /// Reader sees a card without delivering it to the controller.
    pub fn reader_tap(&mut self) -> Result<(), String> {
        self.reader.read()
    }

    /// Present a card from the rotating fixture to the controller.
    pub fn present_card(&mut self, index: usize) -> Result<GateDecision, String> {
        self.reader.read()?;
        let card = self
            .cards
            .get(index % self.cards.len())
            .cloned()
            .ok_or_else(|| "no card fixture".to_string())?;
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.saturating_add(1);
        self.controller
            .present(
                &Presentation::new(card, nonce),
                &self.gate_id,
                self.clock.gate_time_us(),
            )
            .map_err(|error| error.to_string())
    }

    /// Drain controller commands into the physical lane and fold feedback back.
    pub fn settle(&mut self) {
        let at = self.clock.gate_time_us();
        let commands = self.controller.take_commands();
        for command in commands {
            self.turnstile.apply(command, at);
        }
        let feedback = self.turnstile.feedback();
        self.controller.apply_feedback(feedback, at);
    }

    /// Consume the permit and rotate the physical turnstile.
    pub fn passage(&mut self) -> Result<u64, String> {
        let at = self.clock.gate_time_us();
        let permit = self
            .controller
            .passage(at)
            .map_err(|error| error.to_string())?;
        self.turnstile.passage(at);
        let feedback = self.turnstile.feedback();
        self.controller.apply_feedback(feedback, at);
        Ok(permit)
    }

    /// Advance both controller and mechanism by `micros`.
    pub fn advance(&mut self, micros: i64) {
        self.clock.advance(micros);
        let at = self.clock.gate_time_us();
        self.turnstile.tick(at);
        self.controller.tick(at);
        self.settle();
    }

    /// Advance the controller's clock and run its timers, without refreshing
    /// the physical drive. Used to cut power with a re-lock in flight.
    pub fn advance_controller(&mut self, micros: i64) {
        self.clock.advance(micros);
        self.controller.tick(self.clock.gate_time_us());
    }

    /// Advance the physical watchdog only. This proves the lane cannot be held
    /// open by a controller that stops ticking.
    pub fn advance_turnstile(&mut self, micros: i64) {
        self.clock.advance(micros);
        self.turnstile.tick(self.clock.gate_time_us());
    }

    /// Feed the current physical position back to the controller.
    pub fn feed_feedback(&mut self) {
        let feedback = self.turnstile.feedback();
        self.controller
            .apply_feedback(feedback, self.clock.gate_time_us());
    }

    /// Cut all power at `stage` and record the resulting safe states.
    pub fn cut_power(&mut self, stage: LossStage) -> PowerLossRecord {
        let voltage_before_mv = self.power.voltage_mv();
        let at = self.clock.gate_time_us();
        self.power.cut();
        self.reader.power_off();
        self.controller.access_mut().go_offline(at);
        self.controller.power_loss(at);
        self.turnstile.power_cut();
        let safe_command = self.controller.take_commands().last().copied();
        PowerLossRecord {
            stage,
            fail_mode: self.fail_mode(),
            safe_state: self.safe_state(),
            controller_position: self.controller.position(),
            turnstile_position: self.turnstile.position(),
            safe_command,
            voltage_before_mv,
            reader_powered: self.reader.powered(),
        }
    }

    /// Restore power, re-establish the link and drive the lane to a known state.
    pub fn restore_power(&mut self) {
        let at = self.clock.gate_time_us();
        self.power.restore();
        self.reader.power_restore();
        self.controller.access_mut().go_online(at);
        self.controller.power_restore(at);
        self.turnstile.power_restore();
        self.settle();
    }

    /// Apply a shallow or deep supply brownout.
    ///
    /// At or above [`CONTROLLER_BROWNOUT_MV`] the controller and actuator stay
    /// powered but the reader's back-office link drops. Below it, the whole
    /// controller resets and the configured safe state applies.
    pub fn brownout(&mut self, millivolts: u32, stage: LossStage) -> Option<PowerLossRecord> {
        self.power.brownout(millivolts);
        self.reader.brownout();
        let at = self.clock.gate_time_us();
        self.controller.access_mut().go_offline(at);
        if millivolts < CONTROLLER_BROWNOUT_MV {
            let mut record = self.cut_power(stage);
            record.voltage_before_mv = millivolts;
            Some(record)
        } else {
            None
        }
    }

    /// Reader back-office link loss; the reader keeps reading cards locally.
    pub fn lose_network(&mut self) {
        self.reader.backoffice_link = false;
        let at = self.clock.gate_time_us();
        self.controller.access_mut().go_offline(at);
    }

    /// Reader back-office link restored.
    pub fn restore_network(&mut self) {
        self.reader.backoffice_link = true;
        let at = self.clock.gate_time_us();
        self.controller.access_mut().go_online(at);
    }

    /// Prime the ST-03 offline grant cache without opening the lane.
    pub fn prime_cache(&mut self, index: usize) -> Result<(), String> {
        let card = self
            .cards
            .get(index % self.cards.len())
            .cloned()
            .ok_or_else(|| "no card fixture".to_string())?;
        self.controller
            .access_mut()
            .authorize(&card, &self.gate_id, self.clock.gate_time_us())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Assert the fire-alarm input: egress opens in both fail modes.
    pub fn fire_alarm(&mut self) {
        let at = self.clock.gate_time_us();
        self.controller.engage_fire_alarm(at);
        for command in self.controller.take_commands() {
            self.turnstile.apply(command, at);
        }
        let feedback = self.turnstile.feedback();
        self.controller.apply_feedback(feedback, at);
    }

    /// Clear the fire alarm and re-secure the lane.
    pub fn clear_fire_alarm(&mut self) {
        let at = self.clock.gate_time_us();
        self.controller.clear_fire_alarm(at);
        for command in self.controller.take_commands() {
            self.turnstile.apply(command, at);
        }
        let feedback = self.turnstile.feedback();
        self.controller.apply_feedback(feedback, at);
    }

    /// Inject a stuck-open physical mechanism.
    pub fn inject_stuck_open(&mut self) {
        let fail_mode = self.fail_mode();
        self.turnstile =
            std::mem::replace(&mut self.turnstile, Turnstile::new(fail_mode)).with_stuck_open();
    }

    /// Drain and return controller events (for evidence, not the safety check).
    pub fn drain_events(&mut self) -> Vec<GateEvent> {
        self.controller
            .drain_events()
            .into_iter()
            .map(|record| record.event)
            .collect()
    }

    /// Convenience: did the last event stream contain an egress release?
    pub fn fire_alarm_active(&self) -> bool {
        self.controller.fire_alarm_active()
    }
}

/// Gate policy for the bench.
pub fn bench_config(
    fail_mode: FailMode,
    audit_capacity: usize,
    event_capacity: usize,
) -> Result<GateConfig, String> {
    GateConfig::new(gate_id(), fail_mode, GateTimings::standard())
        .map_err(|error| error.to_string())?
        .with_audit_capacity(audit_capacity)
        .map_err(|error| error.to_string())?
        .with_event_capacity(event_capacity)
        .map_err(|error| error.to_string())
}

/// Deterministic card fixtures (public for tests that need a card count).
pub fn cards(count: usize) -> Vec<PresentedCredential> {
    (0..count.clamp(1, MAX_BENCH_CARDS))
        .map(|index| PresentedCredential::new(CredentialSource::Osdp, material(index)))
        .collect()
}

fn material(index: usize) -> Vec<u8> {
    let mut bytes = vec![0x04, 0xA1, 0xB2, 0xC3];
    bytes.extend_from_slice(&(index as u32).to_be_bytes());
    bytes
}

fn access_fixture(count: usize) -> (AccessController, Vec<PresentedCredential>) {
    let mut credentials = CredentialRegistry::new();
    let mut presented = Vec::with_capacity(count);
    for index in 0..count {
        let holder = format!("holder-{}", index + 1);
        let holder_id = holder.parse().expect("holder id");
        credentials
            .add_holder(holder_id, format!("Bench holder {}", index + 1))
            .expect("holder");
        credentials
            .register(
                holder.parse().expect("holder id"),
                ticket_type_id(),
                CredentialSource::Osdp,
                &material(index),
            )
            .expect("credential");
        presented.push(PresentedCredential::new(
            CredentialSource::Osdp,
            material(index),
        ));
    }
    let passback = PassbackPolicy::new(AntiPassbackMode::Disabled, ReEntryPolicy::NotAllowed)
        .expect("bench passback policy");
    let access = AccessController::new(reader_id(), topology(), policies(), space(), credentials)
        .with_passback(passback);
    (access, presented)
}

fn parsed<T>(value: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("literal fixture id")
}

fn gate_id() -> GateId {
    parsed("gate-n1")
}

fn reader_id() -> ReaderId {
    parsed("reader-n1-a")
}

fn zone_id() -> ZoneId {
    parsed("zone-north")
}

fn ticket_type_id() -> TicketTypeId {
    parsed("tt-general")
}

fn topology() -> TopologyVersion {
    let venue = Venue {
        id: parsed("venue-1"),
        name: "TirBase Arena".to_string(),
    };
    let zones = vec![Zone {
        id: zone_id(),
        venue_id: venue.id.clone(),
        name: "North concourse".to_string(),
    }];
    let gates = vec![Gate {
        id: gate_id(),
        zone_id: zone_id(),
        name: "North 1".to_string(),
    }];
    let readers = vec![Reader {
        id: reader_id(),
        gate_id: gate_id(),
        name: "North 1 reader".to_string(),
    }];
    TopologyVersion::new(
        parsed("topology-1"),
        venue,
        EffectiveWindow::new(T0 - 30 * DAY_US, Some(T0 + 365 * DAY_US)).expect("window"),
        zones,
        gates,
        readers,
        Vec::new(),
    )
    .expect("topology")
}

fn space() -> SpaceModel {
    let mut model = SpaceModel::new();
    model
        .add_ticket_type(TicketType {
            id: ticket_type_id(),
            name: "General".to_string(),
            class: TicketClass::General,
            section_id: None,
            standing_area_id: None,
        })
        .expect("ticket type");
    model
}

fn policies() -> AccessPolicyRegistry {
    let mut registry = AccessPolicyRegistry::new();
    registry
        .add_policy(AccessPolicy {
            id: AccessPolicyId::new("policy-general-n1").expect("policy id"),
            name: "General entry".to_string(),
            selector: TicketSelector::TicketType(ticket_type_id()),
            gate_id: gate_id(),
            zone_id: zone_id(),
            time_window: TimeWindow::new(T0, T0 + 365 * DAY_US).expect("window"),
            enabled: true,
        })
        .expect("policy");
    registry
}

/// A compact report of the last bench state, used by evidence details.
pub fn bench_summary(bench: &HilBench) -> BTreeMap<String, String> {
    let mut summary = BTreeMap::new();
    summary.insert(
        "fail_mode".to_string(),
        bench.fail_mode().as_str().to_string(),
    );
    summary.insert(
        "safe_state".to_string(),
        bench.safe_state().as_str().to_string(),
    );
    summary.insert(
        "position".to_string(),
        bench.position().as_str().to_string(),
    );
    summary.insert(
        "turnstile".to_string(),
        bench.turnstile.position().as_str().to_string(),
    );
    summary.insert(
        "supply_mv".to_string(),
        bench.power.voltage_mv().to_string(),
    );
    summary.insert("reader_reads".to_string(), bench.reader.reads().to_string());
    summary.insert(
        "wall_jumps".to_string(),
        bench.clock.wall_jumps().to_string(),
    );
    summary
}

/// Expose event names for tests without requiring a serialization wrapper.
pub fn event_code(event: &GateEvent) -> &'static str {
    match event {
        GateEvent::Authorized { .. } => "authorized",
        GateEvent::Denied { .. } => "denied",
        GateEvent::Replay { .. } => "replay",
        GateEvent::UnpermittedPassage => "unpermitted_passage",
        GateEvent::PassageDetected { .. } => "passage_detected",
        GateEvent::PermitExpired { .. } => "permit_expired",
        GateEvent::Closing => "closing",
        GateEvent::Locked => "locked",
        GateEvent::Unlocked => "unlocked",
        GateEvent::LockTimeout => "lock_timeout",
        GateEvent::PositionFault { .. } => "position_fault",
        GateEvent::TamperDetected => "tamper_detected",
        GateEvent::TamperCleared => "tamper_cleared",
        GateEvent::FireAlarmEngaged => "fire_alarm_engaged",
        GateEvent::FireAlarmCleared => "fire_alarm_cleared",
        GateEvent::PowerLost { .. } => "power_lost",
        GateEvent::PowerRestored => "power_restored",
        GateEvent::ManualCommand { .. } => "manual_command",
        GateEvent::DriveCommanded { .. } => "drive_commanded",
    }
}
