// Brute-force protection for the 4-digit login PIN (only 10,000 combinations).
//
// - Per device (an IPv4 address, or an IPv6 /64 so rotating privacy addresses
//   doesn't help): 5 wrong PINs → that device waits 5 min, doubling on every
//   further lock (10, 20 … up to 24 h).
// - Everyone: 20 wrong PINs in total since the last successful login → nobody can
//   log in for 15 min (doubling likewise). This caps an attacker who keeps changing
//   IPs. Sessions that are already logged in keep working.
//
// While locked, even the correct PIN is refused — otherwise the lock would not slow
// guessing down. A successful login, a new PIN or "Mở khóa" in the app resets it.

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const DEVICE_MAX_FAILS: u32 = 5;
pub const GLOBAL_MAX_FAILS: u32 = 20;
const DEVICE_LOCK: Duration = Duration::from_secs(5 * 60);
const GLOBAL_LOCK: Duration = Duration::from_secs(15 * 60);
const MAX_LOCK: Duration = Duration::from_secs(24 * 3600);
/// Forget idle devices once the table gets this big.
const MAX_TRACKED: usize = 1000;

#[derive(Default)]
struct Counter {
    fails: u32,
    /// Locks so far — each one lasts twice as long as the previous.
    locks: u32,
    until: Option<Instant>,
}

impl Counter {
    fn remaining(&self, now: Instant) -> Option<Duration> {
        self.until
            .map(|u| u.saturating_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    /// Count a failure; returns the lock length if this one triggers a lock.
    fn fail(&mut self, max: u32, base: Duration, now: Instant) -> Option<Duration> {
        self.fails += 1;
        if self.fails < max {
            return None;
        }
        let d = base.saturating_mul(1 << self.locks.min(10)).min(MAX_LOCK);
        self.fails = 0;
        self.locks += 1;
        self.until = Some(now + d);
        Some(d)
    }
}

fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

/// Why a login attempt is refused.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Lock {
    pub secs: u64,
    /// true = everyone is locked out, false = only this device.
    pub global: bool,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Wrong PIN, `left` more tries before a lock.
    Retry { left: u32 },
    /// Wrong PIN, and this one triggered a lock.
    Locked(Lock),
}

#[derive(Serialize, Clone)]
pub struct LockedDevice {
    pub device: String,
    pub secs: u64,
}

#[derive(Serialize, Clone, Default)]
pub struct GuardStatus {
    /// Seconds until logins reopen for everyone (None = not locked).
    pub global_secs: Option<u64>,
    pub devices: Vec<LockedDevice>,
    /// Wrong PINs since the last successful login (towards the global limit).
    pub fails: u32,
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, Counter>,
    global: Counter,
}

#[derive(Default)]
pub struct LoginGuard {
    inner: Mutex<Inner>,
}

/// Rate-limit key: the IPv4 address, or the /64 network for IPv6.
pub fn device_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

impl LoginGuard {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// May this client try a PIN right now?
    pub fn check(&self, ip: IpAddr) -> Result<(), Lock> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Lock> {
        let g = self.lock();
        if let Some(d) = g.global.remaining(now) {
            return Err(Lock { secs: ceil_secs(d), global: true });
        }
        if let Some(d) = g.devices.get(&device_key(ip)).and_then(|c| c.remaining(now)) {
            return Err(Lock { secs: ceil_secs(d), global: false });
        }
        Ok(())
    }

    /// Record a wrong PIN from `ip`.
    pub fn failure(&self, ip: IpAddr) -> Outcome {
        self.failure_at(ip, Instant::now())
    }

    fn failure_at(&self, ip: IpAddr, now: Instant) -> Outcome {
        let mut g = self.lock();
        let inner = &mut *g;
        if inner.devices.len() >= MAX_TRACKED {
            inner.devices.retain(|_, c| c.remaining(now).is_some());
        }
        let dev = inner.devices.entry(device_key(ip)).or_default();
        let dev_lock = dev.fail(DEVICE_MAX_FAILS, DEVICE_LOCK, now);
        let dev_left = DEVICE_MAX_FAILS - dev.fails;
        let global_lock = inner.global.fail(GLOBAL_MAX_FAILS, GLOBAL_LOCK, now);
        let global_left = GLOBAL_MAX_FAILS - inner.global.fails;

        if let Some(d) = global_lock {
            Outcome::Locked(Lock { secs: ceil_secs(d), global: true })
        } else if let Some(d) = dev_lock {
            Outcome::Locked(Lock { secs: ceil_secs(d), global: false })
        } else {
            Outcome::Retry { left: dev_left.min(global_left) }
        }
    }

    /// Correct PIN: forget this device's failures and the global count.
    pub fn success(&self, ip: IpAddr) {
        let mut g = self.lock();
        g.devices.remove(&device_key(ip));
        g.global = Counter::default();
    }

    /// Clear every lock and counter (owner's "Mở khóa", or a new PIN).
    pub fn reset(&self) {
        *self.lock() = Inner::default();
    }

    pub fn status(&self) -> GuardStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&self, now: Instant) -> GuardStatus {
        let g = self.lock();
        let mut devices: Vec<LockedDevice> = g
            .devices
            .iter()
            .filter_map(|(k, c)| {
                c.remaining(now).map(|d| LockedDevice {
                    device: k.clone(),
                    secs: ceil_secs(d),
                })
            })
            .collect();
        devices.sort_by(|a, b| a.device.cmp(&b.device));
        GuardStatus {
            global_secs: g.global.remaining(now).map(ceil_secs),
            devices,
            fails: g.global.fails,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn device_locks_after_five_and_doubles() {
        let g = LoginGuard::default();
        let t0 = Instant::now();
        let a = ip("192.168.1.5");
        for left in (1..DEVICE_MAX_FAILS).rev() {
            assert_eq!(g.failure_at(a, t0), Outcome::Retry { left });
        }
        assert_eq!(
            g.failure_at(a, t0),
            Outcome::Locked(Lock { secs: 300, global: false })
        );
        assert_eq!(g.check_at(a, t0), Err(Lock { secs: 300, global: false }));
        // Other devices are unaffected.
        assert!(g.check_at(ip("192.168.1.6"), t0).is_ok());
        assert_eq!(g.status_at(t0).devices[0].device, "192.168.1.5");

        // Lock expires, and the next one lasts twice as long.
        let t1 = t0 + Duration::from_secs(301);
        assert!(g.check_at(a, t1).is_ok());
        for _ in 1..DEVICE_MAX_FAILS {
            g.failure_at(a, t1);
        }
        assert_eq!(
            g.failure_at(a, t1),
            Outcome::Locked(Lock { secs: 600, global: false })
        );
    }

    #[test]
    fn ipv6_is_grouped_by_64_and_mapped_v4_matches_v4() {
        assert_eq!(device_key(ip("2001:db8:1:2::a")), device_key(ip("2001:db8:1:2:ffff::9")));
        assert_ne!(device_key(ip("2001:db8:1:2::a")), device_key(ip("2001:db8:1:3::a")));
        assert_eq!(device_key(ip("::ffff:10.0.0.7")), "10.0.0.7");

        let g = LoginGuard::default();
        let t0 = Instant::now();
        for i in 0..DEVICE_MAX_FAILS {
            g.failure_at(ip(&format!("2001:db8:1:2::{:x}", i + 1)), t0);
        }
        assert!(g.check_at(ip("2001:db8:1:2::abcd"), t0).is_err());
        assert!(g.check_at(ip("2001:db8:9:9::1"), t0).is_ok());
    }

    #[test]
    fn global_limit_catches_ip_hopping() {
        let g = LoginGuard::default();
        let t0 = Instant::now();
        for i in 1..GLOBAL_MAX_FAILS {
            let out = g.failure_at(ip(&format!("10.0.0.{}", i)), t0);
            assert_eq!(out, Outcome::Retry { left: (DEVICE_MAX_FAILS - 1).min(GLOBAL_MAX_FAILS - i) });
        }
        assert_eq!(
            g.failure_at(ip("10.0.0.200"), t0),
            Outcome::Locked(Lock { secs: 900, global: true })
        );
        // Nobody — not even a fresh device — may try now.
        assert_eq!(g.check_at(ip("10.0.0.250"), t0), Err(Lock { secs: 900, global: true }));
        assert_eq!(g.status_at(t0).global_secs, Some(900));
        g.reset();
        assert!(g.check_at(ip("10.0.0.250"), t0).is_ok());
        assert_eq!(g.status_at(t0).fails, 0);
    }

    #[test]
    fn success_clears_counts() {
        let g = LoginGuard::default();
        let a = ip("192.168.1.5");
        for _ in 1..DEVICE_MAX_FAILS {
            g.failure(a);
        }
        assert_eq!(g.status().fails, DEVICE_MAX_FAILS - 1);
        g.success(a);
        assert_eq!(g.status().fails, 0);
        assert_eq!(g.failure(a), Outcome::Retry { left: DEVICE_MAX_FAILS - 1 });
    }
}
