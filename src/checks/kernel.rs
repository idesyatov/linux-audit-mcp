//! Kernel-domain checks (`sysctl -a`).
//!
//! Each check reads one hardening-relevant sysctl. A key that isn't reported is
//! treated as a failure - the auditor can't confirm the safe value.

use std::collections::HashMap;

use super::parse::parse_sysctl;
use super::{Check, Domain, Outcome, Severity};

const SYSCTL_CMD: &str = "sysctl -a";

/// Pass iff `key` reports one of `want`; fail (with a clear reason) otherwise.
fn expect(output: &str, key: &str, want: &[&str], secure_desc: &str) -> Outcome {
    match parse_sysctl(output).get(key) {
        Some(v) if want.contains(&v.as_str()) => Outcome::pass(format!("{key} = {v}.")),
        Some(v) => Outcome::fail(format!("{key} = {v} ({secure_desc}).")),
        None => Outcome::fail(format!("{key} is not reported ({secure_desc}).")),
    }
}

macro_rules! sysctl_check {
    ($name:ident, $id:literal, $title:literal, $sev:expr, $rec:literal, $key:literal, $want:expr, $desc:literal) => {
        pub struct $name;
        impl Check for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn domain(&self) -> Domain {
                Domain::Kernel
            }
            fn title(&self) -> &'static str {
                $title
            }
            fn severity(&self) -> Severity {
                $sev
            }
            fn recommendation(&self) -> &'static str {
                $rec
            }
            fn command(&self) -> &'static str {
                SYSCTL_CMD
            }
            fn evaluate(&self, output: &str) -> Outcome {
                expect(output, $key, $want, $desc)
            }
        }
    };
}

sysctl_check!(
    Aslr,
    "kernel-aslr",
    "Address-space layout randomization",
    Severity::Medium,
    "Enable full ASLR: sysctl -w kernel.randomize_va_space=2 (and persist it).",
    "kernel.randomize_va_space",
    &["2"],
    "full ASLR requires 2"
);

sysctl_check!(
    TcpSyncookies,
    "kernel-tcp-syncookies",
    "TCP SYN cookies",
    Severity::Low,
    "Enable SYN cookies: net.ipv4.tcp_syncookies=1.",
    "net.ipv4.tcp_syncookies",
    &["1"],
    "SYN-flood protection requires 1"
);

sysctl_check!(
    RpFilter,
    "kernel-rp-filter",
    "Reverse-path filtering",
    Severity::Low,
    "Enable reverse-path filtering: net.ipv4.conf.all.rp_filter=1.",
    "net.ipv4.conf.all.rp_filter",
    &["1", "2"],
    "anti-spoofing requires 1 or 2"
);

/// `true` if the sysctl output shows a Docker/container bridge (`docker0` or a
/// user-defined `br-*` network), which appears as `net.*.conf.<iface>.*` keys.
/// Such a host forwards packets by design, so `ip_forward=1` is expected there.
fn is_container_host(sysctl: &HashMap<String, String>) -> bool {
    sysctl
        .keys()
        .any(|k| k.contains(".conf.docker0.") || k.contains(".conf.br-"))
}

/// IP forwarding on a non-router is a finding - except on a **container host**,
/// where Docker's bridge networking requires it. Docker is detected from the
/// same `sysctl -a` output (a `docker0`/`br-*` bridge), so no extra command is
/// needed; on such a host `ip_forward=1` passes with a note instead of failing.
pub struct IpForward;

impl Check for IpForward {
    fn id(&self) -> &'static str {
        "kernel-ip-forward"
    }
    fn domain(&self) -> Domain {
        Domain::Kernel
    }
    fn title(&self) -> &'static str {
        "IP forwarding enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Disable routing unless this host is a router or runs containers: net.ipv4.ip_forward=0."
    }
    fn command(&self) -> &'static str {
        SYSCTL_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        const KEY: &str = "net.ipv4.ip_forward";
        let sysctl = parse_sysctl(output);
        match sysctl.get(KEY) {
            Some(v) if v == "0" => Outcome::pass(format!("{KEY} = 0.")),
            Some(v) if is_container_host(&sysctl) => Outcome::pass(format!(
                "{KEY} = {v} (expected: a Docker/container bridge is present)."
            )),
            Some(v) => Outcome::fail(format!(
                "{KEY} = {v} (a non-router should not forward packets)."
            )),
            None => Outcome::fail(format!(
                "{KEY} is not reported (a non-router should not forward packets)."
            )),
        }
    }
}

sysctl_check!(
    AcceptRedirects,
    "kernel-accept-redirects",
    "ICMP redirects accepted",
    Severity::Low,
    "Ignore ICMP redirects: net.ipv4.conf.all.accept_redirects=0.",
    "net.ipv4.conf.all.accept_redirects",
    &["0"],
    "accepting redirects allows route hijacking"
);

sysctl_check!(
    AcceptSourceRoute,
    "kernel-source-route",
    "Source-routed packets accepted",
    Severity::Low,
    "Reject source routing: net.ipv4.conf.all.accept_source_route=0.",
    "net.ipv4.conf.all.accept_source_route",
    &["0"],
    "source routing can bypass filtering"
);

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn aslr() {
        assert_eq!(
            Aslr.evaluate("kernel.randomize_va_space = 2\n").status,
            Status::Pass
        );
        assert_eq!(
            Aslr.evaluate("kernel.randomize_va_space = 0\n").status,
            Status::Fail
        );
        // Not reported -> fail.
        assert_eq!(Aslr.evaluate("").status, Status::Fail);
    }

    #[test]
    fn ip_forward_and_redirects() {
        assert_eq!(
            IpForward.evaluate("net.ipv4.ip_forward = 0\n").status,
            Status::Pass
        );
        // ip_forward=1 on a plain host (no container bridge) -> fail.
        assert_eq!(
            IpForward.evaluate("net.ipv4.ip_forward = 1\n").status,
            Status::Fail
        );
        assert_eq!(
            AcceptRedirects
                .evaluate("net.ipv4.conf.all.accept_redirects = 0\n")
                .status,
            Status::Pass
        );
    }

    #[test]
    fn ip_forward_is_expected_on_a_docker_host() {
        // docker0 bridge present -> forwarding is by design -> pass.
        let docker = "net.ipv4.ip_forward = 1\n\
                      net.ipv4.conf.docker0.forwarding = 1\n";
        assert_eq!(IpForward.evaluate(docker).status, Status::Pass);
        // A user-defined docker network (br-*) counts too.
        let br = "net.ipv4.ip_forward = 1\n\
                  net.ipv4.conf.br-c2516d0a6cb9.forwarding = 1\n";
        assert_eq!(IpForward.evaluate(br).status, Status::Pass);
        // But an unrelated bridge name does not excuse forwarding.
        let other = "net.ipv4.ip_forward = 1\n\
                     net.ipv4.conf.eth0.forwarding = 1\n";
        assert_eq!(IpForward.evaluate(other).status, Status::Fail);
    }

    #[test]
    fn rp_filter_accepts_1_or_2() {
        assert_eq!(
            RpFilter
                .evaluate("net.ipv4.conf.all.rp_filter = 2\n")
                .status,
            Status::Pass
        );
        assert_eq!(
            RpFilter
                .evaluate("net.ipv4.conf.all.rp_filter = 0\n")
                .status,
            Status::Fail
        );
    }
}
