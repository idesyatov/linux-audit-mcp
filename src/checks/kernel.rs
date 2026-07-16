//! Kernel-domain checks (`sysctl -a`).
//!
//! Each check reads one hardening-relevant sysctl. A key that isn't reported is
//! treated as a failure — the auditor can't confirm the safe value.

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

sysctl_check!(
    IpForward,
    "kernel-ip-forward",
    "IP forwarding enabled",
    Severity::Medium,
    "Disable routing unless this host is a router: net.ipv4.ip_forward=0.",
    "net.ipv4.ip_forward",
    &["0"],
    "a non-router should not forward packets"
);

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
        // Not reported → fail.
        assert_eq!(Aslr.evaluate("").status, Status::Fail);
    }

    #[test]
    fn ip_forward_and_redirects() {
        assert_eq!(
            IpForward.evaluate("net.ipv4.ip_forward = 0\n").status,
            Status::Pass
        );
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
