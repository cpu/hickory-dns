// Copyright 2015-2025 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;

use hickory_proto::xfer::Protocol;

use crate::name_server::connection_provider::ConnectionProvider;
use crate::name_server::name_server::{ConnectionState, NameServer};

/// Manages name server connection preferences and exclusions for DNS queries.
///
/// This type encapsulates the logic for determining which connections and connection
/// configurations are acceptable for DNS queries based on initial preferences and
/// runtime conditions like truncated responses or suspected spoofing.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub(crate) struct Preferences {
    exclude_udp: bool,
}

impl Preferences {
    /// Checks if the given protocol is allowed by current preferences.
    pub(crate) fn allows_protocol(&self, protocol: Protocol) -> bool {
        !(self.exclude_udp && protocol == Protocol::Udp)
    }

    /// Checks if the given server has any protocols compatible with current preferences.
    pub(crate) fn allows_server<P: ConnectionProvider>(&self, server: &NameServer<P>) -> bool {
        server.protocols().any(|p| self.allows_protocol(p))
    }

    /// Exclude UDP when considering protocols.
    ///
    /// This is useful for re-trying with TCP after a truncated response, or a response
    /// we believe may have been spoofed (e.g. due to 0x20 query case randomization mismatch).
    pub(crate) fn exclude_udp(&mut self) {
        self.exclude_udp = true;
    }

    /// Select the best pre-existing connection to use.
    ///
    /// This choice is made based on protocol preference, and the SRTT performance metrics.
    pub(crate) fn select_connection<'a, P: ConnectionProvider>(
        &self,
        connections: &'a [ConnectionState<P>],
    ) -> Option<&'a ConnectionState<P>> {
        connections
            .iter()
            .filter(|conn| self.allows_protocol(conn.protocol))
            .min_by(|a, b| self.compare_connections(a, b))
    }

    /// Compare two connections according to preferences and performance.
    fn compare_connections<P: ConnectionProvider>(
        &self,
        a: &ConnectionState<P>,
        b: &ConnectionState<P>,
    ) -> Ordering {
        match (a.protocol, b.protocol) {
            (ap, bp) if ap == bp => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
            (Protocol::Udp, _) => Ordering::Less,
            (_, Protocol::Udp) => Ordering::Greater,
            _ => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
        }
    }
}
