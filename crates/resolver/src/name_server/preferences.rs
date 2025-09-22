// Copyright 2015-2025 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hickory_proto::xfer::Protocol;

use crate::name_server::connection_provider::ConnectionProvider;
use crate::name_server::name_server::NameServer;

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

    /// Return whether UDP is excluded.
    pub(crate) fn udp_excluded(&self) -> bool {
        self.exclude_udp
    }
}
