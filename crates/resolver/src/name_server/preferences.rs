// Copyright 2015-2025 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::net::IpAddr;

use hickory_proto::xfer::Protocol;

use crate::config::{ConnectionConfig, NameServerTransportState, OpportunisticEncryption};
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
    /// This choice is made based on encryption status, protocol preference, and the SRTT
    /// performance metrics.
    pub(crate) fn select_connection<'a, P: ConnectionProvider>(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        connections: &'a [ConnectionState<P>],
    ) -> Option<&'a ConnectionState<P>> {
        let selected = connections
            .iter()
            .filter(|conn| self.allows_protocol(conn.protocol))
            .min_by(|a, b| self.compare_connections(opportunistic_encryption.is_enabled(), a, b));

        let selected = selected?;

        // If we're using opportunistic encryption and selected a pre-existing unencrypted connection
        // and have successfully probed on any supported encrypted protocol we should _not_ reuse the
        // existing connection and instead return None. This will result in a new encrypted connection
        // being made to the successfully probed protocol and added to the connection list for future
        // re-use.
        if opportunistic_encryption.is_enabled()
            && !selected.protocol.is_encrypted()
            && encrypted_transport_state.any_recent_success(ip, opportunistic_encryption)
        {
            return None;
        }

        Some(selected)
    }

    pub(crate) fn select_connection_config<'a>(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        connection_configs: &'a [ConnectionConfig],
    ) -> Option<&'a ConnectionConfig> {
        connection_configs
            .iter()
            .filter(|c| self.allows_protocol(c.protocol.to_protocol()))
            .min_by(|a, b| {
                self.compare_connection_configs(
                    ip,
                    encrypted_transport_state,
                    opportunistic_encryption,
                    a,
                    b,
                )
            })
    }

    /// Compare two connections according to preferences and performance.
    /// If opportunistic encryption is enabled we make an effort to select an encrypted connection.
    fn compare_connections<P: ConnectionProvider>(
        &self,
        opportunistic_encryption: bool,
        a: &ConnectionState<P>,
        b: &ConnectionState<P>,
    ) -> Ordering {
        // When opportunistic encryption is in-play, we want to consider encrypted
        // connections with the greatest priority.
        if opportunistic_encryption {
            match (a.protocol.is_encrypted(), b.protocol.is_encrypted()) {
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                // When _both_ are encrypted, then decide on ordering based on other properties (like SRTT).
                _ => {}
            }
        }

        match (a.protocol, b.protocol) {
            (ap, bp) if ap == bp => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
            (Protocol::Udp, _) => Ordering::Less,
            (_, Protocol::Udp) => Ordering::Greater,
            _ => a.meta.srtt.current().total_cmp(&b.meta.srtt.current()),
        }
    }

    /// Compare two connection configs according to protocol preferences and recent success.
    fn compare_connection_configs(
        &self,
        ip: IpAddr,
        encrypted_transport_state: &NameServerTransportState,
        opportunistic_encryption: &OpportunisticEncryption,
        a: &ConnectionConfig,
        b: &ConnectionConfig,
    ) -> Ordering {
        let a_protocol = a.protocol.to_protocol();
        let b_protocol = b.protocol.to_protocol();

        // When opportunistic encryption is in-play, prioritize encrypted protocols
        // that have recent successful connections
        if opportunistic_encryption.is_enabled() {
            let a_recent_enc_success = a_protocol.is_encrypted()
                && encrypted_transport_state.recent_success(
                    ip,
                    a_protocol,
                    opportunistic_encryption,
                );
            let b_recent_enc_success = b_protocol.is_encrypted()
                && encrypted_transport_state.recent_success(
                    ip,
                    b_protocol,
                    opportunistic_encryption,
                );

            match (a_recent_enc_success, b_recent_enc_success) {
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                // When both have recent success or neither do, continue with normal ordering
                _ => {}
            }
        }

        // Default protocol ordering: UDP first, then others
        match (a_protocol, b_protocol) {
            (ap, bp) if ap == bp => Ordering::Equal,
            (Protocol::Udp, _) => Ordering::Less,
            (_, Protocol::Udp) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }

    /// Checks if the given protocol is allowed by current preferences.
    fn allows_protocol(&self, protocol: Protocol) -> bool {
        !(self.exclude_udp && protocol == Protocol::Udp)
    }
}
