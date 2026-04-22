//! In-toto layout subsystem — feature 006 US4.
//!
//! A layout is a signed policy document declaring which functionaries
//! (identified by PEM keyid) are authorized to perform which build
//! steps. Verification consumes a layout + a statement/envelope and
//! reports whether every declared constraint is satisfied.
//!
//! v1 scope per spec's Out of Scope: single-step layouts only. Multi-
//! step / inspection chains are deferred.

pub mod apply;
pub mod layout;
