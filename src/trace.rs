//! Internal tracing helpers gated by the `tracing` feature.
//!
//! Several iterator and resolver paths in this crate **silently** drop
//! malformed entries (`filter_map(|r| r.ok())`, `.ok()?` chains, etc.)
//! rather than abort whole-structure parses. That fail-soft behavior is
//! correct for adversarial malware analysis — one bad row should not
//! poison the whole table — but it makes diagnosis difficult: you see
//! "23 entries parsed" without knowing whether 5 more were dropped.
//!
//! When the `tracing` feature is enabled, the macros in this module
//! forward to [`tracing::warn!`] / [`tracing::debug!`] so a downstream
//! subscriber can capture exactly which entries were dropped and why.
//! When the feature is disabled, the macros expand to no-ops with no
//! runtime cost.
//!
//! # Why a custom wrapper rather than the `tracing` macros directly
//!
//! `tracing::warn!` requires the `tracing` crate to be in scope at every
//! call site. Wrapping behind these helpers means:
//!
//! 1. The crate compiles without `tracing` as a dependency by default.
//! 2. Each call site is a uniform `crate::trace::warn_drop!(...)` rather
//!    than a `#[cfg(feature = "tracing")] tracing::warn!(...)` block.
//! 3. The drop-reason payload is documented once here, rather than
//!    spread across ~10 macro invocations.

/// Records a "silently dropped a malformed entry" event.
///
/// First argument is a `&'static str` site identifier (`"control_iter"`,
/// `"const_pool_resolve"`, etc.); the optional `error = ?e` payload is
/// the dropped error / value formatted with `Debug`, recorded as a
/// structured field when `tracing` is enabled.
///
/// Expands to a no-op when the `tracing` feature is disabled — but still
/// references the payload so `unused_variables` does not fire on the
/// caller's `e` binding.
#[macro_export]
#[doc(hidden)]
macro_rules! __vb_trace_drop {
    ($site:expr, error = ?$err:expr) => {{
        #[cfg(feature = "tracing")]
        $crate::__tracing::warn!(target: "visualbasic::dropped", site = $site, error = ?$err);
        #[cfg(not(feature = "tracing"))]
        {
            let _ = $site;
            let _ = &$err;
        }
    }};
    ($site:expr) => {{
        #[cfg(feature = "tracing")]
        $crate::__tracing::warn!(target: "visualbasic::dropped", site = $site);
        #[cfg(not(feature = "tracing"))]
        {
            let _ = $site;
        }
    }};
}

pub(crate) use __vb_trace_drop as warn_drop;
