/// Generate recorder metrics for a module.
#[macro_export]
macro_rules! make_metric_recorders {
    ($module_name:expr, $($name:ident: $type:ident: $description:expr $(,)?)+) => {
        paste::paste! {
            #[cfg(feature = "metrics")]
            #[allow(unused_imports)]
            use prometheus_client::metrics::counter::*;

            /// Define the metrics for the module
            #[cfg(feature = "metrics")]
            #[derive(Default, Debug, Clone)]
                pub struct Metrics {
                    $(
                        /// macro generated metric
                        pub [<$name:snake>]: $type,
                    )+
                }

            #[cfg(not(feature = "metrics"))]
            #[derive(Default, Clone, Debug)]
            #[allow(dead_code)]
            pub(crate) struct Metrics {
                $(
                    [<$name:snake>]: (),
                )+
            }
        }

        paste::paste! {
            $(
                /// Define a metric for the module
                pub const [<METRICS_CNT_ $name:snake:upper>]: &str = stringify!([<$name:snake>]);
            )+

            #[cfg(feature = "metrics")]
            impl Metrics {
                /// Create a new metrics object with the given registry
                pub fn new(registry: &mut prometheus_client::registry::Registry) -> Self {
                    let sub_registry = registry.sub_registry_with_prefix(stringify!([<$module_name:snake>]));

                    $(
                        let [<$name:snake>] = <$type>::default();
                        sub_registry.register(
                            stringify!([<$name:snake>]),
                            $description,
                            [<$name:snake>].clone()
                        );
                    )+

                    Self {
                        $(
                            [<$name:snake>],
                        )+
                    }
                }
           }

            #[cfg(feature = "metrics")]
            impl $crate::core::MetricsRecorder for Metrics {
                fn record(&self, m: &str, value: u64)
                {
                    use $crate::core::MetricType;
                    match m {
                        $(
                            x if x ==  [<$module_name Metrics>]::$name.name() => {
                                // TODO(arqu): this always assumes only counters
                                self.[<$name:snake>].inc_by(value);
                            }
                        )+
                        name => {
                            tracing::error!("record ([<$module_name:snake>]): unknown metric {}", name);
                        }
                    }

                }

                fn observe(&self, m: &str, _value: f64)
                {
                    tracing::error!("observe ([<$module_name:snake>]): unknown metric {}", m);
                }
            }

            #[cfg(feature = "metrics")]
            impl $crate::core::Metric for Metrics {
                fn as_any(&self) -> &dyn std::any::Any {
                    self
                }
            }

            #[cfg(feature = "metrics")]
            impl $crate::core::MetricType for [<$module_name Metrics>] {
                fn name(&self) -> &'static str {
                    match self {
                        $(
                            [<$module_name Metrics>]::$name => {
                                [<METRICS_CNT_ $name:snake:upper>]
                            }
                        )+
                    }
                }
            }

            #[cfg(feature = "metrics")]
            impl $crate::core::MRecorder for  [<$module_name Metrics>] {
                fn record(&self, value: u64) {
                    $crate::core::record(
                        $module_name,
                        self.clone(),
                        value
                    );
                }
            }


            #[cfg(feature = "metrics")]
            impl std::fmt::Display for  [<$module_name Metrics>] {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    use $crate::core::MetricType;

                    write!(f, "{}", self.name())
                }
            }

            /// Enum of metrics for the module
            #[derive(Debug, Copy, Clone)]
            pub enum [<$module_name Metrics>] {
                $(
                    #[doc = $description]
                    $name,
                )+
            }
        }
    }
}
pub use make_metric_recorders;
