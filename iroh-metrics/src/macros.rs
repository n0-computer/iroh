/// Records a new value for a counter or gauge.
///
/// Recording is for single-value metrics, each recorded metric represents a metric value.
#[macro_export]
macro_rules! record {
    ( $e:expr, $v:expr) => {{
        #[cfg(feature = "metrics")]
        {
            use $crate::core::MRecorder;
            $e.record($v);
        }
        #[cfg(not(feature = "metrics"))]
        #[allow(path_statements)]
        {
            $e;
        }
    }};
}
pub use record;

/// Increments a counter metric by 1.
///
/// Technically you can call this on any single-value metric, but the semantics are for
/// counters.
#[macro_export]
macro_rules! inc {
    ( $e:expr) => {{
        {
            #[cfg(feature = "metrics")]
            {
                use $crate::core::MRecorder;
                $e.record(1);
            }
            #[cfg(not(feature = "metrics"))]
            #[allow(path_statements)]
            {
                $e;
            }
        }
    }};
}
pub use inc;

/// Observes a value into a histogram or summary metric.
///
/// Observing is for distribution metrics, when multiple observations are combined in a
/// single metric value.
#[macro_export]
macro_rules! observe {
    ( $e:expr, $v:expr) => {{
        #[cfg(feature = "metrics")]
        {
            use $crate::metrics::core::MObserver;
            $e.observe($v);
        }
        #[cfg(not(feature = "metrics"))]
        #[allow(path_statements)]
        {
            $e;
        }
    }};
}
pub use observe;

/// Generate recorder metrics for a module.
#[macro_export]
macro_rules! make_metric_recorders {
    ($module_name:ident, $($name:ident: $type:ident: $description:expr $(,)?)+) => {
        paste::paste! {
            #[cfg(feature = "metrics")]
            #[allow(unused_imports)]
            use prometheus_client::metrics::counter::*;

            #[cfg(feature = "metrics")]
            #[derive(Default, Clone, Debug)]
                pub struct Metrics {
                    $(
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
                pub(crate) fn new(registry: &mut prometheus_client::registry::Registry) -> Self {
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
                fn record<M>(&self, m: M, value: u64)
                where
                    M: $crate::core::MetricType + std::fmt::Display,
                {
                    use $crate::core::MetricType;
                    match m.name() {
                        $(
                            x if x ==  [<$module_name Metrics>]::$name.name() => {
                                self.[<$name:snake>].inc_by(value);
                            }
                        )+
                        name => {
                            tracing::error!("record ([<$module_name:snake>]): unknown metric {}", name);
                        }
                    }

                }

                fn observe<M>(&self, m: M, _value: f64)
                where
                    M: $crate::core::HistogramType + std::fmt::Display,
                {
                    tracing::error!("observe ([<$module_name:snake>]): unknown metric {}", m.name());
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
                        $crate::core::Collector::$module_name,
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
