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
    ($module_name:expr, $($name:ident: $type:ident: $description:expr $(,)?)+) => {
        paste::paste! {
            #[cfg(feature = "metrics")]
            #[allow(unused_imports)]
            use prometheus_client::metrics::counter::*;

            #[cfg(feature = "metrics")]
            #[derive(Default, Debug, Clone)]
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
            use $crate::core::MetricsRecorder;
            $(
                /// Define a metric for the module
                pub const [<METRICS_CNT_ $name:snake:upper>]: &str = stringify!([<$name:snake>]);
            )+

            #[cfg(feature = "metrics")]
            impl Metrics {
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

                pub fn run(self, rx: std::sync::mpsc::Receiver<$crate::core::MMsg>) {
                    tokio::task::spawn_blocking(move || {
                        while true {
                            let msg = rx.recv();
                            match msg {
                                Ok(msg) => {
                                    self.handle_message(msg);
                                }
                                Err(e) => {
                                    tracing::error!("error receiving message: {}", e);
                                }
                            }
                        }
                    });
                }

                pub(crate) fn handle_message(&self, msg: $crate::core::MMsg) where Self: $crate::core::MetricsRecorder{
                    match msg.m_callback {
                        Some(cb) => {
                            // TODO(arqu): this always assumes only counters
                            match msg.m.as_str() {
                                $(
                                    [<METRICS_CNT_ $name:snake:upper>] => {
                                        let x = self.[<$name:snake>].get();
                                        let rm = $crate::core::MMsg {
                                            m: msg.m,
                                            m_type: $crate::core::MMsgType::Record,
                                            m_val_u64: x,
                                            m_val_f64: 0.0,
                                            m_callback: None,
                                        };
                                        tokio::spawn(async move {
                                            match cb.send(rm).await {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    tracing::error!("error sending message: {}", e);
                                                }
                                            };
                                        });
                                    }
                                )+
                                _ => {
                                    tracing::error!("Unknown metric: {}", msg.m);
                                }
                            }
                        }
                        None => {
                            match msg.m_type {
                                $crate::core::MMsgType::Record => {
                                    self.record(&msg.m, msg.m_val_u64);
                                }
                                $crate::core::MMsgType::Observe => {
                                    self.observe(&msg.m, msg.m_val_f64);
                                }
                                $crate::core::MMsgType::Unknown => {
                                    tracing::trace!("Unknown message type: {:?}", msg);
                                }
                            }
                        }
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
