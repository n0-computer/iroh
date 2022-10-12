#[allow(unused_imports)]
use std::any::Any;

#[macro_export]
macro_rules! record {
    ( $e:expr, $v:expr) => {
        $e.record($v);
    };
}

#[macro_export]
macro_rules! inc {
    ( $e:expr) => {
        $e.record(1);
    };
}

#[macro_export]
macro_rules! observe {
    ( $e:expr, $v:expr) => {
        $e.observe($v);
    };
}

#[macro_export]
macro_rules! make_metrics {
    ($module_name:ident, $($name:ident: $type:ident: $description:expr),+) => {
        paste::paste! {
            #[derive(Default, Clone)]
            pub(crate) struct Metrics {
                $(
                    [<$name:snake>]: $type,
                )+
            }
        }

        impl fmt::Debug for Metrics {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("Store Metrics").finish()
            }
        }

        paste::paste! {
            $(
                pub const [<METRICS_CNT_ $name:snake:upper>]: &str = stringify!([<$name:snake>]);
            )+

            impl Metrics {
                pub(crate) fn new(registry: &mut Registry) -> Self {
                    let sub_registry = registry.sub_registry_with_prefix(stringify!([<$module_name:snake>]));

                    $(
                        let [<$name:snake>] = <$type>::default();
                        sub_registry.register(
                            stringify!([<$name:snake>]),
                            $description,
                            Box::new([<$name:snake>].clone())
                        );
                    )+

                    Self {
                        $(
                            [<$name:snake>],
                        )+
                    }
                }
            }

            impl MetricsRecorder for Metrics {
                fn record<M>(&self, m: M, value: u64)
                where
                    M: MetricType + std::fmt::Display,
                {
                    match m.name() {
                        $(
                            x if x ==  [<$module_name Metrics>]::$name.name() => {
                                self.[<$name:snake>].inc_by(value);
                            }
                        )+
                        name => {
                            error!("record ([<$module_name:snake>]): unknown metric {}", name);
                        }
                    }

                }

                fn observe<M>(&self, m: M, _value: f64)
                where
                    M: HistogramType + std::fmt::Display,
                {
                    error!("observe ([<$module_name:snake>]): unknown metric {}", m.name());
                }
            }

            impl MetricType for [<$module_name Metrics>] {
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

            impl MRecorder for  [<$module_name Metrics>] {
                fn record(&self, value: u64) {
                    crate::record(Collector::$module_name, self.clone(), value);
                }
            }

            impl std::fmt::Display for  [<$module_name Metrics>] {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{}", self.name())
                }
            }

            #[derive(Debug, Copy, Clone)]
            pub enum [<$module_name Metrics>] {
                $(
                    $name,
                )+
            }
        }
    }
}
