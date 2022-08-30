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
