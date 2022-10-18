pub fn ewma(old: f64, new: f64, alpha: f64) -> f64 {
    new * alpha + (1. - alpha) * old
}
