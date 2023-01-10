#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    Piece { index: usize, total: usize },
}
