pub struct DerpMap {
    pub regions: Vec<DerpRegion>,
}

pub struct DerpRegion {
    pub nodes: Vec<DerpNode>,
}

pub struct DerpNode {
    pub name: String,
    pub stun_only: bool,
}
