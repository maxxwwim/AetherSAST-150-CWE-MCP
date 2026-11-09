pub struct HybridService {
    pub port: u16,
}

impl HybridService {
    pub fn start(port: u16) -> Self {
        Self { port }
    }
}
