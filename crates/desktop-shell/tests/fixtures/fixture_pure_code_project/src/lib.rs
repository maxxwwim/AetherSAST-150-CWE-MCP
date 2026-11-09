pub struct EngineCore {
    pub active: bool,
}

impl EngineCore {
    pub fn new() -> Self {
        Self { active: true }
    }

    pub fn compute(&self, val: u32) -> u32 {
        val * 2
    }
}
