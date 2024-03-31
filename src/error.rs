use std::error;

pub type Error = Box<dyn error::Error + Send + Sync + 'static>;
