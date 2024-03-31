use core::{future::Future, pin::Pin};

pub type BoxFuture<'f, O> = Pin<Box<dyn Future<Output = O> + Send + 'f>>;
