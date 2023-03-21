use core::{future::Future, pin::Pin};

use alloc::boxed::Box;

pub type BoxFuture<'f, O> = Pin<Box<dyn Future<Output = O> + Send + 'f>>;
