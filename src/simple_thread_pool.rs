use std::thread::{JoinHandle, spawn, sleep};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use rust_util::XResult;

pub struct SimpleThreadPool {
    max_pool_size: u32,
    running_pool_size: Arc<AtomicU32>,
}

impl SimpleThreadPool {
    pub fn new(max_pool_size: u32) -> XResult<Self> {
        if max_pool_size > 20 {
            return simple_error!("Illegal pool size: {}", max_pool_size);
        }
        Ok(Self {
            max_pool_size,
            running_pool_size: Arc::new(AtomicU32::new(0)),
        })
    }

    pub fn submit<F>(&mut self, f: F) -> Option<JoinHandle<()>> where
        F: FnOnce() -> (),
        F: Send + 'static,
    {
        let running = self.running_pool_size.fetch_add(1, Ordering::SeqCst);
        let running_pool_size_clone = self.running_pool_size.clone();
        if running < self.max_pool_size {
            Some(spawn(move || {
                f();
                running_pool_size_clone.fetch_sub(1, Ordering::SeqCst);
            }))
        } else {
            f();
            self.running_pool_size.fetch_sub(1, Ordering::SeqCst);
            None
        }
    }
}

#[test]
fn test_simple_thread_pool() {
    let mut stp = SimpleThreadPool::new(2).unwrap();
    let mut handlers = vec![];
    for i in 1..10 {
        if let Some(h) = stp.submit(move || {
            println!("Task start: {}", i);
            sleep(Duration::from_secs(1));
            println!("Task end: {}", i);
        }) {
            handlers.push(h);
        }
    }

    for h in handlers {
        h.join().unwrap();
    }
}