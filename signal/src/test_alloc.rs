use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
  static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn count_allocation() {
  let _ = ALLOCATIONS.try_with(|count| {
    if let Some(n) = count.get() {
      count.set(Some(n + 1));
    }
  });
}

unsafe impl GlobalAlloc for CountingAllocator {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    count_allocation();
    unsafe { System.alloc(layout) }
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    count_allocation();
    unsafe { System.alloc_zeroed(layout) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
    count_allocation();
    unsafe { System.realloc(ptr, layout, size) }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    unsafe { System.dealloc(ptr, layout) }
  }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
  struct Reset;
  impl Drop for Reset {
    fn drop(&mut self) {
      ALLOCATIONS.with(|count| count.set(None));
    }
  }

  ALLOCATIONS.with(|count| assert!(count.replace(Some(0)).is_none()));
  let _reset = Reset;
  let result = f();
  let count = ALLOCATIONS.with(|count| count.get().unwrap());
  (result, count)
}
