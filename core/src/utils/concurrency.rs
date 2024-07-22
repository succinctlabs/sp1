use std::sync::{Condvar, Mutex};

/// A turn-based synchronization primitive.
pub struct TurnBasedSync {
    pub current_turn: Mutex<usize>,
    pub cv: Condvar,
}

impl TurnBasedSync {
    pub fn new() -> Self {
        TurnBasedSync {
            current_turn: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    pub fn wait_for_turn(&self, my_turn: usize) {
        let mut turn = self.current_turn.lock().unwrap();
        while *turn != my_turn {
            turn = self.cv.wait(turn).unwrap();
        }
    }

    pub fn advance_turn(&self) {
        let mut turn = self.current_turn.lock().unwrap();
        *turn += 1;
        self.cv.notify_all();
    }
}
