use std::sync::{Condvar, Mutex};

/// A turn-based synchronization primitive.
pub struct TurnBasedSync {
    pub current_turn: Mutex<usize>,
    pub cv: Condvar,
}

impl TurnBasedSync {
    /// Creates a new [TurnBasedSync].
    pub fn new() -> Self {
        TurnBasedSync {
            current_turn: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    /// Waits for the current turn to be equal to the given turn.
    pub fn wait_for_turn(&self, my_turn: usize) {
        let mut turn = self.current_turn.lock().unwrap();
        while *turn != my_turn {
            turn = self.cv.wait(turn).unwrap();
        }
    }

    /// Advances the current turn.
    pub fn advance_turn(&self) {
        let mut turn = self.current_turn.lock().unwrap();
        *turn += 1;
        self.cv.notify_all();
    }
}
