pub mod signal {
    pub mod session {
        include!(concat!(env!("OUT_DIR"), "/signal.session.rs"));
    }
    pub mod wire {
        include!(concat!(env!("OUT_DIR"), "/signal.wire.rs"));
    }
    pub mod group_wire {
        include!(concat!(env!("OUT_DIR"), "/signal.group_proto.rs"));
    }
}