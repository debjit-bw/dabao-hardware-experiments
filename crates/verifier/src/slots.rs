//! Adapted from btchip/ethereum-app dabao-app-eth-burner (MIT OR Apache-2.0), with changes:
//! the storage calls.
//!
//! 32-byte app slots for the verifier's persistent state, served by the signer
//! (`sim_types::ipc::SLOTS_SERVER_NAME`). The signer runs as PID 3 in place of the keystore
//! and is the only process that maps the RRAM slots; on the emulator it keeps them in host
//! files. Every call carries the per-boot token the signer handed over in `OP_SIGNER_WAIT`.
//! The signer serves only `ipc::VERIFIER_SLOTS` (policy counters 176..208, light client
//! 208..210), and only to the first process that presented the token.

use sim_types::ipc;

pub type Token = [u8; ipc::SLOT_TOKEN_LEN];

pub struct Slots {
    cid: Option<xous::CID>,
    token: Token,
    base: usize,
    len: usize,
    /// The signer's slot server is reachable / storage is usable.
    pub ok: bool,
}

impl Slots {
    /// `token`: None if no signer attached in time; every call then fails (fail closed).
    pub fn open(range: core::ops::Range<usize>, what: &str, token: Option<Token>) -> Slots {
        let (base, len) = (range.start, range.len());
        let Some(token) = token else {
            log::error!("app slots {base}..{} ({what}): no signer attached", range.end);
            return Slots { cid: None, token: [0; ipc::SLOT_TOKEN_LEN], base, len, ok: false };
        };
        let xns = xous_names::XousNames::new().unwrap();
        let cid = xns.request_connection_blocking(ipc::SLOTS_SERVER_NAME).ok();
        log::info!("app slots {base}..{} ({what}) via the signer: {}", range.end, if cid.is_some() { "connected" } else { "unreachable" });
        Slots { cid, token, base, len, ok: cid.is_some() }
    }

    fn call(&self, op: usize, i: usize, data: Option<&[u8; 32]>) -> Option<Vec<u8>> {
        let cid = self.cid?;
        let mut req = self.token.to_vec();
        req.extend_from_slice(&((self.base + i) as u32).to_be_bytes());
        if let Some(d) = data {
            req.extend_from_slice(d);
        }
        let mut range = xous::map_memory(None, None, 4096, xous::MemoryFlags::R | xous::MemoryFlags::W).ok()?;
        unsafe { range.as_slice_mut::<u8>()[..req.len()].copy_from_slice(&req) };
        let r = xous::send_message(cid, xous::Message::new_lend_mut(op, range, None, xous::MemorySize::new(req.len())));
        let out = match r {
            Ok(xous::Result::MemoryReturned(_, Some(v))) => Some(unsafe { range.as_slice::<u8>()[..v.get().min(4096)].to_vec() }),
            _ => None,
        };
        // the token was in this page: clear it before handing the page back
        unsafe { range.as_slice_mut::<u8>()[..ipc::SLOT_TOKEN_LEN].fill(0) };
        xous::unmap_memory(range).ok();
        out
    }

    pub fn read(&mut self, i: usize) -> Option<[u8; 32]> {
        if i >= self.len {
            return None;
        }
        match self.call(ipc::OP_SLOT_READ, i, None) {
            Some(d) if d.len() == 32 => d.try_into().ok(),
            _ => {
                log::error!("app slot {}: read refused or failed", self.base + i);
                None
            }
        }
    }

    pub fn write(&mut self, i: usize, data: &[u8; 32]) -> bool {
        i < self.len && matches!(self.call(ipc::OP_SLOT_WRITE, i, Some(data)).as_deref(), Some([1]))
    }
}
