use super::pdu::PduFlags;
use crate::{
    command::Command,
    error::{Error, PduError},
    pdu_loop::{frame_header::FrameHeader, pdu::Pdu},
    ETHERCAT_ETHERTYPE, MASTER_ADDR,
};
use core::{
    future::Future,
    mem,
    pin::Pin,
    sync::atomic::{Ordering, AtomicUsize},
    task::{Context, Poll, Waker},
};
use smoltcp::wire::{EthernetAddress, EthernetFrame};

pub(crate) struct FrameState(pub(crate) AtomicUsize);

impl FrameState {
    /// Owner: PduStorage. Safe to atomically swap to created at any time
    pub(crate) const NONE: usize = 0x00;
    /// Owner: Whoever owns the CreatedFrame. NOT safe to atomically swap.
    pub(crate) const CREATED: usize = 0x01;
    /// Owner: PduStorage. Safe to atomically swap to sending at any time
    pub(crate) const SENDABLE: usize = 0x02;
    /// Owner: Whoever owns the SendableFrame. NOT safe to atomically swap.
    pub(crate) const SENDING: usize = 0x03;
    /// ???
    pub(crate) const WAIT_RX: usize = 0x04;
    /// ???
    pub(crate) const RX_BUSY: usize = 0x04;
    /// >>>
    pub(crate) const RX_DONE: usize = 0x06;
    /// ???
    pub(crate) const RX_PROCESSING: usize = 0x07;
    /// ???
    pub(crate) const DONE: usize = 0x42;

    pub const fn const_default() -> Self {
        Self(AtomicUsize::new(Self::NONE))
    }
}

impl Default for FrameState {
    fn default() -> Self {
        Self(AtomicUsize::new(Self::NONE))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Frame {
    pub(crate) waker: Option<Waker>,
    pub pdu: Pdu,
}

impl Frame {
    pub(crate) const fn new() -> Self {
        Self {
            waker: None,
            pdu: Pdu::new(),
        }
    }

    pub(crate) fn new_with(pdu: Pdu) -> Self {
        Self {
            waker: None,
            pdu,
        }
    }

    pub(crate) fn pdu(&self) -> &Pdu {
        &self.pdu
    }

    /// The size of the total payload to be insterted into an Ethernet frame, i.e. EtherCAT frame
    /// payload and header.
    fn ethernet_payload_len(&self) -> usize {
        usize::from(self.pdu.ethercat_payload_len()) + mem::size_of::<FrameHeader>()
    }

    pub fn to_ethernet_frame<'a>(
        &self,
        buf: &'a mut [u8],
        data: &[u8],
    ) -> Result<&'a [u8], PduError> {
        let ethernet_len = EthernetFrame::<&[u8]>::buffer_len(self.ethernet_payload_len());

        let buf = buf.get_mut(0..ethernet_len).ok_or(PduError::TooLong)?;

        let mut ethernet_frame = EthernetFrame::new_checked(buf).map_err(PduError::CreateFrame)?;

        ethernet_frame.set_src_addr(MASTER_ADDR);
        ethernet_frame.set_dst_addr(EthernetAddress::BROADCAST);
        ethernet_frame.set_ethertype(ETHERCAT_ETHERTYPE);

        let ethernet_payload = ethernet_frame.payload_mut();

        self.pdu.to_ethernet_payload(ethernet_payload, data)?;

        Ok(ethernet_frame.into_inner())
    }
}

// /// A frame that is in a sendable state.
// #[derive(Debug)]
// pub struct SendableFrame<'a> {
//     frame: &'a mut Frame,
// }

// impl<'a> SendableFrame<'a> {
//     pub(crate) fn mark_sending(&mut self) {
//         todo!("ajm")
//         // self.frame
//         //     .state
//         //     .store(FrameState::Sending, Ordering::SeqCst);
//     }

//     pub(crate) fn data_len(&self) -> usize {
//         usize::from(self.frame.pdu.flags.len())
//     }

//     pub(crate) fn write_ethernet_packet<'buf>(
//         &self,
//         buf: &'buf mut [u8],
//         data: &[u8],
//     ) -> Result<&'buf [u8], PduError> {
//         self.frame.to_ethernet_frame(buf, data)
//     }
// }

// impl Future for Frame {
//     type Output = Result<Pdu, Error>;

//     fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
//         todo!("ajm")
//         // let state = self.state.load(Ordering::SeqCst);

//         // match state {
//         //     FrameState::None => {
//         //         trace!("Frame future polled in None state");
//         //         Poll::Ready(Err(Error::Pdu(PduError::InvalidFrameState)))
//         //     }
//         //     FrameState::Created | FrameState::Sending => {
//         //         // NOTE: Drops previous waker
//         //         self.waker.replace(ctx.waker().clone());

//         //         Poll::Pending
//         //     }
//         //     FrameState::Done => {
//         //         // Clear frame state ready for reuse
//         //         self.state.store(FrameState::None, Ordering::SeqCst);

//         //         // Drop waker so it doesn't get woken again
//         //         self.waker.take();

//         //         Poll::Ready(Ok(core::mem::take(&mut self.pdu)))
//         //     }
//         // }
//     }
// }
