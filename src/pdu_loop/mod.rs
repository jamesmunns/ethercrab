#![allow(dead_code, unused_imports, unused_variables, unused_mut)] // todo

mod frame_header;
mod pdu;
pub mod pdu_frame;

use crate::{
    command::{Command, CommandCode},
    error::{Error, PduError, PduValidationError},
    pdu_loop::{frame_header::FrameHeader, pdu::PduFlags},
    ETHERCAT_ETHERTYPE, MASTER_ADDR,
};
use core::{
    cell::UnsafeCell,
    future::Future,
    marker::PhantomData,
    mem::MaybeUninit,
    ops::Deref,
    ptr::{addr_of, addr_of_mut, NonNull},
    sync::atomic::{AtomicU8, Ordering},
    task::{Poll, Waker},
};
use nom::{
    bytes::complete::take,
    combinator::map_res,
    error::context,
    number::complete::{le_u16, u8},
};
use packed_struct::PackedStructSlice;
use smoltcp::wire::EthernetFrame;
use spin::RwLock;

use self::{
    pdu::Pdu,
    pdu_frame::{Frame, FrameState},
};

pub type PduResponse<T> = (T, u16);

pub trait CheckWorkingCounter<T> {
    fn wkc(self, expected: u16, context: &'static str) -> Result<T, Error>;
}

impl<T> CheckWorkingCounter<T> for PduResponse<T> {
    fn wkc(self, expected: u16, context: &'static str) -> Result<T, Error> {
        if self.1 == expected {
            Ok(self.0)
        } else {
            Err(Error::WorkingCounter {
                expected,
                received: self.1,
                context: Some(context),
            })
        }
    }
}

struct ReceiveFrameFut<'sto> {
    fb: Option<FrameBox<'sto>>,
}

pub struct ReceivedFrame<'sto> {
    fb: FrameBox<'sto>,
}

pub struct RxFrameDataBuf<'sto> {
    rx_fr: ReceivedFrame<'sto>,
    data_start: NonNull<u8>,
    data_end: NonNull<u8>,
}

impl<'sto> Drop for ReceivedFrame<'sto> {
    fn drop(&mut self) {
        unsafe { FrameElement::set_state(self.fb.fe, FrameState::NONE) }
    }
}

impl<'sto> Deref for RxFrameDataBuf<'sto> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let len = self.len();
        unsafe { core::slice::from_raw_parts(self.data_start.as_ptr(), len) }
    }
}

impl<'sto> RxFrameDataBuf<'sto> {
    pub fn len(&self) -> usize {
        (self.data_end.as_ptr() as usize) - (self.data_start.as_ptr() as usize)
    }

    pub fn trim_front(&mut self, ct: usize) {
        let sz = self.len();
        if ct > sz {
            self.data_start = self.data_end;
        } else {
            self.data_start = unsafe { NonNull::new_unchecked(self.data_start.as_ptr().add(ct)) };
        }
    }
}

impl<'sto> ReceivedFrame<'sto> {
    pub(crate) fn frame(&self) -> &Frame {
        unsafe { self.fb.frame() }
    }

    pub(crate) fn frame_and_data(&self) -> (&Frame, &[u8]) {
        let (frame, buf) = unsafe { self.fb.frame_and_buf() };
        let data = &buf[..frame.pdu.flags.len().into()];
        (frame, data)
    }

    fn into_data_buf(self) -> RxFrameDataBuf<'sto> {
        let len: usize = self.frame().pdu.flags.len().into();
        debug_assert!(len <= self.fb.buf_len);
        let sptr = unsafe { FrameElement::buf_ptr(self.fb.fe) };
        let eptr = unsafe { NonNull::new_unchecked(sptr.as_ptr().add(len)) };
        RxFrameDataBuf {
            rx_fr: self,
            data_start: sptr,
            data_end: eptr,
        }
    }
}

impl<'sto> ReceivedFrame<'sto> {
    pub fn wkc(self, expected: u16, context: &'static str) -> Result<RxFrameDataBuf<'sto>, Error> {
        let (frame, data) = self.frame_and_data();
        let act_wc = frame.pdu.working_counter();

        if act_wc == expected {
            Ok(self.into_data_buf())
        } else {
            Err(Error::WorkingCounter {
                expected,
                received: act_wc,
                context: Some(context),
            })
        }
    }
}

impl<'sto> Future for ReceiveFrameFut<'sto> {
    type Output = Result<ReceivedFrame<'sto>, Error>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let rxin = match self.fb.take() {
            Some(r) => r,
            None => return Poll::Ready(Err(Error::Internal)),
        };

        let swappy = unsafe {
            FrameElement::swap_state(rxin.fe, FrameState::RX_DONE, FrameState::RX_PROCESSING)
        };
        let was = match swappy {
            Ok(fe) => {
                return Poll::Ready(Ok(ReceivedFrame { fb: rxin }));
            }
            Err(e) => e,
        };

        // These are the states from the time we start sending until the response
        // is received. If we observe any of these, it's fine, and we should keep
        // waiting.
        let okay = &[
            FrameState::SENDING,
            FrameState::WAIT_RX,
            FrameState::RX_BUSY,
            FrameState::RX_DONE,
        ];

        if okay.iter().any(|s| s == &was) {
            // TODO: touching the waker here would be unsound!
            //
            // This is because if the sender ever touches this
            //
            // let fm = unsafe { rxin.frame_mut() };
            // if let Some(w) = fm.waker.replace(cx.waker().clone()) {
            //     w.wake();
            // }
            // self.fb = Some(rxin);
            // return Poll::Pending;
            todo!("ajm");
        }

        // any OTHER observed values of `was` indicates that this future has
        // lived longer than it should have.
        //
        // We have had a bad day.
        Poll::Ready(Err(Error::Internal))
    }
}

struct CreatedFrame<'sto> {
    fb: FrameBox<'sto>,
}

pub struct SendableFrame<'sto> {
    fb: FrameBox<'sto>,
}

struct ReceivingFrame<'sto> {
    fb: FrameBox<'sto>,
}

impl<'sto> CreatedFrame<'sto> {
    fn mark_sendable(self) -> ReceiveFrameFut<'sto> {
        unsafe {
            FrameElement::set_state(self.fb.fe, FrameState::SENDABLE);
        }
        ReceiveFrameFut { fb: Some(self.fb) }
    }
}

impl<'sto> SendableFrame<'sto> {
    fn mark_sent(self) {
        unsafe {
            FrameElement::set_state(self.fb.fe, FrameState::WAIT_RX);
        }
    }

    fn frame_and_buf(&self) -> (&Frame, &[u8]) {
        unsafe { self.fb.frame_and_buf() }
    }

    pub(crate) fn write_ethernet_packet<'buf>(
        &self,
        scratch: &'buf mut [u8],
    ) -> Result<&'buf [u8], PduError> {
        let (frame, buf) = self.frame_and_buf();
        let buf = &buf[..frame.pdu.flags.len().into()];
        frame.to_ethernet_frame(scratch, buf)
    }
}

impl<'sto> ReceivingFrame<'sto> {
    fn mark_received(
        mut self,
        flags: PduFlags,
        irq: u16,
        working_counter: u16,
    ) -> Result<(), Error> {
        let (frame, buf) = self.frame_and_buf_mut();

        let waker = frame.waker.take().ok_or_else(|| {
            error!(
                "Attempted to wake frame #{} with no waker, possibly caused by timeout",
                frame.pdu.index
            );

            PduError::InvalidFrameState
        })?;

        frame.pdu.set_response(flags, irq, working_counter);

        waker.wake();

        unsafe {
            FrameElement::set_state(self.fb.fe, FrameState::RX_DONE);
        }
        Ok(())
    }

    fn reset_readable(self) {
        unsafe { FrameElement::set_state(self.fb.fe, FrameState::WAIT_RX) }
    }

    fn frame_and_buf_mut(&mut self) -> (&mut Frame, &mut [u8]) {
        unsafe { self.fb.frame_and_buf_mut() }
    }
}

struct FrameBox<'sto> {
    fe: NonNull<FrameElement<0>>,
    buf_len: usize,
    _lt: PhantomData<&'sto mut FrameElement<0>>,
}

impl<'sto> FrameBox<'sto> {
    unsafe fn frame(&self) -> &Frame {
        unsafe { &*addr_of!((*self.fe.as_ptr()).frame) }
    }

    unsafe fn frame_mut(&self) -> &mut Frame {
        unsafe { &mut *addr_of_mut!((*self.fe.as_ptr()).frame) }
    }

    unsafe fn frame_and_buf(&self) -> (&Frame, &[u8]) {
        let buf_ptr = unsafe { addr_of!((*self.fe.as_ptr()).buffer).cast::<u8>() };
        let buf = unsafe { core::slice::from_raw_parts(buf_ptr, self.buf_len) };
        let frame = unsafe { &*addr_of!((*self.fe.as_ptr()).frame) };
        (frame, buf)
    }

    unsafe fn frame_and_buf_mut(&mut self) -> (&mut Frame, &mut [u8]) {
        let buf_ptr = unsafe { addr_of_mut!((*self.fe.as_ptr()).buffer).cast::<u8>() };
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, self.buf_len) };
        let frame = unsafe { &mut *addr_of_mut!((*self.fe.as_ptr()).frame) };
        (frame, buf)
    }

    unsafe fn buf_mut(&mut self) -> &mut [u8] {
        let ptr = FrameElement::<0>::buf_ptr(self.fe);
        core::slice::from_raw_parts_mut(ptr.as_ptr(), self.buf_len)
    }
}

#[repr(C)]
struct FrameElement<const N: usize> {
    frame: Frame,
    status: FrameState,
    buffer: [u8; N],
}

impl<const N: usize> FrameElement<N> {
    const unsafe fn buf_ptr(this: NonNull<FrameElement<N>>) -> NonNull<u8> {
        let buf_ptr: *mut [u8; N] = unsafe { addr_of_mut!((*this.as_ptr()).buffer) };
        let buf_ptr: *mut u8 = buf_ptr.cast();
        NonNull::new_unchecked(buf_ptr)
    }

    unsafe fn set_state(this: NonNull<FrameElement<N>>, state: usize) {
        // TODO: not every state?

        let fptr = this.as_ptr();
        // Attempt to swap from "None" to "Created". Return None if this fails.
        //
        // ONLY create a ref to the status, we have no idea if the rest of the
        // FrameElement is garbage at this point.
        (&*addr_of_mut!((*fptr).status))
            .0
            .store(state, Ordering::Release);
    }

    unsafe fn swap_state(
        this: NonNull<FrameElement<N>>,
        from: usize,
        to: usize,
    ) -> Result<NonNull<FrameElement<N>>, usize> {
        let fptr = this.as_ptr();
        // Attempt to swap from "None" to "Created". Return None if this fails.
        //
        // ONLY create a ref to the status, we have no idea if the rest of the
        // FrameElement is garbage at this point.
        (&*addr_of_mut!((*fptr).status)).0.compare_exchange(
            from,
            to,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )?;

        // If we got here, it's ours.
        Ok(this)
    }

    /// Attempt to clame a frame element as CREATED. Succeeds if the selected
    /// FrameElement is currently in the NONE state.
    unsafe fn claim_created(this: NonNull<FrameElement<N>>) -> Option<NonNull<FrameElement<N>>> {
        Self::swap_state(this, FrameState::NONE, FrameState::CREATED).ok()
    }

    /// Attempt to clame a frame element as CREATED. Succeeds if the selected
    /// FrameElement is currently in the NONE state.
    unsafe fn claim_sending(this: NonNull<FrameElement<N>>) -> Option<NonNull<FrameElement<N>>> {
        Self::swap_state(this, FrameState::SENDABLE, FrameState::SENDING).ok()
    }

    unsafe fn claim_receiving(this: NonNull<FrameElement<N>>) -> Option<NonNull<FrameElement<N>>> {
        Self::swap_state(this, FrameState::WAIT_RX, FrameState::RX_BUSY).ok()
    }
}

impl<const N: usize> FrameElement<N> {
    pub const fn new() -> Self {
        Self {
            frame: pdu_frame::Frame::new(),
            status: FrameState::const_default(),
            buffer: [0u8; N],
        }
    }
}

unsafe impl Sync for PduLoop {}

/// Stores PDU frames that are currently being prepared to send, in flight, or being received and
/// processed.
#[derive(Debug)]
pub struct PduStorage<const MAX_FRAMES: usize, const MAX_PDU_DATA: usize> {
    // TODO(AJM): We could kill the MU if we can get a const array constructor.
    inner: UnsafeCell<MaybeUninit<[FrameElement<MAX_PDU_DATA>; MAX_FRAMES]>>,
}

unsafe impl<const MAX_FRAMES: usize, const MAX_PDU_DATA: usize> Sync
    for PduStorage<MAX_FRAMES, MAX_PDU_DATA>
{
}

impl<const MAX_FRAMES: usize, const MAX_PDU_DATA: usize> PduStorage<MAX_FRAMES, MAX_PDU_DATA> {
    /// Create a new `PduStorage` instance.
    pub const fn new() -> Self {
        // MSRV: Make `MAX_FRAMES` a `u8` when `generic_const_exprs` is stablised
        assert!(
            MAX_FRAMES <= u8::MAX as usize,
            "Packet indexes are u8s, so cache array cannot be any bigger than u8::MAX"
        );

        let inner: UnsafeCell<MaybeUninit<[FrameElement<MAX_PDU_DATA>; MAX_FRAMES]>> =
            UnsafeCell::new(MaybeUninit::zeroed());

        Self { inner }
    }

    /// Get a reference to this `PduStorage` with erased lifetimes.
    pub const fn as_ref<'a>(&'a self) -> PduStorageRef<'a> {
        let fptr: *mut MaybeUninit<[FrameElement<MAX_PDU_DATA>; MAX_FRAMES]> = self.inner.get();
        let fptr: *mut FrameElement<0> = fptr.cast();
        PduStorageRef {
            frames: unsafe { NonNull::new_unchecked(fptr) },
            num_frames: MAX_FRAMES,
            frame_data_len: MAX_PDU_DATA,
            _lifetime: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct PduStorageRef<'a> {
    frames: NonNull<FrameElement<0>>,
    num_frames: usize,
    frame_data_len: usize,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> PduStorageRef<'a> {
    fn get_readable(&self, idx: u8) -> Option<ReceivingFrame<'a>> {
        let idx_usize: usize = idx.into();

        if idx_usize >= self.num_frames {
            return None;
        }

        let idx_nn = unsafe { NonNull::new_unchecked(self.frames.as_ptr().add(idx_usize)) };
        let rx_nn = unsafe { FrameElement::claim_receiving(idx_nn)? };

        Some(ReceivingFrame {
            fb: FrameBox {
                fe: rx_nn,
                buf_len: self.frame_data_len,
                _lt: PhantomData,
            },
        })
    }

    fn alloc_frame(&self, command: Command, data_length: u16) -> Result<CreatedFrame<'a>, Error> {
        let mut found = None;

        // Do a linear search to find the first idle frame
        for idx in 0..self.num_frames {
            let idx_nn = unsafe { NonNull::new_unchecked(self.frames.as_ptr().add(idx)) };
            if let Some(nn) = unsafe { FrameElement::claim_created(idx_nn) } {
                found = Some((idx as u8, nn));
                break;
            }
        }

        // Did we find one?
        let (idx, idle) = match found {
            Some(nn) => nn,
            None => return Err(Error::StorageFull),
        };

        // Now initialize the frame.
        unsafe {
            addr_of_mut!((*idle.as_ptr()).frame).write(Frame::new_with(Pdu::new_with(
                command,
                data_length,
                idx,
            )));
            let buf_ptr = addr_of_mut!((*idle.as_ptr()).buffer);
            buf_ptr.write_bytes(0x00, self.frame_data_len);
        }

        Ok(CreatedFrame {
            fb: FrameBox {
                fe: idle,
                buf_len: self.frame_data_len,
                _lt: PhantomData,
            },
        })
    }
}

/// The core of the PDU send/receive machinery.
///
/// This item orchestrates queuing, sending and receiving responses to individual PDUs. It uses a
/// fixed length list of frame slots which are cycled through sequentially to ensure each PDU packet
/// has a unique ID (by using the slot index).
#[derive(Debug)]
pub struct PduLoop {
    // frame_data: &'static [UnsafeCell<&'static [u8]>],
    // frames: &'static [UnsafeCell<pdu_frame::Frame>],
    // pub(crate) max_pdu_data: usize,
    storage: PduStorageRef<'static>,

    /// A waker used to wake up the TX task when a new frame is ready to be sent.
    tx_waker: RwLock<Option<Waker>>,
    /// EtherCAT frame index.
    idx: AtomicU8,
}

impl PduLoop {
    /// Create a new PDU loop with the given backing storage.
    pub const fn new(storage: PduStorageRef<'static>) -> Self {
        assert!(storage.num_frames <= u8::MAX as usize);

        Self {
            // frames: storage.frames,
            // frame_data: storage.frame_data,
            // max_pdu_data: storage.max_pdu_data,
            storage,
            tx_waker: RwLock::new(None),
            idx: AtomicU8::new(0),
        }
    }

    pub(crate) fn max_frame_data(&self) -> usize {
        self.storage.frame_data_len
    }

    // TX
    /// Iterate through any PDU TX frames that are ready and send them.
    ///
    /// The blocking `send` function is called for each ready frame. It is given a `SendableFrame`.
    pub fn send_frames_blocking<F>(&self, waker: &Waker, mut send: F) -> Result<(), Error>
    where
        F: FnMut(&SendableFrame<'_>) -> Result<(), ()>,
    {
        // Do a linear search to find the first idle frame
        for idx in 0..self.storage.num_frames {
            let idx_nn = unsafe { NonNull::new_unchecked(self.storage.frames.as_ptr().add(idx)) };
            let found = match unsafe { FrameElement::claim_sending(idx_nn) } {
                Some(nn) => nn,
                None => continue,
            };
            // The frame is initialized, we are free to treat it as a sending type now.
            let sending = SendableFrame {
                fb: FrameBox {
                    fe: found,
                    buf_len: self.storage.frame_data_len,
                    _lt: PhantomData,
                },
            };

            match send(&sending) {
                Ok(_) => {
                    sending.mark_sent();
                }
                Err(_) => {
                    return Err(Error::SendFrame);
                }
            }
        }

        if self.tx_waker.read().is_none() {
            self.tx_waker.write().replace(waker.clone());
        }

        Ok(())
    }

    // TX
    /// Read data back from one or more slave devices.
    pub async fn pdu_tx_readonly(
        &self,
        command: Command,
        data_length: u16,
    ) -> Result<ReceivedFrame<'static>, Error> {
        let created_frame = self.storage.alloc_frame(command, data_length)?;
        let rx_fut = created_frame.mark_sendable();
        self.wake_sender();

        rx_fut.await
    }

    /// Tell the packet sender there is data ready to send.
    fn wake_sender(&self) {
        if let Some(waker) = self.tx_waker.read().as_ref() {
            waker.wake_by_ref()
        }
    }

    // TX
    /// Broadcast (BWR) a packet full of zeroes, up to `max_data_length`.
    pub async fn pdu_broadcast_zeros(
        &self,
        register: u16,
        payload_length: u16,
    ) -> Result<PduResponse<()>, Error> {
        todo!("ajm")
        // let idx = self.next_index();

        // let (frame, frame_data) = self.storage.frame(idx)?;

        // frame.replace(
        //     Command::Bwr {
        //         address: 0,
        //         register,
        //     },
        //     payload_length,
        //     idx,
        // )?;

        // let payload_length = usize::from(payload_length);

        // let payload = frame_data
        //     .get_mut(0..payload_length)
        //     .ok_or(Error::Pdu(PduError::TooLong))?;

        // payload.fill(0);

        // self.wake_sender();

        // let res = frame.await?;

        // Ok(((), res.working_counter()))
    }

    // TX
    /// Send data to and read data back from multiple slaves.
    ///
    /// Unlike [`pdu_tx_readwrite`](crate::pdu_loop::PduLoop::pdu_tx_readwrite), this method allows
    /// overriding the minimum data length of the payload.
    ///
    /// The PDU data length will be the larger of `send_data.len()` and `data_length`. If a larger
    /// response than `send_data` is desired, set the expected response length in `data_length`.
    pub async fn pdu_tx_readwrite_len<'a>(
        &'a self,
        command: Command,
        send_data: &[u8],
        data_length: u16,
    ) -> Result<PduResponse<&'a [u8]>, Error> {
        todo!("ajm")
        // let idx = self.next_index();

        // let send_data_len = send_data.len();
        // let payload_length = u16::try_from(send_data.len())?.max(data_length);

        // let (frame, frame_data) = self.storage.frame(idx)?;

        // frame.replace(command, payload_length, idx)?;

        // let payload = frame_data
        //     .get_mut(0..usize::from(payload_length))
        //     .ok_or(Error::Pdu(PduError::TooLong))?;

        // let (data, rest) = payload.split_at_mut(send_data_len);

        // data.copy_from_slice(send_data);
        // // If we write fewer bytes than the requested payload length (e.g. write SDO with data
        // // payload section reserved for reply), make sure the remaining data is zeroed out from any
        // // previous request.
        // rest.fill(0);

        // self.wake_sender();

        // let res = frame.await?;

        // Ok((&payload[0..send_data_len], res.working_counter()))
    }

    // TX
    /// Send data to and read data back from multiple slaves.
    pub async fn pdu_tx_readwrite<'a>(
        &'a self,
        command: Command,
        send_data: &[u8],
    ) -> Result<PduResponse<&'a [u8]>, Error> {
        self.pdu_tx_readwrite_len(command, send_data, send_data.len().try_into()?)
            .await
    }

    // RX
    /// Parse a PDU from a complete Ethernet II frame.
    pub fn pdu_rx(&self, ethernet_frame: &[u8]) -> Result<(), Error> {
        let raw_packet = EthernetFrame::new_checked(ethernet_frame)?;

        // Look for EtherCAT packets whilst ignoring broadcast packets sent from self.
        // As per <https://github.com/OpenEtherCATsociety/SOEM/issues/585#issuecomment-1013688786>,
        // the first slave will set the second bit of the MSB of the MAC address. This means if we
        // send e.g. 10:10:10:10:10:10, we receive 12:10:10:10:10:10 which is useful for this
        // filtering.
        if raw_packet.ethertype() != ETHERCAT_ETHERTYPE || raw_packet.src_addr() == MASTER_ADDR {
            return Ok(());
        }

        let i = raw_packet.payload();

        let (i, header) = context("header", FrameHeader::parse)(i)?;

        // Only take as much as the header says we should
        let (_rest, i) = take(header.payload_len())(i)?;

        let (i, command_code) = map_res(u8, CommandCode::try_from)(i)?;
        let (i, index) = u8(i)?;

        // let (frame, frame_data) = self.storage.frame(index)?;

        let mut rxin_frame = self
            .storage
            .get_readable(index)
            .expect("todo(ajm) should fix this/data race says what?");
        let (frame, frame_data) = rxin_frame.frame_and_buf_mut();

        if frame.pdu.index != index {
            let sent = frame.pdu.index;
            rxin_frame.reset_readable();
            return Err(Error::Pdu(PduError::Validation(
                PduValidationError::IndexMismatch {
                    sent,
                    received: index,
                },
            )));
        }

        let (i, command) = command_code.parse_address(i)?;

        // Check for weird bugs where a slave might return a different command than the one sent for
        // this PDU index.
        if command.code() != frame.pdu().command().code() {
            let received = frame.pdu().command();
            rxin_frame.reset_readable();
            return Err(Error::Pdu(PduError::Validation(
                PduValidationError::CommandMismatch {
                    sent: command,
                    received,
                },
            )));
        }

        let (i, flags) = map_res(take(2usize), PduFlags::unpack_from_slice)(i)?;
        let (i, irq) = le_u16(i)?;
        let (i, data) = take(flags.length)(i)?;
        let (i, working_counter) = le_u16(i)?;

        log::trace!("Received frame with index {index:#04x}, WKC {working_counter}");

        // `_i` should be empty as we `take()`d an exact amount above.
        debug_assert_eq!(i.len(), 0);

        frame_data[0..usize::from(flags.len())].copy_from_slice(data);

        rxin_frame.mark_received(flags, irq, working_counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{task::Poll, time::Duration};
    use smoltcp::wire::EthernetAddress;
    use std::thread;

    static STORAGE: PduStorage<16, 128> = PduStorage::<16, 128>::new();
    static PDU_LOOP: PduLoop = PduLoop::new(STORAGE.as_ref());

    // Test the whole TX/RX loop with multiple threads
    #[test]
    fn parallel() {
        // Comment out to make this test work with miri
        // env_logger::try_init().ok();

        let (s, mut r) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        thread::Builder::new()
            .name("TX task".to_string())
            .spawn(move || {
                smol::block_on(async move {
                    let mut packet_buf = [0u8; 1536];

                    log::info!("Spawn TX task");

                    core::future::poll_fn::<(), _>(move |ctx| {
                        log::info!("Poll fn");

                        PDU_LOOP
                            .send_frames_blocking(ctx.waker(), |frame, data| {
                                let packet = frame
                                    .write_ethernet_packet(&mut packet_buf, data)
                                    .expect("Write Ethernet frame");

                                s.send(packet.to_vec()).unwrap();

                                // Simulate packet send delay
                                smol::Timer::after(Duration::from_millis(1));

                                log::info!("Sent packet");

                                Ok(())
                            })
                            .unwrap();

                        Poll::Pending
                    })
                    .await
                })
            })
            .unwrap();

        thread::Builder::new()
            .name("RX task".to_string())
            .spawn(move || {
                smol::block_on(async move {
                    log::info!("Spawn RX task");

                    while let Some(ethernet_frame) = r.recv().await {
                        // Munge fake sent frame into a fake received frame
                        let ethernet_frame = {
                            let mut frame = EthernetFrame::new_checked(ethernet_frame).unwrap();
                            frame.set_src_addr(EthernetAddress([
                                0x12, 0x10, 0x10, 0x10, 0x10, 0x10,
                            ]));
                            frame.into_inner()
                        };

                        log::info!("Received packet");

                        PDU_LOOP.pdu_rx(&ethernet_frame).expect("RX");
                    }
                })
            })
            .unwrap();

        // let task_1 = thread::Builder::new()
        //     .name("Task 1".to_string())
        //     .spawn(move || {
        smol::block_on(async move {
            for i in 0..64 {
                let data = [0xaa, 0xbb, 0xcc, 0xdd, i];

                log::info!("Send PDU {i}");

                let (result, _wkc) = PDU_LOOP
                    .pdu_tx_readwrite(
                        Command::Fpwr {
                            address: 0x1000,
                            register: 0x0980,
                        },
                        &data,
                    )
                    .await
                    .unwrap();

                assert_eq!(result, &data);
            }
        });
        // })
        // .unwrap();

        // smol::block_on(async move {
        //     for i in 0..64 {
        //         let data = [0x11, 0x22, 0x33, 0x44, 0x55, i];

        //         log::info!("Send PDU {i}");

        //         let (result, _wkc) = pdu_loop
        //             .pdu_tx_readwrite(
        //                 Command::Fpwr {
        //                     address: 0x1000,
        //                     register: 0x0980,
        //                 },
        //                 &data,
        //                 &Timeouts::default(),
        //             )
        //             .await
        //             .unwrap();

        //         assert_eq!(result, &data);
        //     }
        // });

        // task_1.join().unwrap();
    }
}
