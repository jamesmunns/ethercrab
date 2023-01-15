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
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{addr_of_mut, NonNull, addr_of},
    sync::atomic::{AtomicU8, Ordering},
    task::Waker,
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

use self::pdu_frame::{Frame, FrameState};

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

struct CreatedFrame<'sto> {
    fb: FrameBox<'sto>,
}

pub struct SendableFrame<'sto> {
    fb: FrameBox<'sto>,
}

impl<'sto> SendableFrame<'sto> {
    fn frame_and_buf(&self) -> (&Frame, &[u8]) {
        let buf_ptr = unsafe { addr_of!((*self.fb.fe.as_ptr()).buffer).cast::<u8>() };
        let buf = unsafe { core::slice::from_raw_parts(buf_ptr, self.fb.buf_len) };
        let frame = unsafe { &*addr_of!((*self.fb.fe.as_ptr()).frame) };
        (frame, buf)
    }
}

impl<'sto> SendableFrame<'sto> {
    pub(crate) fn write_ethernet_packet<'buf>(
        &self,
        scratch: &'buf mut [u8],
    ) -> Result<&'buf [u8], PduError> {
        let (frame, buf) = self.frame_and_buf();
        let buf = &buf[..frame.pdu.flags.len().into()];
        frame.to_ethernet_frame(scratch, buf)
    }
}

struct ResponseFrame<'sto> {
    fb: FrameBox<'sto>,
}

struct FrameBox<'sto> {
    fe: NonNull<FrameElement<0>>,
    buf_len: usize,
    _lt: PhantomData<&'sto mut FrameElement<0>>,
}

impl<'sto> FrameBox<'sto> {
    fn buf_mut(&mut self) -> &mut [u8] {
        unsafe {
            let ptr = FrameElement::<0>::buf_ptr(self.fe);
            core::slice::from_raw_parts_mut(ptr.as_ptr(), self.buf_len)
        }
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

    unsafe fn swap_state(
        this: NonNull<FrameElement<N>>,
        from: usize,
        to: usize,
    ) -> Option<NonNull<FrameElement<N>>> {
        let fptr = this.as_ptr();
        // Attempt to swap from "None" to "Created". Return None if this fails.
        //
        // ONLY create a ref to the status, we have no idea if the rest of the
        // FrameElement is garbage at this point.
        (&*addr_of_mut!((*fptr).status))
            .0
            .compare_exchange(
                from,
                to,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .ok()?;

        // If we got here, it's ours.
        Some(this)
    }

    /// Attempt to clame a frame element as CREATED. Succeeds if the selected
    /// FrameElement is currently in the NONE state.
    unsafe fn claim_created(this: NonNull<FrameElement<N>>) -> Option<NonNull<FrameElement<N>>> {
        Self::swap_state(this, FrameState::NONE, FrameState::CREATED)
    }

    /// Attempt to clame a frame element as CREATED. Succeeds if the selected
    /// FrameElement is currently in the NONE state.
    unsafe fn claim_sending(this: NonNull<FrameElement<N>>) -> Option<NonNull<FrameElement<N>>> {
        Self::swap_state(this, FrameState::SENDABLE, FrameState::SENDING)
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

pub struct SendableIter<'a, 'b> {
    storage: &'b PduStorageRef<'a>,
    idx: usize,
}

impl<'a> PduStorageRef<'a> {
    fn alloc_frame(&self) -> Result<CreatedFrame<'a>, Error> {
        let mut found = None;

        // Do a linear search to find the first idle frame
        for idx in 0..self.num_frames {
            let idx_nn = unsafe { NonNull::new_unchecked(self.frames.as_ptr().add(idx)) };
            if let Some(nn) = unsafe { FrameElement::claim_created(idx_nn) } {
                found = Some(nn);
                break;
            }
        }

        // Did we find one?
        let idle = match found {
            Some(nn) => nn,
            None => return Err(Error::StorageFull),
        };

        // Now initialize the frame.
        unsafe {
            addr_of_mut!((*idle.as_ptr()).frame).write(Frame::default());
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
            let sending = SendableFrame { fb: FrameBox { fe: found, buf_len: self.storage.frame_data_len, _lt: PhantomData }};

            send(&sending).map_err(|_| Error::SendFrame)?;


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
    ) -> Result<PduResponse<&'_ [u8]>, Error> {
        let mut frame = self.storage.alloc_frame()?;

        todo!("ajm")
        // // Remove any previous frame's data or other garbage that might be lying around. For
        // // performance reasons (maybe - need to bench) this only blanks the portion of the buffer
        // // that will be used.
        // frame_data[0..usize::from(data_length)].fill(0);

        // frame.replace(command, data_length, idx)?;

        // self.wake_sender();

        // let res = frame.await?;

        // Ok((
        //     &frame_data[0..usize::from(data_length)],
        //     res.working_counter(),
        // ))
    }

    // fn next_index(&self) -> u8 {
    //     self.idx.fetch_add(1, Ordering::AcqRel) % self.storage.num_frames as u8
    // }

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
        todo!("ajm")

        // let raw_packet = EthernetFrame::new_checked(ethernet_frame)?;

        // // Look for EtherCAT packets whilst ignoring broadcast packets sent from self.
        // // As per <https://github.com/OpenEtherCATsociety/SOEM/issues/585#issuecomment-1013688786>,
        // // the first slave will set the second bit of the MSB of the MAC address. This means if we
        // // send e.g. 10:10:10:10:10:10, we receive 12:10:10:10:10:10 which is useful for this
        // // filtering.
        // if raw_packet.ethertype() != ETHERCAT_ETHERTYPE || raw_packet.src_addr() == MASTER_ADDR {
        //     return Ok(());
        // }

        // let i = raw_packet.payload();

        // let (i, header) = context("header", FrameHeader::parse)(i)?;

        // // Only take as much as the header says we should
        // let (_rest, i) = take(header.payload_len())(i)?;

        // let (i, command_code) = map_res(u8, CommandCode::try_from)(i)?;
        // let (i, index) = u8(i)?;

        // let (frame, frame_data) = self.storage.frame(index)?;

        // if frame.pdu.index != index {
        //     return Err(Error::Pdu(PduError::Validation(
        //         PduValidationError::IndexMismatch {
        //             sent: frame.pdu.index,
        //             received: index,
        //         },
        //     )));
        // }

        // let (i, command) = command_code.parse_address(i)?;

        // // Check for weird bugs where a slave might return a different command than the one sent for
        // // this PDU index.
        // if command.code() != frame.pdu().command().code() {
        //     return Err(Error::Pdu(PduError::Validation(
        //         PduValidationError::CommandMismatch {
        //             sent: command,
        //             received: frame.pdu().command(),
        //         },
        //     )));
        // }

        // let (i, flags) = map_res(take(2usize), PduFlags::unpack_from_slice)(i)?;
        // let (i, irq) = le_u16(i)?;
        // let (i, data) = take(flags.length)(i)?;
        // let (i, working_counter) = le_u16(i)?;

        // log::trace!("Received frame with index {index:#04x}, WKC {working_counter}");

        // // `_i` should be empty as we `take()`d an exact amount above.
        // debug_assert_eq!(i.len(), 0);

        // frame_data[0..usize::from(flags.len())].copy_from_slice(data);

        // frame.wake_done(flags, irq, working_counter)?;

        // Ok(())
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
