use crate::{
    al_control::AlControl,
    al_status_code::AlStatusCode,
    command::Command,
    dc,
    error::{Error, Item, PduError},
    pdi::PdiOffset,
    pdu_data::{PduData, PduRead},
    pdu_loop::{CheckWorkingCounter, PduLoop, PduResponse},
    register::RegisterAddress,
    slave::Slave,
    slave_group::SlaveGroupContainer,
    slave_state::SlaveState,
    timer_factory::{timeout, Timeouts, TimerFactory},
    BASE_SLAVE_ADDR,
};
use core::{
    any::type_name,
    marker::PhantomData,
    sync::atomic::{AtomicU16, AtomicU8, Ordering},
};
use packed_struct::PackedStruct;

/// A medium-level interface over PDUs (e.g. `BRD`, `LRW`, etc) and other EtherCAT master related
/// infrastructure.
#[derive(Debug)]
pub struct Client<'client, TIMEOUT> {
    // TODO: un-pub
    pub(crate) pdu_loop: &'client PduLoop,
    /// The total number of discovered slaves.
    ///
    /// Using an `AtomicU16` here only to satisfy `Sync` requirements, but it's only ever written to
    /// once so its safety is largely unused.
    num_slaves: AtomicU16,
    _timeout: PhantomData<TIMEOUT>,
    pub(crate) timeouts: Timeouts,
    /// The 1-7 cyclic counter used when working with mailbox requests.
    mailbox_counter: AtomicU8,
}

unsafe impl<'client, TIMEOUT> Sync for Client<'client, TIMEOUT> {}

impl<'client, TIMEOUT> Client<'client, TIMEOUT>
where
    TIMEOUT: TimerFactory,
{
    /// Create a new EtherCrab client.
    pub const fn new(pdu_loop: &'client PduLoop, timeouts: Timeouts) -> Self {
        Self {
            pdu_loop,
            // slaves: UnsafeCell::new(heapless::Vec::new()),
            num_slaves: AtomicU16::new(0),
            _timeout: PhantomData,
            timeouts,
            // 0 is a reserved value, so we initialise the cycle at 1. The cycle repeats 1 - 7.
            mailbox_counter: AtomicU8::new(1),
        }
    }

    /// Return the current cyclic mailbox counter value, from 0-7.
    ///
    /// Calling this method internally increments the counter, so subequent calls will produce a new
    /// value.
    pub(crate) fn mailbox_counter(&self) -> u8 {
        self.mailbox_counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n >= 7 {
                    Some(1)
                } else {
                    Some(n + 1)
                }
            })
            .unwrap()
    }

    /// Write zeroes to every slave's memory in chunks.
    async fn blank_memory(&self, start: impl Into<u16>, len: u16) -> Result<(), Error> {
        let start: u16 = start.into();
        let step = self.pdu_loop.max_pdu_data;
        let range = start..(start + len);

        // TODO: This will miss the last step if step is not a multiple of range. Use a loop instead.
        for chunk_start in range.step_by(step) {
            timeout::<TIMEOUT, _, _>(
                self.timeouts.pdu,
                self.pdu_loop.pdu_broadcast_zeros(chunk_start, step as u16),
            )
            .await?;
        }

        Ok(())
    }

    // FIXME: When adding a powered on slave to the network, something breaks. Maybe need to reset
    // the configured address? But this broke other stuff so idk...
    async fn reset_slaves(&self) -> Result<(), Error> {
        // Reset slaves to init
        self.bwr(
            RegisterAddress::AlControl,
            AlControl::reset().pack().unwrap(),
        )
        .await?;

        // Clear FMMUs. FMMU memory section is 0xff (255) bytes long - see ETG1000.4 Table 57
        self.blank_memory(RegisterAddress::Fmmu0, 0xff).await?;

        // Clear SMs. SM memory section is 0x7f bytes long - see ETG1000.4 Table 59
        self.blank_memory(RegisterAddress::Sm0, 0x7f).await?;

        self.blank_memory(
            RegisterAddress::DcSystemTime,
            core::mem::size_of::<u64>() as u16,
        )
        .await?;
        self.blank_memory(
            RegisterAddress::DcSystemTimeOffset,
            core::mem::size_of::<u64>() as u16,
        )
        .await?;
        self.blank_memory(
            RegisterAddress::DcSystemTimeTransmissionDelay,
            core::mem::size_of::<u32>() as u16,
        )
        .await?;

        // ETG1020 Section 22.2.4 defines these initial parameters. The data types are defined in
        // ETG1000.4 Table 60 – Distributed clock local time parameter, helpfully named "Control
        // Loop Parameter 1" to 3.
        //
        // According to ETG1020, we'll use the mode where the DC reference clock is adjusted to the
        // master clock.
        self.bwr(RegisterAddress::DcControlLoopParam3, 0x0c00u16)
            .await?;
        // Must be after param 3 so DC control unit is reset
        self.bwr(RegisterAddress::DcControlLoopParam1, 0x1000u16)
            .await?;

        Ok(())
    }

    /// Detect slaves, set their configured station addresses, assign to groups, configure slave
    /// devices from EEPROM.
    pub async fn init<const MAX_SLAVES: usize, G>(
        &self,
        mut groups: G,
        mut group_filter: impl FnMut(&mut G, Slave) -> Result<(), Error>,
    ) -> Result<G, Error>
    where
        G: SlaveGroupContainer<TIMEOUT>,
    {
        self.reset_slaves().await?;

        // Each slave increments working counter, so we can use it as a total count of slaves
        let (_res, num_slaves) = self.brd::<u8>(RegisterAddress::Type).await?;

        // This is the only place we store the number of slave devices, so the ordering can be
        // pretty much anything.
        self.num_slaves.store(num_slaves, Ordering::Relaxed);

        let mut slaves = heapless::Deque::<Slave, MAX_SLAVES>::new();

        // Set configured address for all discovered slaves
        for slave_idx in 0..num_slaves {
            let configured_address = BASE_SLAVE_ADDR.wrapping_add(slave_idx);

            self.apwr(
                slave_idx,
                RegisterAddress::ConfiguredStationAddress,
                configured_address,
            )
            .await?
            .wkc(1, "set station address")?;

            let slave = Slave::new(self, usize::from(slave_idx), configured_address).await?;

            slaves
                .push_back(slave)
                .map_err(|_| Error::Capacity(Item::Slave))?;
        }

        // Configure distributed clock offsets/propagation delays, perform static drift
        // compensation. We need the slaves in a list to do this.
        dc::configure_dc(self, slaves.as_mut_slices().0).await?;

        while let Some(slave) = slaves.pop_front() {
            let configured_address = slave.configured_address;
            let slave_name = slave.name.clone();

            let before_count = groups.total_slaves();

            group_filter(&mut groups, slave)?;

            if groups.total_slaves() != before_count + 1 {
                log::error!(
                    "Slave {:#06x} ({}) was not assigned to a group. All slaves must be assigned.",
                    configured_address,
                    slave_name
                );
            }
        }

        let mut offset = PdiOffset::default();

        // Loop through groups and configure the slaves in each one.
        for i in 0..groups.num_groups() {
            let mut group = groups.group(i).ok_or(Error::NotFound {
                item: Item::Group,
                index: Some(i),
            })?;

            offset = group.configure_from_eeprom(offset, self).await?;

            log::debug!("After group #{i} offset: {:?}", offset);
        }

        log::debug!("Total PDI {} bytes", offset.start_address);

        // Wait for all slaves to reach SAFE-OP
        self.wait_for_state(SlaveState::SafeOp).await?;

        Ok(groups)
    }

    /// Get the number of discovered slaves in the EtherCAT network.
    ///
    /// As [`init`](crate::Client::init) runs slave autodetection, it must be called before this
    /// method to get an accurate count.
    pub fn num_slaves(&self) -> usize {
        usize::from(self.num_slaves.load(Ordering::Relaxed))
    }

    /// Request the same state for all slaves.
    pub async fn request_slave_state(&self, desired_state: SlaveState) -> Result<(), Error> {
        let num_slaves = self.num_slaves.load(Ordering::Relaxed);

        self.bwr(
            RegisterAddress::AlControl,
            AlControl::new(desired_state).pack().unwrap(),
        )
        .await?
        .wkc(num_slaves, "set all slaves state")?;

        self.wait_for_state(desired_state).await
    }

    /// Wait for all slaves on the network to reach a given state.
    pub async fn wait_for_state(&self, desired_state: SlaveState) -> Result<(), Error> {
        let num_slaves = self.num_slaves.load(Ordering::Relaxed);

        timeout::<TIMEOUT, _, _>(self.timeouts.state_transition, async {
            loop {
                let status = self
                    .brd::<AlControl>(RegisterAddress::AlStatus)
                    .await?
                    .wkc(num_slaves, "read all slaves state")?;

                log::trace!("Global AL status {status:?}");

                if status.error {
                    log::error!(
                        "Error occurred transitioning all slaves to {:?}",
                        desired_state,
                    );

                    for slave_addr in BASE_SLAVE_ADDR..(BASE_SLAVE_ADDR + self.num_slaves() as u16)
                    {
                        let (slave_status, _wkc) = self
                            .fprd::<AlStatusCode>(slave_addr, RegisterAddress::AlStatusCode)
                            .await?;

                        log::error!("--> Slave {:#06x} status code {}", slave_addr, slave_status);
                    }

                    return Err(Error::StateTransition);
                }

                if status.state == desired_state {
                    break Ok(());
                }

                self.timeouts.loop_tick::<TIMEOUT>().await;
            }
        })
        .await
    }

    async fn read_service<T>(&self, command: Command) -> Result<PduResponse<T>, Error>
    where
        T: PduRead,
    {
        let (data, working_counter) = timeout::<TIMEOUT, _, _>(
            self.timeouts.pdu,
            self.pdu_loop.pdu_tx_readonly(command, T::len()),
        )
        .await?;

        let res = T::try_from_slice(data).map_err(|e| {
            log::error!(
                "PDU data decode: {:?}, T: {} data {:?}",
                e,
                type_name::<T>(),
                data
            );

            PduError::Decode
        })?;

        Ok((res, working_counter))
    }

    async fn write_service<T>(&self, command: Command, value: T) -> Result<PduResponse<T>, Error>
    where
        T: PduData,
    {
        let (data, working_counter) = timeout::<TIMEOUT, _, _>(
            self.timeouts.pdu,
            self.pdu_loop.pdu_tx_readwrite(command, value.as_slice()),
        )
        .await?;

        let res = T::try_from_slice(data).map_err(|e| {
            log::error!(
                "PDU data decode: {:?}, T: {} data {:?}",
                e,
                type_name::<T>(),
                data
            );

            PduError::Decode
        })?;

        Ok((res, working_counter))
    }

    /// Send a `BRD` (Broadcast Read).
    pub async fn brd<T>(&self, register: RegisterAddress) -> Result<PduResponse<T>, Error>
    where
        T: PduRead,
    {
        self.read_service(Command::Brd {
            // Address is always zero when sent from master
            address: 0,
            register: register.into(),
        })
        .await
    }

    /// Broadcast write.
    pub async fn bwr<T>(
        &self,
        register: RegisterAddress,
        value: T,
    ) -> Result<PduResponse<()>, Error>
    where
        T: PduData,
    {
        self.write_service(
            Command::Bwr {
                address: 0,
                register: register.into(),
            },
            value,
        )
        .await
        .map(|(_, wkc)| ((), wkc))
    }

    /// Auto Increment Physical Read.
    pub async fn aprd<T>(
        &self,
        address: u16,
        register: RegisterAddress,
    ) -> Result<PduResponse<T>, Error>
    where
        T: PduRead,
    {
        self.read_service(Command::Aprd {
            address: 0u16.wrapping_sub(address),
            register: register.into(),
        })
        .await
    }

    /// Auto Increment Physical Write.
    pub async fn apwr<T>(
        &self,
        address: u16,
        register: RegisterAddress,
        value: T,
    ) -> Result<PduResponse<T>, Error>
    where
        T: PduData,
    {
        self.write_service(
            Command::Apwr {
                address: 0u16.wrapping_sub(address),
                register: register.into(),
            },
            value,
        )
        .await
    }

    /// Configured address read.
    pub async fn fprd<T>(
        &self,
        address: u16,
        register: RegisterAddress,
    ) -> Result<PduResponse<T>, Error>
    where
        T: PduRead,
    {
        self.read_service(Command::Fprd {
            address,
            register: register.into(),
        })
        .await
    }

    /// Configured address write.
    pub async fn fpwr<T>(
        &self,
        address: u16,
        register: impl Into<u16>,
        value: T,
    ) -> Result<PduResponse<T>, Error>
    where
        T: PduData,
    {
        self.write_service(
            Command::Fpwr {
                address,
                register: register.into(),
            },
            value,
        )
        .await
    }

    /// Configured address read, multiple write.
    ///
    /// This can be used to distributed a value from one slave to all others on the network, e.g.
    /// with distributed clocks.
    pub async fn frmw<T>(
        &self,
        address: u16,
        register: RegisterAddress,
    ) -> Result<PduResponse<T>, Error>
    where
        T: PduRead,
    {
        self.read_service(Command::Frmw {
            address,
            register: register.into(),
        })
        .await
    }

    /// Logical write.
    pub async fn lwr<T>(&self, address: u32, value: T) -> Result<PduResponse<T>, Error>
    where
        T: PduData,
    {
        self.write_service(Command::Lwr { address }, value).await
    }

    /// Logical read/write.
    pub async fn lrw<T>(&self, address: u32, value: T) -> Result<PduResponse<T>, Error>
    where
        T: PduData,
    {
        self.write_service(Command::Lrw { address }, value).await
    }

    /// Logical read/write, but direct from/to a mutable slice.
    ///
    /// Using the given `read_back_len = N`, only the first _N_ bytes will be read back into the
    /// buffer, leaving the rest of the buffer as-transmitted.
    ///
    /// This is useful for only changing input data from slaves. If the passed buffer structure is
    /// e.g. `IIIIOOOO` and a length of `4` is given, only the `I` parts will have data written into
    /// them.
    // TODO: Chunked sends if buffer is too long for MAX_PDU_DATA
    // TODO: DC sync FRMW
    pub async fn lrw_buf<'buf>(
        &self,
        address: u32,
        value: &'buf mut [u8],
        read_back_len: usize,
    ) -> Result<PduResponse<&'buf mut [u8]>, Error> {
        assert!(value.len() <= self.pdu_loop.max_pdu_data, "Chunked LRW not yet supported. Buffer of length {} is too long to send in one {} frame", value.len(), self.pdu_loop.max_pdu_data);

        let (data, working_counter) = timeout::<TIMEOUT, _, _>(
            self.timeouts.pdu,
            self.pdu_loop
                .pdu_tx_readwrite(Command::Lrw { address }, value),
        )
        .await?;

        if data.len() != value.len() {
            log::error!(
                "Data length {} does not match value length {}",
                data.len(),
                value.len()
            );
            return Err(Error::Pdu(PduError::Decode));
        }

        value[0..read_back_len].copy_from_slice(&data[0..read_back_len]);

        Ok((value, working_counter))
    }
}
