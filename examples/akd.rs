//! Configure a Kollmorgen AKD servo drive and put it in enabled state.

use async_ctrlc::CtrlC;
use async_io::Timer;
use ethercrab::{
    error::{Error, MailboxError},
    std::tx_rx_task,
    Client, PduLoop, PduStorage, SlaveGroup, SlaveState, SubIndex, Timeouts,
};
use futures_lite::{FutureExt, StreamExt};
use smol::LocalExecutor;
use std::{sync::Arc, time::Duration};

#[cfg(target_os = "windows")]
// ASRock NIC
// const INTERFACE: &str = "TODO";
// // USB NIC
// const INTERFACE: &str = "\\Device\\NPF_{DCEDC919-0A20-47A2-9788-FC57D0169EDB}";
// Lenovo USB-C NIC
const INTERFACE: &str = "\\Device\\NPF_{CC0908D5-3CB8-46D6-B8A2-575D0578008D}";
// Silver USB NIC
// const INTERFACE: &str = "\\Device\\NPF_{CC0908D5-3CB8-46D6-B8A2-575D0578008D}";
#[cfg(not(target_os = "windows"))]
const INTERFACE: &str = "eth1";

const MAX_SLAVES: usize = 16;
const MAX_PDU_DATA: usize = 1100;
const MAX_FRAMES: usize = 16;
const PDI_LEN: usize = 64;

static PDU_STORAGE: PduStorage<MAX_FRAMES, MAX_PDU_DATA> = PduStorage::new();
static PDU_LOOP: PduLoop = PduLoop::new(PDU_STORAGE.as_ref());

async fn main_inner(ex: &LocalExecutor<'static>) -> Result<(), Error> {
    log::info!("Starting SDO demo...");

    let client = Arc::new(Client::<smol::Timer>::new(&PDU_LOOP, Timeouts::default()));

    ex.spawn(tx_rx_task(INTERFACE, &client).unwrap()).detach();

    // let num_slaves = client.num_slaves();

    let groups = SlaveGroup::<MAX_SLAVES, PDI_LEN, _>::new(|slave| {
        Box::pin(async {
            // --- Reads ---

            // // Name
            // dbg!(slave
            //     .read_sdo::<heapless::String<64>>(0x1008, SdoAccess::Index(0))
            //     .await
            //     .unwrap());

            // // Software version. For AKD, this should equal "M_01-20-00-003"
            // dbg!(slave
            //     .read_sdo::<heapless::String<64>>(0x100a, SdoAccess::Index(0))
            //     .await
            //     .unwrap());

            // --- Writes ---

            log::info!("Found {}", slave.name());

            let profile = match slave.read_sdo::<u32>(0x1000, SubIndex::Index(0)).await {
                Err(Error::Mailbox(MailboxError::NoMailbox)) => Ok(None),
                Ok(device_type) => Ok(Some(device_type & 0xffff)),
                Err(e) => Err(e),
            }?;

            // CiA 402/DS402 device
            if profile == Some(402) {
                log::info!("CiA402 drive found");
            }

            // AKD config
            if slave.name() == "AKD" {
                slave.write_sdo(0x1c12, SubIndex::Index(0), 0u8).await?;
                // 0x1702 = fixed velocity mapping
                slave
                    .write_sdo(0x1c12, SubIndex::Index(1), 0x1702u16)
                    .await?;
                slave.write_sdo(0x1c12, SubIndex::Index(0), 0x01u8).await?;

                // Must set both read AND write SDOs for AKD otherwise it times out going into OP
                slave.write_sdo(0x1c13, SubIndex::Index(0), 0u8).await?;
                slave
                    .write_sdo(0x1c13, SubIndex::Index(1), 0x1B01u16)
                    .await?;
                slave.write_sdo(0x1c13, SubIndex::Index(0), 0x01u8).await?;

                // Opmode - Cyclic Synchronous Position
                // slave.write_sdo(0x6060, SubIndex::Index(0), 0x08).await?;
                // Opmode - Cyclic Synchronous Velocity
                slave.write_sdo(0x6060, SubIndex::Index(0), 0x09u8).await?;

                {
                    // Shows up as default value of 2^20, but I'm using a 2^32 counts/rev encoder.
                    let encoder_increments =
                        slave.read_sdo::<u32>(0x608f, SubIndex::Index(1)).await?;
                    let num_revs = slave.read_sdo::<u32>(0x608f, SubIndex::Index(2)).await?;

                    let gear_ratio_motor =
                        slave.read_sdo::<u32>(0x6091, SubIndex::Index(1)).await?;
                    let gear_ratio_final =
                        slave.read_sdo::<u32>(0x6091, SubIndex::Index(2)).await?;

                    let feed = slave.read_sdo::<u32>(0x6092, SubIndex::Index(1)).await?;
                    let shaft_revolutions =
                        slave.read_sdo::<u32>(0x6092, SubIndex::Index(2)).await?;

                    dbg!(
                        encoder_increments,
                        num_revs,
                        gear_ratio_motor,
                        gear_ratio_final,
                        feed,
                        shaft_revolutions,
                    );

                    let counts_per_rev = encoder_increments / num_revs;

                    log::info!("Counts per rev {}", counts_per_rev);
                }
            }

            Ok(())
        })
    });

    let group = client
        .init::<16, _>(groups, |groups, slave| groups.push(slave))
        .await
        .expect("Init");

    client
        .request_slave_state(SlaveState::Op)
        .await
        .expect("OP");

    log::info!("Slaves moved to OP state");

    log::info!("Group has {} slaves", group.len());

    let slave = group.slave(0).unwrap();

    // Run twice to prime PDI
    group.tx_rx(&client).await.expect("TX/RX");

    let cycle_time = {
        let base = slave
            .read_sdo::<u8>(&client, 0x60c2, SubIndex::Index(1))
            .await?;
        let x10 = slave
            .read_sdo::<i8>(&client, 0x60c2, SubIndex::Index(2))
            .await?;

        let base = f32::from(base);
        let x10 = 10.0f32.powi(i32::from(x10));

        let cycle_time_ms = (base * x10) * 1000.0;

        Duration::from_millis(unsafe { cycle_time_ms.round().to_int_unchecked() })
    };

    log::debug!("Cycle time: {} ms", cycle_time.as_millis());

    // AKD will error with F706 if cycle time is not 2ms or less
    let mut cyclic_interval = Timer::interval(cycle_time);

    // Check for and clear faults
    {
        log::info!("Checking faults");

        group.tx_rx(&client).await.expect("TX/RX");

        let (i, o) = slave.io();

        let status = {
            let status = u16::from_le_bytes(i[4..=5].try_into().unwrap());

            unsafe { AkdStatusWord::from_bits_unchecked(status) }
        };

        if status.contains(AkdStatusWord::FAULT) {
            log::warn!("Fault! Clearing...");

            let (_pos_cmd, control) = o.split_at_mut(4);
            let reset = AkdControlWord::RESET_FAULT;
            let reset = reset.bits().to_le_bytes();
            control.copy_from_slice(&reset);

            while let Some(_) = cyclic_interval.next().await {
                group.tx_rx(&client).await.expect("TX/RX");

                let (i, _o) = slave.io();

                let status = {
                    let status = u16::from_le_bytes(i[4..=5].try_into().unwrap());

                    unsafe { AkdStatusWord::from_bits_unchecked(status) }
                };

                if !status.contains(AkdStatusWord::FAULT) {
                    log::info!("Fault cleared, status is now {status:?}");

                    break;
                }
            }
        }
    }

    // Shutdown state
    {
        log::info!("Putting drive in shutdown state");

        let (_i, o) = slave.io();

        let (_pos_cmd, control) = o.split_at_mut(4);
        let value = AkdControlWord::SHUTDOWN;
        let value = value.bits().to_le_bytes();
        control.copy_from_slice(&value);

        while let Some(_) = cyclic_interval.next().await {
            group.tx_rx(&client).await.expect("TX/RX");

            let (i, _o) = slave.io();

            let status = {
                let status = u16::from_le_bytes(i[4..=5].try_into().unwrap());

                unsafe { AkdStatusWord::from_bits_unchecked(status) }
            };

            if status.contains(AkdStatusWord::READY_TO_SWITCH_ON) {
                log::info!("Drive is shut down");

                break;
            }
        }
    }

    // Switch drive on
    {
        log::info!("Switching drive on");

        let (_i, o) = slave.io();

        let (_pos_cmd, control) = o.split_at_mut(4);
        let reset = AkdControlWord::SWITCH_ON
            | AkdControlWord::DISABLE_VOLTAGE
            | AkdControlWord::QUICK_STOP;
        let reset = reset.bits().to_le_bytes();
        control.copy_from_slice(&reset);

        while let Some(_) = cyclic_interval.next().await {
            group.tx_rx(&client).await.expect("TX/RX");

            let (i, o) = slave.io();

            let status = {
                let status = u16::from_le_bytes(i[4..=5].try_into().unwrap());

                unsafe { AkdStatusWord::from_bits_unchecked(status) }
            };

            if status.contains(AkdStatusWord::SWITCHED_ON) {
                log::info!("Drive switched on, begin cyclic operation");

                let (_pos_cmd, control) = o.split_at_mut(4);

                // Enable operation so we can send cyclic data
                let state = AkdControlWord::SWITCH_ON
                    | AkdControlWord::DISABLE_VOLTAGE
                    | AkdControlWord::QUICK_STOP
                    | AkdControlWord::ENABLE_OP;
                let state = state.bits().to_le_bytes();
                control.copy_from_slice(&state);

                break;
            }
        }
    }

    let mut velocity: i32 = 0;

    while let Some(_) = cyclic_interval.next().await {
        group.tx_rx(&client).await.expect("TX/RX");

        let (i, o) = slave.io();

        let (pos, status) = {
            let pos = u32::from_le_bytes(i[0..=3].try_into().unwrap());
            let status = u16::from_le_bytes(i[4..=5].try_into().unwrap());

            let status = unsafe { AkdStatusWord::from_bits_unchecked(status) };

            (pos, status)
        };

        println!("Position: {pos}, Status: {status:?} | {:?}", o);

        let (pos_cmd, _control) = o.split_at_mut(4);

        pos_cmd.copy_from_slice(&velocity.to_le_bytes());

        if velocity < 100_000_0 {
            velocity += 200;
        }
    }

    Ok(())
}

bitflags::bitflags! {
    /// AKD EtherCAT Communications Manual section 5.3.55
    struct AkdControlWord: u16 {
        /// Switch on
        const SWITCH_ON = 1 << 0;
        /// Disable Voltage
        const DISABLE_VOLTAGE = 1 << 1;
        /// Quick Stop
        const QUICK_STOP = 1 << 2;
        /// Enable Operation
        const ENABLE_OP = 1 << 3;
        /// Operation mode specific
        const OP_SPECIFIC_1 = 1 << 4;
        /// Operation mode specific
        const OP_SPECIFIC_2 = 1 << 5;
        /// Operation mode specific
        const OP_SPECIFIC_3 = 1 << 6;
        /// Reset Fault (only effective for faults)
        const RESET_FAULT = 1 << 7;
        /// Pause/halt
        const PAUSE = 1 << 8;

        const SHUTDOWN = Self::DISABLE_VOLTAGE.bits | Self::QUICK_STOP.bits;
    }
}

bitflags::bitflags! {
    /// AKD EtherCAT Communications Manual section   5.3.56
    struct AkdStatusWord: u16 {
        /// Ready to switch on
        const READY_TO_SWITCH_ON = 1 << 0;
        /// Switched on
        const SWITCHED_ON = 1 << 1;
        /// Operation enabled
        const OP_ENABLED = 1 << 2;
        /// Fault
        const FAULT = 1 << 3;
        /// Voltage enabled
        const VOLTAGE_ENABLED = 1 << 4;
        /// Quick stop
        const QUICK_STOP = 1 << 5;
        /// Switch on disabled
        const SWITCH_ON_DISABLED = 1 << 6;
        /// Warning
        const WARNING = 1 << 7;
        /// STO – Safe Torque Off
        const STO = 1 << 8;
        /// Remote
        const REMOTE = 1 << 9;
        /// Target reached
        const TARGET_REACHED = 1 << 10;
        /// Internal limit active
        const INTERNAL_LIMIT = 1 << 11;
        /// Operation mode specific (reserved)
        const OP_SPECIFIC_1 = 1 << 12;
        /// Operation mode specific (reserved)
        const OP_SPECIFIC_2 = 1 << 13;
        /// Manufacturer-specific (reserved)
        const MAN_SPECIFIC_1 = 1 << 14;
        /// Manufacturer-specific (reserved)
        const MAN_SPECIFIC_2 = 1 << 15;
    }
}

fn main() -> Result<(), Error> {
    env_logger::init();
    let local_ex = LocalExecutor::new();

    let ctrlc = CtrlC::new().expect("cannot create Ctrl+C handler?");

    futures_lite::future::block_on(
        local_ex.run(ctrlc.race(async { main_inner(&local_ex).await.unwrap() })),
    );

    Ok(())
}
