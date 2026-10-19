//! Process memory and CPU, measured the way the iOS memory limit counts.
//!
//! `phys_footprint` from `task_info(TASK_VM_INFO)` is the figure jetsam
//! compares against an extension's ceiling, so that is what Flynn reports,
//! not RSS. Public API on both iOS and macOS.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemSample {
    /// Current physical footprint, bytes.
    pub footprint: u64,
    /// Highest footprint over the process lifetime, bytes.
    pub peak_footprint: u64,
    /// User plus system CPU time, milliseconds.
    pub cpu_ms: u64,
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple {
    /// `struct task_vm_info` from <mach/task_info.h>, through revision 3.
    /// The header packs it to 4 bytes.
    #[repr(C, packed(4))]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
        min_address: u64,
        max_address: u64,
        ledger_phys_footprint_peak: i64,
    }

    const TASK_VM_INFO: i32 = 22;

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn task_info(task: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    }

    pub(super) fn footprint() -> Option<(u64, u64)> {
        let mut info = TaskVmInfo::default();
        let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
        // SAFETY: `info` is a buffer of `count` 32-bit words, as task_info expects.
        let rc = unsafe {
            task_info(
                mach_task_self_,
                TASK_VM_INFO,
                (&mut info as *mut TaskVmInfo).cast(),
                &mut count,
            )
        };
        if rc != 0 {
            return None;
        }
        let current = info.phys_footprint;
        let peak = info.ledger_phys_footprint_peak;
        Some((current, if peak > 0 { peak as u64 } else { current }))
    }
}

#[cfg(unix)]
fn cpu_ms() -> u64 {
    // SAFETY: rusage is plain data; getrusage fills it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let ms = |t: libc::timeval| t.tv_sec as u64 * 1000 + t.tv_usec as u64 / 1000;
    ms(usage.ru_utime) + ms(usage.ru_stime)
}

pub fn sample() -> MemSample {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    let (footprint, peak_footprint) = apple::footprint().unwrap_or_default();
    // Android reads /proc/self/status in Phase 2.
    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    let (footprint, peak_footprint) = (0, 0);
    MemSample {
        footprint,
        peak_footprint,
        cpu_ms: cpu_ms(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn reports_a_plausible_footprint() {
        let s = super::sample();
        assert!(
            s.footprint > 64 * 1024,
            "footprint {} too small",
            s.footprint
        );
        assert!(s.peak_footprint >= s.footprint);
    }
}
