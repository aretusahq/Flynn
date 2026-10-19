//! Process memory and CPU, as the iOS memory limit counts it.
//!
//! `phys_footprint` is the figure jetsam compares against an extension's
//! ceiling, so the harness reports it rather than RSS. The same call works
//! inside an iOS extension (M2).

#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    pub footprint: u64,
    pub peak_footprint: u64,
    pub cpu_secs: f64,
}

#[cfg(target_os = "macos")]
pub fn sample() -> Sample {
    // SAFETY: rusage_info_v4 is plain data; proc_pid_rusage fills it.
    let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            (&mut info as *mut libc::rusage_info_v4).cast::<libc::rusage_info_t>(),
        )
    };
    // SAFETY: rusage is plain data; getrusage fills it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let tv = |t: libc::timeval| t.tv_sec as f64 + f64::from(t.tv_usec) / 1e6;
    Sample {
        footprint: if rc == 0 { info.ri_phys_footprint } else { 0 },
        peak_footprint: if rc == 0 {
            info.ri_lifetime_max_phys_footprint
        } else {
            0
        },
        cpu_secs: tv(usage.ru_utime) + tv(usage.ru_stime),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn sample() -> Sample {
    Sample::default()
}
