# MLAT sample-clock development (experimental)

The receiver now tracks a 64-bit IQ sample index for the 1090 MHz SDR.
Each detected preamble carries its sample index through demodulation to Beast
TCP output as a 48-bit, big-endian, 12 MHz counter.

At 2,000,000 IQ pairs/s, one sample corresponds to six Beast clock ticks.
This avoids using variable-latency USB completion times as arrival timestamps.

## Safety and enablement

The feature is **off by default**: `CONFIG_ADSBIN_MLAT_EXPERIMENTAL=n`.
With the option disabled, Beast timestamps remain zero exactly as before.
Enable it only in a throwaway test build using `idf.py menuconfig`:
Remote ADS-B receiver -> EXPERIMENTAL Beast 12 MHz sample timestamps.

The counter is per SDR device. It counts complete IQ pairs received, including
pairs delivered by USB when the downstream IQ ring is full. A USB transfer
failure, cancellation, device loss, or resubmit failure latches clock validity
false. Subsequent output reverts to zero timestamp until reboot.

**Known limitation:** RTL2832U bulk USB does not provide a trustworthy hardware
timestamp or a count of samples lost inside the SDR FIFO. Even with no
reported USB errors, an invisible FIFO overflow or out-of-order transfer
completion can disrupt the relation between sample count and RF arrival time.
The project has previously measured lower-than-nominal effective USB rates.
Thus nonzero Beast timestamps do **not** prove MLAT accuracy or eligibility.

Additionally, the demodulator does not presently join frames split across IQ
block boundaries, which can reduce Mode S reception. That is not solved here.

## Validation gates before enabling PiAware MLAT

1. Confirm unchanged ADS-B and Beast counts versus the proven main firmware.
2. Verify that the timestamp increments between decoded frames correspond
   approximately to the physical time between messages (12 million ticks/sec).
   Do not compare USB callback timestamps.
3. Test high-traffic reception for USB transfer errors, restreams, ring drops,
   and sustained sample throughput. Nominal 2 MS/s USB throughput is required
   for an unbroken sample timeline, but even matching throughput is not proof.
4. Force a USB stream fault and verify the transmitted Beast timestamp becomes
   zero; reconnection should not silently requalify the clock.
5. Only after hardware tests, enable MLAT on a separate DietPi TEST feeder
   and inspect the MLAT client clock tracking and synchronization logs.
   Never re-enable MLAT on production just because Beast timestamps are nonzero.

Do not merge or enable this experimental option without a successful
ESP-IDF build, hardware timing validation, and MLAT synchronization evidence.
