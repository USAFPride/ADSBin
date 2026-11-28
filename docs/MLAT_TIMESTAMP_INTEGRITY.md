# MLAT timestamp-integrity investigation (diagnostics only)

Branch: `diagnostics/mlat-timestamp-integrity-20261128`, based on the unmerged adaptive-clock PR #19. **No production deployment or MLAT qualification.**

## Findings from the running experiment, 2026-11-27/28

- Experimental PiAware reports Beast input with a 12 MHz clock, accepted aircraft messages, and a connected MLAT client.
- FlightAware server reports `not synchronized with any nearby receivers` throughout the captured 15-minute status intervals, including when 8/8 Mode S and 7/7 ADS-B aircraft were used.
- A separate Python Beast bridge stalled and interrupted feeding around 09:05–09:17 EST on Nov 28. Exclude this interval and subsequent reconnect warmup from timestamp/MLAT conclusions.
- The 5-minute calibrated clock drift was -0.0146% (-44 ms / 300 s); 10-minute drift was +0.01545% (+92.6 ms / 599.5 s). These measurements **cannot** certify per-frame time of arrival.
- 1-second arrival-time comparisons on DietPi showed tens of milliseconds of spread. Network and host buffering contaminate those observations; they do **not** measure RF timestamp jitter.

## Source-level audit

`components/usb_rtlsdr/usb_rtlsdr.c`:

1. `rtl_set_sample_rate()` programs the resampler for the requested rate. Confirm the actual programmed ratio and the SDR oscillator model. Do not confuse requested SDR ADC output sample rate with rate of samples *delivered over USB*.
2. `bulk_in_cb()` increments `mlat_sample_index` by IQ pairs present in each completed USB transfer (even if the software demod ring later overflows). This preserves ordering of *received* pairs, but cannot detect pairs silently lost upstream in the RTL-SDR hardware FIFO.
3. `mlat_cal_update()` observes USB-delivered IQ pairs divided by ESP monotonic wall time over 10-second windows, then EMA-filters the result (alpha 1/4).
4. `mlat_cal_delta_ticks()` divides sample index differences by the USB-delivered rate and multiplies by the Beast 12 MHz clock. Rate changes reanchor without timestamp jumps, but **continuity of the computed clock is not proof that missing hardware samples were accounted for**.
5. At nominal 2,000,000 samples/s, 1 sample = 6 Beast ticks = 0.5 microseconds. At an inferred 1,794,000 samples/s, 1 received sample is instead assigned about 6.69 ticks. If the SDR hardware genuinely samples at 2 MS/s but discards unseen samples, treating the received stream as continuous at 1.794 MS/s assigns incorrect timestamps to individual messages.
6. USB callbacks are asynchronous and include scheduling delay. Do not substitute their arrival times as aircraft RF times.

## Investigation order

### A. Verify feed health independently of MLAT

Confirm at the same instant: ESP Beast TCP connected; bridge upstream/downstream single established connection each; experimental `dump1090-fa` recent valid messages and aircraft > 0; PiAware messages sent incrementing; FlightAware site is the **experimental** site. If bridge has multiple upstream connections or growing TCP Recv-Q, stop interpreting MLAT status until bridge is corrected. Never alter production Ultrafeeder/PiAware/FR24 or port 30004.

### B. Quantify physical timing assumptions without changing the clock

From serial diagnostics, log 10-second `SPS`, `CAL_SPS`, USB URB input bytes and short-transfer/stall/drop counters. Compare to the actual RTL2832U programmed output rate. A throughput deficit may indicate loss or pacing, not oscillator error. The separate mismatch between ~1.79 MS/s delivered and 2.00 MS/s configured is *too large to attribute to ordinary oscillator tolerance*.

### C. Test continuity and short-timescale behavior

Use a nonintrusive **single** Beast consumer / tee on the experimental pipeline. Decode escaped Beast frames and inspect strictly monotonic timestamps, zero-timestamp periods, large discontinuities, wrap, duplicate timestamps and elapsed Beast ticks over short intervals (1, 5, 10, 30 seconds). Compare to host arrival time **only as an end-to-end buffering indicator**, never as ground-truth RF accuracy. Ensure the test instrumentation doesn't replace PiAware as the bridge's sole downstream client.

### D. Obtain an independent same-signal timing reference

The actual MLAT timing test requires the same live RF events captured by a known-good independent receiver at the same antenna, using a properly split RF signal or controlled switched-A/B experiments. Compare by ICAO plus identical Mode S payload and event ordering; compensate constant receiver clock offset and oscillator slope before examining per-message residuals. Report median, p95, p99, max absolute residual, drift per minute and discontinuity count. Separate network delivery time from Beast RF timestamp.

### E. Instrument loss and invalidation

Record USB URB sequence, short transfer, scheduler gap distribution, IQ FIFO/RTL loss indicators if available, DSP/ring drops, sample-clock invalid transitions, calibration rate changes, and timestamp generation for each tested frame. For known observable loss, make the clock invalid instead of silently continuing. Invisible SDR FIFO loss may make the present architecture incapable of qualified MLAT, regardless of average drift.

## Acceptance / decision criteria

- The experimental FlightAware MLAT client must *directly* report sustained synchronization and continued contributions, not only the website's green label.
- The bridge must run without reconnect accumulation and feeding gaps during the evaluation interval.
- Recorded timestamp residuals must be evaluated against a simultaneous, independent RF reference; acceptable error tolerance must be established for the actual MLAT network before declaring success.
- If USB delivery cannot preserve all sample intervals or reveal dropped hardware samples, stop using throughput-derived sample time for MLAT, even if it shows good average drift.

## Next actions

1. Capture fresh read-only serial and experimental PiAware health logs with the antenna fixed.
2. Repair the **experimental-only** bridge's connection handling before another overnight test.
3. Add optional diagnostic counters / trace sampling on this branch; avoid modifying decoder behavior or timestamps until source-level evidence identifies the cause.
4. Design a simultaneous common-RF comparison against a known-good receiver. Do not use Wi-Fi TCP arrival times as RF ground truth.

## USB transfer-pipeline instrumented build (PR #22)

The source implementation keeps the existing single-submitted-URB behavior, IQ ring handling, adaptive MLAT clock, and Beast forwarding unchanged. An optional trace line is emitted once per existing 10-second `usb_cbtime` report:

```
usb_pipeline: slot=0 active_min=1 active_max=1 wait_avg_us=... wait_max_us=... wait_n=... callback_avg_us=... callback_max_us=... callback_n=... full=... short=... status_other=...
```

Definitions:

- `active_min/max`: number of submitted USB URBs observed at callback entry. An allocated pool of 8 does **not** mean 8 were submitted; `submit_urbs()` currently submits just 1.
- `wait_avg/max_us`: wall-clock delay from successful transfer submit returning to the next USB completion callback entry. Includes USB fill time, host controller servicing, task scheduling; not an RF timestamp.
- `callback_avg/max_us`: callback entry until the current transfer's resubmit call returns; includes the existing IQ copy, statistics lock, and submit overhead.
- `full/short`: number of completed URBs matching/falling below the configured transfer size during this 10-second interval.
- `status_other`: completion statuses outside COMPLETED, NO_DEVICE, STALL, CANCELED.
- The sum of wait and callback times should approximately match the existing callback-entry spacing in normal, single-URB continuous operation; differing sample counts, first intervals and scheduling may cause small discrepancies.

**Testing**: Build on Windows in ESP-IDF v6.0.3 on a clean copy of this diagnostic branch, check `CONFIG_ADSBIN_MLAT_EXPERIMENTAL` and `CONFIG_ADSBIN_MLAT_CALIBRATE_THROUGHPUT` explicitly, flash on COM5 without erasing NVS, and collect 2 minutes of `usb_pipeline`, `usb_cbtime`, `usb_perf`, `rf_diag` counters. The firmware adds no changes to the SDR sample rate, URB count, stream callbacks, time conversion, or MLAT enablement settings. An ESP reboot/flash interrupts experimental feeding; do not interrupt a valuable ongoing measurement.

**Limits**: These counters can locate host-side delays or underutilization but cannot, by themselves, prove whether the RTL2832U lost IQ samples internally. No instrumented build has yet been compiled/flashed/tested on the board.
