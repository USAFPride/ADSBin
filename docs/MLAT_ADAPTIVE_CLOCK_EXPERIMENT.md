# Experiment: calibrate Beast timestamps against observed USB IQ throughput

This is a **diagnostic clock model**, not an implementation of reliable MLAT.
It extends PR #18's sample-count clock. It is deliberately a separate branch
and is OFF by default.

## Enablement

Build ESP-IDF 6.0.3 with:

```
CONFIG_ADSBIN_MLAT_EXPERIMENTAL=y
CONFIG_ADSBIN_MLAT_CALIBRATE_THROUGHPUT=y
```

The second option requires the first. When the calibration option is OFF,
PR #18's fixed-rate timestamp logic is preserved. When both are OFF, normal
zero-timestamp Beast output is preserved.

## Algorithm

- Per RTL-SDR device, track the number of received IQ pairs across USB
  completions, including data dropped downstream by the demodulation ring.
- Every ~10 seconds of monotonic ESP time, calculate received samples / elapsed
  wall time, bounded to 1.5–2.1 MS/s to reject unusable windows.
- First valid window seeds the rate. Subsequent valid windows use an exponential
  moving average with alpha = 1/4.
- Convert each block's first sample index to Beast 12 MHz ticks using a
  piecewise-linear clock. **At each rate change, re-anchor at the current
  sample count using the old rate first**, so timestamps do not jump.
- Snapshot calibrated block timestamp and rate in the IQ ring item. Each
  decoded preamble adds its sample offset using the same rate snapshot.
- The first ~10 seconds produce zero-timestamp Beast output (rate not ready).
  Known USB transfer faults continue to disable timestamp output.
- ESP serial diagnostics report `CAL_SPS=` beside `SPS=` every 10 seconds.

## Validation

Keep DietPi production Ultrafeeder at 30004 untouched. Connect the ESP to a
separate Beast listener at port 30014. The listener must actually be active
before enabling forwarding; connection retries after it exits are expected.

1. Build and flash this branch with both options ON. Check for nonzero
   timestamps after the first calibration interval.
2. Run the existing five-minute Beast-vs-monotonic-clock test on DietPi.
   Compare with the uncalibrated PR #18 baseline:
   - Frame count around 550 (traffic dependent)
   - Zero timestamps: 0 after warmup
   - Backward timestamps: 0
   - Clock error: previously -10.4556%
   - Clock drift: previously -31.358 s over 299.920 s
3. Observe `SPS=` and `CAL_SPS=` in serial diagnostics. The calibrated rate
   should settle near the measured ~1.745–1.854 MS/s range.
4. Repeat five-minute tests under different aircraft loads, and inspect
   shorter-interval timing errors. A low *average* drift does not establish
   MLAT-quality short-term time-of-arrival accuracy.
5. Force or observe a USB stream fault; verify subsequent Beast timestamps are
   zero and the receiver does not silently claim timing recovery.

## Failure modes and limitations

The RTL2832U normally samples from its own hardware oscillator. The rate at
which USB transfers reach the ESP32 is **not necessarily that oscillator rate**.
If RF samples are lost in the SDR FIFO, using USB throughput as a clock can
mask the average number of missing samples while giving **wrong timestamps
for individual aircraft messages**. USB callback buffering and scheduling also
add jitter. This experiment makes no attempt to infer lost samples or qualify
a clock after an invisible FIFO overflow.

Do NOT enable production FlightAware MLAT based on drift improvement alone.
If this experiment reduces five-minute drift but does not stabilize short-term
arrival times, abandon this clock model and retain the standard ADS-B receiver.
