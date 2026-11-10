# LoopShield: Layered Sensor Spoofing Detection for Real-Time Controllers

Can a resource-constrained real-time controller detect sensor spoofing on its
communication link, at both the protocol and physical layers, without missing
its control deadlines?

```
 ┌──────────────┐ sg/sensor (signed, 100 ms) ┌─────────┐       ┌──────────┐        ┌───────────────────────┐
 │ plant (C#)   │──────────────────────────▶│ broker  │◀─────▶│ attacker │◀──────▶│ controller            │
 │ room+heater  │◀──────────────────────────│ :1884   │       │ proxy    │  :1883 │ ESP32 / FreeRTOS      │
 │ TRUE temp log│ sg/actuator               └─────────┘       │ (MITM)   │        │ in Wokwi              │
 └──────────────┘                                ▲            └──────────┘        │ PI @ 100 ms           │
                                                 │ sg/config, sg/telem, sg/stats  │ protocol checks       │
                                          ┌──────┴──────┐                         │ physics detector task │
                                          │ harness (C#)│                         └───────────────────────┘
                                          └─────────────┘
```

The controller always reaches the broker through the attacker's proxy. With no
attack running it is a transparent relay, so attacked and clean runs share
the same network path.

| Folder              | What                                                                   |
|---------------------|------------------------------------------------------------------------|
| `firmware/`         | ESP-IDF v6.1 controller: PI task, protocol checks, physics detector     |
| `firmware/test/`    | Host unit tests, closed-loop detector simulation, host stand-in controller |
| `plant/`            | Room simulator: signs readings, logs ground truth, optional disturbance |
| `attacker/`         | On-path MQTT proxy with five attack modes                               |
| `broker/`           | Local MQTT broker (MQTTnet), port 1884                                  |
| `harness/`          | Runs the attack × defense matrix unattended                             |
| `shared/`           | Wire format, HMAC, topics (mirrors `firmware/main/sg_msg.h`)            |
| `eval/`             | Analysis: matrix, plots, ROC, timing tables                             |
| `paper/`            | Write-up (LaTeX); tables and figures come from `eval/analyze.py`        |

## Defenses

Both layers are switched at runtime through `sg/config`, so one firmware image
covers every configuration.

- **Protocol layer** (MQTT task, on every sensor message): truncated
  HMAC-SHA256 (64 bit, PSA Crypto), strictly increasing sequence numbers, and a
  freshness check that needs no clock synchronization. It tracks the
  smallest local-minus-sender offset seen and rejects anything more than
  250 ms (+1 % drift) above it. An earlier "relative to the last message"
  version allowed an incremental-delay attack, which the protocol search found.
- **Physics layer** (its own task, each period): a model-based observer, a
  two-sided CUSUM on its innovation (k = 0.05, h = 4), and a slope invariant
  (the temperature can't change faster or slower than any heater duty and any
  ambient in [5, 25] °C allow). After an alarm, the controller regulates the
  model estimate instead of the sensor.
- **No fresh data for 5 periods** → the controller holds its output instead of
  integrating on stale readings.

## Wire format

Every message is 28 bytes, little-endian: version, type, flags, seq,
timestamp (ms), float value, and an 8-byte truncated HMAC. All fields are
present in every configuration, so enabling a defense changes only the
checking. Message size and parse cost stay the same.

## Setup (once)

```bash
echo 'export DOTNET_ROOT=/var/snap/dotnet/common/dotnet' >> ~/.bashrc   # snap .NET
python3 -m venv eval/.venv && eval/.venv/bin/pip install matplotlib numpy
```

## Build

```bash
dotnet build
. ~/.espressif/tools/activate_idf_v6.1.sh && idf.py -C firmware build
make -C firmware/test test        # protocol unit tests
```

## Run the full matrix

1. **Broker** (terminal 1): `broker/bin/Debug/net10.0/LoopShield.Broker`
2. **Controller**: VS Code → *Wokwi: Select Config File* → `firmware/wokwi.toml`
   → *Wokwi: Start Simulator*. Leave it running. The serial log should show
   `HMAC-SHA256/64 self-test passed`.
3. **Harness** (terminal 2):
   ```bash
   harness/bin/Debug/net10.0/LoopShield.Eval matrix --trials 3
   ```
   That's 7 scenarios × 4 configs × 3 trials = 84 runs of ~3 min, about 4.5 h.
   Use `--trials 1` for a first pass (~1.5 h). If you stop it with Ctrl+C,
   rerun with `--out runs/<session>` and it skips completed runs.
4. **Analyze**:
   ```bash
   eval/.venv/bin/python eval/analyze.py runs/<session> --out results/final
   ```
   This writes `matrix.md`, `matrix.tex`, `timing.tex`, `roc.png`,
   `temp_grid.png` and `timing.png` to `results/final/`.
5. **Paper**: `cd paper && latexmk -pdf loopshield.tex`

Single cells: `LoopShield.Eval single --attack replay --config both`.
Options: `--warmup 30 --attack-s 120 --recover 30 --k 0.05 --h 4 --no-mitigate
--bias -3 --ramp -0.01 --forge-value 18 --flood-rate 1000`.

### Attacks

| Mode      | What the controller sees                                                     |
|-----------|-------------------------------------------------------------------------------|
| `bias`    | every reading −3 °C (MAC no longer valid)                                     |
| `ramp`    | offset growing at −0.01 °C/s                                                  |
| `replay`  | 30 s of earlier genuine readings, looped, while the room really cools (ambient → 5 °C) |
| `forgery` | after each genuine reading, a fake 18 °C one with the next seq number and a random MAC |
| `flood`   | 1000 random sensor messages/s on top of genuine traffic                       |
| `disturb` | *not an attack*: ambient really drops to 5 °C, to measure false positives      |

Run any attack by hand: `attacker/bin/Debug/net10.0/LoopShield.Attacker --mode bias --start 30 --duration 60`
(start/stop are logged with Unix timestamps).

## Without Wokwi

`firmware/test/` lets you exercise everything except the ESP32 itself:

- `make -C firmware/test search` runs the protocol state-machine search
  (stretch goal). It explores attacker delivery sequences against the
  firmware's own checks for all 8 check combinations.
- `make -C firmware/test sim` runs a closed-loop simulation using the firmware's
  own detector and PI code, all attacks, in seconds.
  `build/sim --roc --ramp -0.005` sweeps the CUSUM threshold.
- `make -C firmware/test hostlib && dotnet build firmware/test/hostctl` builds
  a **host stand-in controller** that runs the firmware's C protocol and detector
  code behind the same MQTT interface. Start it instead of Wokwi to test the
  attacker, harness and analysis end to end. Its timing numbers are host
  numbers: never report them. `analyze.py` labels such sessions.
