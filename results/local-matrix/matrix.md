# Attack × defense matrix

Session: `matrix-20261110-231635`

> **Host stand-in controller data.** Detection and deviation reflect the real
> defense code, but timing numbers are from the host, not the ESP32.

Each cell: detection rate · mean time-to-detect · worst true-temperature
deviation from the setpoint · false-positive rate (runs with a pre-attack alarm).

| Attack | No defense | Protocol | Physics | Both |
|---|---|---|---|---|
| No attack | FP 0% · dev 0.02°C | FP 0% · dev 0.02°C | FP 0% · dev 0.02°C | FP 0% · dev 0.02°C |
| Bias | 0% · TTD – · dev 2.94°C · FP 0% | 100% · TTD 0.1 s · dev 0.29°C · FP 0% | 100% · TTD 0.2 s · dev 0.04°C · FP 0% | 100% · TTD 0.1 s · dev 0.18°C · FP 0% |
| Slow ramp | 0% · TTD – · dev 1.12°C · FP 0% | 100% · TTD 0.1 s · dev 0.13°C · FP 0% | 100% · TTD 18.8 s · dev 0.13°C · FP 0% | 100% · TTD 0.2 s · dev 0.12°C · FP 0% |
| Replay | 0% · TTD – · dev 8.41°C · FP 0% | 100% · TTD 0.2 s · dev 8.93°C · FP 0% | 0% · TTD – · dev 8.98°C · FP 0% | 100% · TTD 0.1 s · dev 9.00°C · FP 0% |
| Forgery | 0% · TTD – · dev 11.24°C · FP 0% | 100% · TTD 0.1 s · dev 0.01°C · FP 0% | 100% · TTD 0.3 s · dev 0.06°C · FP 0% | 100% · TTD 0.1 s · dev 0.02°C · FP 0% |
| Flooding | 0% · TTD – · dev 0.75°C · FP 0% | 100% · TTD 0.1 s · dev 0.02°C · FP 0% |  | 100% · TTD 0.0 s · dev 0.01°C · FP 0% |
| Disturbance* | FP 0% · dev 0.80°C | FP 0% · dev 0.81°C | FP 100% · dev 9.03°C | FP 100% · dev 9.03°C |

\* Disturbance is not an attack: the ambient temperature really drops (a window opens). Any alarm there is a false positive.

## Real-time cost under each attack (mean over trials, attack window)

| Attack | Config | ctl exec mean/max (µs) | ctl resp max (µs) | detector mean (µs) | proto check mean (µs/msg) | msgs/s | proto CPU % | deadline misses |
|---|---|---|---|---|---|---|---|---|
| No attack | No defense | 12.2 / 231 | 24003 | 1.0 | 26.9 | 7 | 0.02 | 0 |
| No attack | Protocol | 12.8 / 263 | 26859 | 0.6 | 28.1 | 7 | 0.02 | 0 |
| No attack | Physics | 11.0 / 193 | 22996 | 2.8 | 21.1 | 7 | 0.01 | 0 |
| No attack | Both | 11.8 / 157 | 24537 | 3.4 | 27.0 | 6 | 0.02 | 0 |
| Bias | No defense | 10.3 / 163 | 27069 | 0.5 | 20.3 | 6 | 0.01 | 0 |
| Bias | Protocol | 11.7 / 290 | 22559 | 0.7 | 27.7 | 6 | 0.02 | 0 |
| Bias | Physics | 14.1 / 197 | 27535 | 3.3 | 27.8 | 6 | 0.02 | 0 |
| Bias | Both | 11.4 / 252 | 27779 | 2.6 | 27.4 | 6 | 0.02 | 0 |
| Slow ramp | No defense | 12.8 / 147 | 26996 | 0.6 | 27.8 | 6 | 0.02 | 0 |
| Slow ramp | Protocol | 11.5 / 294 | 27829 | 0.6 | 27.3 | 6 | 0.02 | 0 |
| Slow ramp | Physics | 15.3 / 331 | 27879 | 3.6 | 28.4 | 6 | 0.02 | 0 |
| Slow ramp | Both | 15.1 / 275 | 15065 | 2.7 | 30.7 | 6 | 0.02 | 0 |
| Replay | No defense | 15.6 / 191 | 26839 | 0.8 | 31.0 | 6 | 0.02 | 0 |
| Replay | Protocol | 11.5 / 257 | 26794 | 0.6 | 27.1 | 6 | 0.02 | 0 |
| Replay | Physics | 10.9 / 364 | 15688 | 2.5 | 18.2 | 6 | 0.01 | 0 |
| Replay | Both | 12.5 / 293 | 28668 | 2.6 | 27.0 | 6 | 0.02 | 0 |
| Forgery | No defense | 13.9 / 265 | 28122 | 0.7 | 16.4 | 13 | 0.02 | 0 |
| Forgery | Protocol | 13.7 / 218 | 23011 | 0.8 | 16.2 | 13 | 0.02 | 0 |
| Forgery | Physics | 14.0 / 190 | 22395 | 3.4 | 16.8 | 13 | 0.02 | 0 |
| Forgery | Both | 13.7 / 304 | 26902 | 3.4 | 16.4 | 13 | 0.02 | 0 |
| Flooding | No defense | 13.0 / 213 | 26920 | 0.6 | 8.9 | 657 | 0.58 | 0 |
| Flooding | Protocol | 12.6 / 215 | 28293 | 0.7 | 8.6 | 655 | 0.57 | 0 |
| Flooding | Both | 9.5 / 301 | 4294988753 | 2.6 | 5.5 | 652 | 0.36 | 1863 |
| Disturbance* | No defense | 13.8 / 447 | 4294989203 | 0.6 | 27.5 | 6 | 0.02 | 1853 |
| Disturbance* | Protocol | 14.1 / 294 | 4294989447 | 0.7 | 27.8 | 6 | 0.02 | 1859 |
| Disturbance* | Physics | 15.4 / 240 | 4294995271 | 4.3 | 28.6 | 6 | 0.02 | 1853 |
| Disturbance* | Both | 14.8 / 350 | 4294993349 | 3.4 | 25.9 | 7 | 0.02 | 1860 |
