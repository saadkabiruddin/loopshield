// LoopShield evaluation harness: runs the attack x defense matrix end to end.
//
// Prerequisites (left running): broker on 1884, the controller in Wokwi.
// For each run it:
//   1. starts the attacker proxy (always: in "none" mode it is a plain relay),
//      with the attack window fixed in advance in Unix time,
//   2. sends the defense configuration to the controller and waits for its ack
//      (this also resets the controller's PI, detector, protocol state, stats),
//   3. starts the plant at the setpoint (warm start) for warmup+attack+recover,
//   4. logs controller telemetry/stats next to the plant's ground truth.
//
//   LoopShield.Eval matrix [--trials 3] [--attacks bias,ramp] [--configs none,both]
//   LoopShield.Eval single --attack bias --config both
//
// Runs land in runs/<session>/<attack>__<config>__t<n>/ ; finished runs are
// skipped, so an interrupted session resumes with the same --out.
using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using MQTTnet;
using LoopShield.Shared;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

var opt = EvalOptions.Parse(args);
string root = FindRepoRoot();
string Exe(string project, string name) => Path.Combine(root, project, "bin", "Debug", "net10.0", OperatingSystem.IsWindows() ? name + ".exe" : name);
string attackerExe = Exe("attacker", "LoopShield.Attacker");
string plantExe = Exe("plant", "LoopShield.Plant");
foreach (var exe in new[] { attackerExe, plantExe })
{
    if (!File.Exists(exe)) Fail($"{exe} not found; run `dotnet build` first");
}

var configs = new Dictionary<string, string>
{
    ["none"] = "seq=0 fresh=0 mac=0 phys=0",
    ["proto"] = "seq=1 fresh=1 mac=1 phys=0",
    ["phys"] = "seq=0 fresh=0 mac=0 phys=1",
    ["both"] = "seq=1 fresh=1 mac=1 phys=1",
};
// "disturb" is not an attack: a real ambient drop (window opens) with no
// attacker, to measure false alarms on a legitimate change.
var attacks = new[] { "none", "bias", "ramp", "replay", "forgery", "flood", "disturb" };
foreach (var a in opt.Attacks) if (!attacks.Contains(a)) Fail($"unknown attack '{a}'");
foreach (var c in opt.Configs) if (!configs.ContainsKey(c)) Fail($"unknown config '{c}'");

var sessionDir = Path.GetFullPath(opt.Out ?? Path.Combine(root, "runs", "matrix-" + DateTime.Now.ToString("yyyyMMdd-HHmmss")));
Directory.CreateDirectory(sessionDir);
File.WriteAllText(Path.Combine(sessionDir, "session.json"), JsonSerializer.Serialize(opt, new JsonSerializerOptions { WriteIndented = true }));

var plan = new List<(int Trial, string Attack, string Config)>();
for (int t = 1; t <= opt.Trials; t++)
    foreach (var a in opt.Attacks)
        foreach (var c in opt.Configs)
            plan.Add((t, a, c));

double runS = opt.WarmupS + opt.AttackS + opt.RecoverS + LeadMs / 1000.0 + 3;
Console.WriteLine($"session {sessionDir}");
Console.WriteLine($"{plan.Count} runs x ~{runS:F0} s = ~{plan.Count * runS / 3600:F1} h");

// ---- MQTT: one client for the whole session ------------------------------

var current = new RunState();     // swapped per run
var factory = new MqttClientFactory();
using var mqtt = factory.CreateMqttClient();
mqtt.ApplicationMessageReceivedAsync += e =>
{
    var topic = e.ApplicationMessage.Topic;
    var text = Encoding.UTF8.GetString(e.ApplicationMessage.Payload.ToArray());
    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    var run = current;
    if (topic == Topics.ConfigAck) run.OnAck(text);
    else if (topic == Topics.Telemetry) run.OnTelemetry(now, text);
    else if (topic == Topics.Stats) run.OnStats(text);
    return Task.CompletedTask;
};
try
{
    await mqtt.ConnectAsync(new MqttClientOptionsBuilder()
        .WithTcpServer("localhost", Ports.Broker).WithClientId("sg-harness").Build());
}
catch (Exception ex)
{
    Fail($"cannot reach the broker on localhost:{Ports.Broker} ({ex.Message}). Start broker/ first.");
}
await mqtt.SubscribeAsync(factory.CreateSubscribeOptionsBuilder()
    .WithTopicFilter(Topics.ConfigAck).WithTopicFilter(Topics.Telemetry).WithTopicFilter(Topics.Stats).Build());

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Console.WriteLine("\nstopping after cleanup..."); };

int done = 0;
foreach (var (trial, attack, config) in plan)
{
    if (cts.IsCancellationRequested) break;
    done++;
    var name = $"{attack}__{config}__t{trial}";
    var dir = Path.Combine(sessionDir, name);
    if (File.Exists(Path.Combine(dir, "run.json")) &&
        JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "run.json"))).RootElement.GetProperty("complete").GetBoolean())
    {
        Console.WriteLine($"[{done}/{plan.Count}] {name}: already complete, skipping");
        continue;
    }

    bool ok = false;
    for (int attempt = 1; attempt <= 3 && !ok && !cts.IsCancellationRequested; attempt++)
    {
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
        Directory.CreateDirectory(dir);
        Console.Write($"[{done}/{plan.Count}] {name}{(attempt > 1 ? $" (attempt {attempt})" : "")}: ");
        ok = await RunOne(dir, trial, attack, config, cts.Token);
    }
    if (!ok && !cts.IsCancellationRequested)
    {
        Console.WriteLine("  giving up on this run (controller not responding?)");
    }
}

await mqtt.DisconnectAsync();
Console.WriteLine($"\nsession finished: {sessionDir}");
Console.WriteLine($"analyse with: eval/.venv/bin/python eval/analyze.py {Path.GetRelativePath(root, sessionDir)}");
return;

// ---------------------------------------------------------------------------

async Task<bool> RunOne(string dir, int trial, string attack, string config, CancellationToken ct)
{
    uint runId = (uint)(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 100 % 1_000_000_000);
    long t0 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    long plantStart = t0 + LeadMs;
    long attackStart = plantStart + (long)(opt.WarmupS * 1000);
    long attackStop = attackStart + (long)(opt.AttackS * 1000);
    double total = opt.WarmupS + opt.AttackS + opt.RecoverS;
    double integ0 = (opt.Setpoint - opt.TAmb) / opt.Gain;   // steady-state duty: bumpless warm start
    bool disturb = attack is "replay" or "disturb";
    int seed = trial;

    var run = new RunState(dir, runId);
    current = run;

    string attackerMode = attack == "disturb" ? "none" : attack;
    var attacker = Launch(attackerExe, dir, "attacker.log",
        "--mode", attackerMode, "--start-unix", attackStart.ToString(), "--duration", opt.AttackS.ToString(),
        "--bias", opt.Bias.ToString(), "--ramp", opt.Ramp.ToString(), "--record", opt.RecordS.ToString(),
        "--forge-value", opt.ForgeValue.ToString(), "--flood-rate", opt.FloodRate.ToString(),
        "--seed", (100 + trial).ToString(), "--log", Path.Combine(dir, "attack.jsonl"));

    string cfg = $"run={runId} {configs[config]} mitigate={(opt.Mitigate ? 1 : 0)} " +
                 $"k={opt.CusumK} h={opt.CusumH} integ={integ0:F4}";

    // The controller reconnects through the new proxy within ~1 s; keep
    // sending the config until it acknowledges this run id.
    while (!run.Acked && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < plantStart - 500 && !ct.IsCancellationRequested)
    {
        await mqtt.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(Topics.Config)
            .WithPayload(cfg).WithQualityOfServiceLevel(MQTTnet.Protocol.MqttQualityOfServiceLevel.AtLeastOnce).Build(), ct);
        await Task.Delay(700, ct).ContinueWith(_ => { });
    }
    if (!run.Acked)
    {
        Kill(attacker);
        run.Close();
        Console.WriteLine("no config ack from the controller");
        return false;
    }

    await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(0, plantStart - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())), ct)
        .ContinueWith(_ => { });
    var plantArgs = new List<string>
    {
        "--t0", opt.Setpoint.ToString(), "--u0", integ0.ToString("F4"), "--tamb", opt.TAmb.ToString(),
        "--duration", total.ToString(), "--seed", seed.ToString(), "--run-dir", dir, "--quiet",
    };
    if (disturb) plantArgs.AddRange(["--dist-at", (opt.WarmupS + 10).ToString(), "--dist-tamb", opt.DistTAmb.ToString()]);
    long plantLaunch = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    var plant = Launch(plantExe, dir, "plant.log", [.. plantArgs]);

    var sw = Stopwatch.StartNew();
    while (!plant.HasExited && !ct.IsCancellationRequested)
    {
        await Task.Delay(1000, ct).ContinueWith(_ => { });
        if (sw.Elapsed.TotalSeconds > total + 30) { Kill(plant); break; }
        Console.Write($"\r[{done}/{plan.Count}] {attack}__{config}__t{trial}: {sw.Elapsed.TotalSeconds,4:F0}/{total:F0} s  ");
    }
    if (ct.IsCancellationRequested) Kill(plant);
    await Task.Delay(1500).ContinueWith(_ => { });   // last telemetry
    Kill(attacker);
    run.Close();

    var meta = new
    {
        complete = !ct.IsCancellationRequested && plant.HasExited && plant.ExitCode == 0,
        attack, config, trial, seed, run_id = runId, controller_config = cfg,
        ack = run.AckText,
        plant_launch_unix_ms = plantLaunch,
        attack_start_unix_ms = attack is "none" or "disturb" ? (long?)null : attackStart,
        attack_stop_unix_ms = attack is "none" or "disturb" ? (long?)null : attackStop,
        disturbance_at_s = disturb ? opt.WarmupS + 10 : (double?)null,
        warmup_s = opt.WarmupS, attack_s = opt.AttackS, recover_s = opt.RecoverS,
        setpoint = opt.Setpoint, mitigate = opt.Mitigate, cusum_k = opt.CusumK, cusum_h = opt.CusumH,
        telemetry_rows = run.TelemetryRows,
    };
    File.WriteAllText(Path.Combine(dir, "run.json"), JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"\r[{done}/{plan.Count}] {attack}__{config}__t{trial}: {(meta.complete ? "done" : "INCOMPLETE")}, " +
                      $"{run.TelemetryRows} telemetry rows                ");
    return meta.complete;
}

Process Launch(string exe, string dir, string logName, params string[] a)
{
    var psi = new ProcessStartInfo(exe)
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        WorkingDirectory = root,
    };
    foreach (var x in a) psi.ArgumentList.Add(x);
    // Snap-installed .NET does not tell apphosts where the runtime is.
    if (Environment.GetEnvironmentVariable("DOTNET_ROOT") is null && Directory.Exists("/var/snap/dotnet/common/dotnet"))
        psi.Environment["DOTNET_ROOT"] = "/var/snap/dotnet/common/dotnet";

    var p = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {exe}");
    var log = new StreamWriter(Path.Combine(dir, logName)) { AutoFlush = true };
    p.OutputDataReceived += (_, e) => { if (e.Data != null) lock (log) log.WriteLine(e.Data); };
    p.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (log) log.WriteLine(e.Data); };
    p.BeginOutputReadLine();
    p.BeginErrorReadLine();
    p.Exited += (_, _) => { lock (log) log.Dispose(); };
    p.EnableRaisingEvents = true;
    return p;
}

static void Kill(Process p)
{
    try { if (!p.HasExited) { p.Kill(entireProcessTree: true); p.WaitForExit(3000); } }
    catch (InvalidOperationException) { }
}

static string FindRepoRoot()
{
    foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
    {
        for (var d = new DirectoryInfo(start); d != null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "loopshield.slnx"))) return d.FullName;
    }
    Fail("cannot find the repo root (loopshield.slnx)");
    return "";
}

[System.Diagnostics.CodeAnalysis.DoesNotReturn]
static void Fail(string msg)
{
    Console.Error.WriteLine("error: " + msg);
    Environment.Exit(1);
}

partial class Program
{
    /// <summary>Time from launching the attacker to starting the plant: covers
    /// the controller's reconnect through the new proxy and the config ack.</summary>
    const long LeadMs = 8000;
}

sealed class RunState
{
    private readonly StreamWriter? _telem, _stats;
    private readonly uint _runId;
    private readonly object _lock = new();
    public volatile bool Acked;
    public string? AckText;
    public int TelemetryRows;

    public RunState() { }

    public RunState(string dir, uint runId)
    {
        _runId = runId;
        _telem = new StreamWriter(Path.Combine(dir, "telem.csv"));
        _telem.WriteLine("host_unix_ms," + Telemetry.Columns);
        _stats = new StreamWriter(Path.Combine(dir, "stats.jsonl"));
    }

    public void OnAck(string text)
    {
        if (text.StartsWith($"run={_runId} ")) { AckText = text; Acked = true; }
    }

    /// <summary>One sg/telem message carries one or more rows (the firmware
    /// batches ten per message).</summary>
    public void OnTelemetry(long hostMs, string payload)
    {
        if (!Acked || _telem is null) return;
        lock (_lock)
        {
            foreach (var line in payload.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                _telem.Write(hostMs);
                _telem.Write(',');
                _telem.WriteLine(line.TrimEnd('\r'));
                TelemetryRows++;
            }
        }
    }

    public void OnStats(string json)
    {
        if (_stats is null || !json.Contains($"\"run\":{_runId},")) return;
        lock (_lock) { _stats.WriteLine(json); _stats.Flush(); }
    }

    public void Close()
    {
        lock (_lock) { _telem?.Dispose(); _stats?.Dispose(); }
    }
}

record EvalOptions(string Command, int Trials, string[] Attacks, string[] Configs,
                   double WarmupS, double AttackS, double RecoverS,
                   double Setpoint, double TAmb, double Gain, double DistTAmb,
                   bool Mitigate, double CusumK, double CusumH,
                   double Bias, double Ramp, double RecordS, double ForgeValue, double FloodRate,
                   string? Out)
{
    public static EvalOptions Parse(string[] a)
    {
        if (a.Length == 0 || a[0] is not ("matrix" or "single"))
        {
            Console.Error.WriteLine("usage: LoopShield.Eval matrix [--trials N] [--attacks a,b] [--configs c,d] [--out DIR]");
            Console.Error.WriteLine("       LoopShield.Eval single --attack ATTACK --config CONFIG [--out DIR]");
            Console.Error.WriteLine("attacks: none bias ramp replay forgery flood disturb   configs: none proto phys both");
            Console.Error.WriteLine("timing:  --warmup 30 --attack 120 --recover 30   detector: --k 0.05 --h 4 --no-mitigate");
            Environment.Exit(2);
        }
        string? Get(string key)
        {
            int i = Array.IndexOf(a, key);
            return i >= 0 && i + 1 < a.Length ? a[i + 1] : null;
        }
        double D(string k, double d) => Get(k) is { } s ? double.Parse(s, CultureInfo.InvariantCulture) : d;
        string[] L(string k, string d) => (Get(k) ?? d).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        bool single = a[0] == "single";
        return new EvalOptions(
            Command: a[0],
            Trials: single ? 1 : (int)D("--trials", 3),
            Attacks: single ? [Get("--attack") ?? "none"] : L("--attacks", "none,bias,ramp,replay,forgery,flood,disturb"),
            Configs: single ? [Get("--config") ?? "none"] : L("--configs", "none,proto,phys,both"),
            WarmupS: D("--warmup", 30), AttackS: D("--attack-s", 120), RecoverS: D("--recover", 30),
            Setpoint: 22, TAmb: 15, Gain: 20, DistTAmb: D("--dist-tamb", 5),
            Mitigate: !a.Contains("--no-mitigate"), CusumK: D("--k", 0.05), CusumH: D("--h", 4),
            Bias: D("--bias", -3), Ramp: D("--ramp", -0.01), RecordS: D("--record", 30),
            ForgeValue: D("--forge-value", 18), FloodRate: D("--flood-rate", 1000),
            Out: Get("--out"));
    }
}
