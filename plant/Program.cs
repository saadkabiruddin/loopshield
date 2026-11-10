// LoopShield plant simulator: a single room with a heater.
//
//   dT/dt = ((T_amb - T) + K * u) / tau
//
// u is the heater duty (0..1) last received from the controller. The plant
// publishes a signed sensor reading (true temperature + Gaussian noise) on
// sg/sensor every 100 ms and logs the TRUE temperature, which the attacker
// can never touch, so every run has ground truth for evaluation.
//
// It always signs (HMAC) and stamps seq/time; whether the controller checks
// those is the controller's configuration, not the plant's.
using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using MQTTnet;
using LoopShield.Shared;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
var opt = Options.Parse(args);

var runDir = opt.RunDir ?? Path.Combine("runs", DateTime.Now.ToString("yyyyMMdd-HHmmss"));
Directory.CreateDirectory(runDir);
using var csv = new StreamWriter(Path.Combine(runDir, "plant.csv"));
csv.WriteLine("t_s,unix_ms,true_temp_c,sensor_c,duty,tamb_c,sensor_seq,act_seq,act_age_ms");
File.WriteAllText(Path.Combine(runDir, "plant_config.txt"), opt.ToString());

var rng = new Random(opt.Seed);
double Gaussian() =>
    Math.Sqrt(-2 * Math.Log(1 - rng.NextDouble())) * Math.Cos(2 * Math.PI * rng.NextDouble());

// Actuator state, written by the MQTT handler and read by the physics loop.
var actLock = new object();
double duty = opt.U0;
uint actSeq = 0;
long actRxMs = -1;

var clock = Stopwatch.StartNew();
var factory = new MqttClientFactory();
using var client = factory.CreateMqttClient();

client.ApplicationMessageReceivedAsync += e =>
{
    var payload = e.ApplicationMessage.Payload.ToArray();
    if (SgMessage.TryDecode(payload, out var m) && m.Type == SgMessageType.Actuator)
    {
        lock (actLock)
        {
            duty = Math.Clamp(m.Value, 0f, 1f);
            actSeq = m.Seq;
            actRxMs = clock.ElapsedMilliseconds;
        }
    }
    return Task.CompletedTask;
};

await client.ConnectAsync(new MqttClientOptionsBuilder()
    .WithTcpServer(opt.Broker, opt.Port)
    .WithClientId("sg-plant")
    .Build());
await client.SubscribeAsync(factory.CreateSubscribeOptionsBuilder()
    .WithTopicFilter(Topics.Actuator)
    .Build());

if (!opt.Quiet)
{
    Console.WriteLine($"plant up: {opt}");
    Console.WriteLine($"logging to {runDir}");
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
if (opt.DurationS > 0) cts.CancelAfter(TimeSpan.FromSeconds(opt.DurationS));

const int PhysicsMs = 10;
const int PublishEvery = 10;          // 10 x 10 ms = 100 ms sensor period
double temp = opt.T0;
uint sensorSeq = 0;
long lastMs = 0;
using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(PhysicsMs));

try
{
    for (long tick = 1; await timer.WaitForNextTickAsync(cts.Token); tick++)
    {
        long nowMs = clock.ElapsedMilliseconds;
        double dt = (nowMs - lastMs) / 1000.0;
        lastMs = nowMs;

        double u; uint aSeq; long aRx;
        lock (actLock) { u = duty; aSeq = actSeq; aRx = actRxMs; }

        // Disturbance: the ambient temperature steps (a window opens).
        double tamb = opt.DistAtS >= 0 && nowMs / 1000.0 >= opt.DistAtS ? opt.DistTAmb : opt.TAmb;

        // Exact solution of the first-order ODE for constant u over dt, so
        // timer jitter does not introduce integration error.
        double target = tamb + opt.Gain * u;
        temp = target + (temp - target) * Math.Exp(-dt / opt.Tau);

        if (tick % PublishEvery != 0) continue;

        float sensor = (float)(temp + opt.Noise * Gaussian());
        long unixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var msg = new SgMessage(SgMessageType.Sensor, ++sensorSeq, (ulong)unixMs, sensor);
        await client.PublishAsync(new MqttApplicationMessageBuilder()
            .WithTopic(Topics.Sensor)
            .WithPayload(SgMac.EncodeSigned(msg))
            .Build(), cts.Token);

        long age = aRx < 0 ? -1 : nowMs - aRx;
        csv.WriteLine($"{nowMs / 1000.0:F2},{unixMs},{temp:F4},{sensor:F4},{u:F4},{tamb:F1},{sensorSeq},{aSeq},{age}");

        if (sensorSeq % 50 == 0)
        {
            csv.Flush();
            if (!opt.Quiet)
                Console.WriteLine($"t={nowMs / 1000.0,7:F1}s  T={temp,6:F2}C  u={u:F3}  act_seq={aSeq}  act_age={age}ms");
        }
    }
}
catch (OperationCanceledException) { }

csv.Flush();
await client.DisconnectAsync();
if (!opt.Quiet) Console.WriteLine($"stopped; log in {runDir}");

record Options(string Broker, int Port, double TAmb, double T0, double U0, double Gain, double Tau,
               double Noise, int Seed, double DurationS, double DistAtS, double DistTAmb,
               string? RunDir, bool Quiet)
{
    public static Options Parse(string[] a)
    {
        string? Get(string key)
        {
            int i = Array.IndexOf(a, key);
            return i >= 0 && i + 1 < a.Length ? a[i + 1] : null;
        }
        double D(string k, double d) => Get(k) is { } s ? double.Parse(s, CultureInfo.InvariantCulture) : d;

        return new Options(
            Broker: Get("--broker") ?? "localhost",
            Port: (int)D("--port", Ports.Broker),
            TAmb: D("--tamb", 15),         // ambient, degC
            T0: D("--t0", 15),             // initial room temperature
            U0: D("--u0", 0),              // heater duty until the controller speaks
            Gain: D("--gain", 20),         // full heater raises steady state by 20 degC
            Tau: D("--tau", 60),           // thermal time constant, s
            Noise: D("--noise", 0.05),     // sensor noise sigma, degC
            Seed: (int)D("--seed", 1),
            DurationS: D("--duration", 0), // 0 = run until Ctrl+C
            DistAtS: D("--dist-at", -1),   // disturbance start, s (-1 = none)
            DistTAmb: D("--dist-tamb", 5), // ambient during the disturbance
            RunDir: Get("--run-dir"),
            Quiet: a.Contains("--quiet"));
    }
}
