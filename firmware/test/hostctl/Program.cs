// Host stand-in for the ESP32 controller, for testing the pipeline (attacker,
// plant, harness, analysis) without Wokwi.
//
// It runs the firmware's OWN protocol checks, detector and PI law (the C
// sources, via firmware/test/build/libsghost.so) and speaks the same MQTT
// protocol: sg/config + ack, sg/actuator, sg/telem, sg/stats. Its TIMING
// numbers are host numbers and say nothing about the ESP32; never use them
// in results.
//
//   make -C firmware/test hostlib && firmware/test/hostctl/bin/Debug/net10.0/LoopShield.HostCtl
using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using MQTTnet;
using LoopShield.Shared;

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, (name, _, _) =>
{
    if (name != "sghost") return IntPtr.Zero;
    string library = OperatingSystem.IsWindows() ? "sghost.dll" : "libsghost.so";
    for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
    {
        var p = Path.Combine(d.FullName, "firmware", "test", "build", library);
        if (File.Exists(p)) return NativeLibrary.Load(p);
    }
    throw new DllNotFoundException($"{library} not found; on Windows run ./scripts/run-local.ps1; on Linux run `make -C firmware/test hostlib`");
});

const float Sp = 22f, Kp = 0.5f, Ki = 0.5f / 60f, Dt = 0.1f;
const int StaleLimit = 5;

var clock = Stopwatch.StartNew();
long NowUs() => clock.ElapsedTicks * 1_000_000 / Stopwatch.Frequency;
var gate = new object();

// --- state shared between the receive path and the control loop (under gate)
var cfg = Cfg.Default;
uint epoch = 0;
IntPtr proto = Native.sgw_proto_new();
uint rxId = 0;
(float Y, uint Id, uint Epoch)? latest = null;
var rx = new uint[5];
long ppN = 0, ppSum = 0, ppMax = 0;
var st = new Stats();

var factory = new MqttClientFactory();
using var mqtt = factory.CreateMqttClient();
mqtt.ApplicationMessageReceivedAsync += e =>
{
    var payload = e.ApplicationMessage.Payload.ToArray();
    if (e.ApplicationMessage.Topic == Topics.Sensor) OnSensor(payload);
    else if (e.ApplicationMessage.Topic == Topics.Config) OnConfig(Encoding.UTF8.GetString(payload));
    return Task.CompletedTask;
};

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
_ = Task.Run(() => KeepConnected(cts.Token));
_ = Task.Run(() => StatsLoop(cts.Token));
Console.WriteLine("hostctl: stand-in controller (host timing, NOT ESP32 timing)");

// --- control loop -----------------------------------------------------------
uint myEpoch = uint.MaxValue, lastId = 0, actSeq = 0;
Cfg c = cfg;
float integ = 0, u = 0, tHat = Sp;
bool have = false;
int stale = 0, alarm = 0;
IntPtr det = IntPtr.Zero;
var dout = new float[7];
long t0 = NowUs();

using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
try
{
    for (uint k = 1; await timer.WaitForNextTickAsync(cts.Token); k++)
    {
        long release = t0 + k * 100_000;
        long start = NowUs();
        (float Y, uint Id, uint Epoch)? s;
        uint[] rxSnap;
        long pn, psum, pmax;
        lock (gate)
        {
            if (epoch != myEpoch)
            {
                myEpoch = epoch;
                c = cfg;
                integ = c.Integ;
                u = c.Integ;
                have = false;
                stale = 0;
                alarm = 0;
                if (det != IntPtr.Zero) Native.sgw_free(det);
                det = Native.sgw_det_new(Dt, c.K, c.H);
            }
            s = latest;
            rxSnap = (uint[])rx.Clone();
            (pn, psum, pmax) = (ppN, ppSum, ppMax);
            ppN = ppSum = ppMax = 0;
        }

        bool fresh = s is { } v && v.Epoch == myEpoch && v.Id != lastId;
        float y = fresh ? s!.Value.Y : float.NaN;
        if (fresh) { lastId = s!.Value.Id; have = true; }
        stale = fresh ? 0 : stale + 1;

        float uPrev = u;
        int mode = 0;
        if (c.Phys && c.Mitigate && alarm != 0) { mode = 2; u = Native.sgw_pi_step(ref integ, Kp, Ki, Sp, tHat, Dt); }
        else if (fresh) u = Native.sgw_pi_step(ref integ, Kp, Ki, Sp, y, Dt);
        else if (have && stale >= StaleLimit) mode = 1;

        long ctlEnd = NowUs();
        long exec = ctlEnd - start, rt = ctlEnd - release;

        // detector (on the device this is a separate task)
        long d0 = NowUs();
        if (c.Phys)
        {
            alarm = Native.sgw_det_step(det, fresh ? y : 0, fresh ? 1 : 0, uPrev, dout);
            tHat = dout[1];
        }
        else
        {
            Array.Fill(dout, float.NaN);
        }
        long dExec = NowUs() - d0;

        await Publish(Topics.Actuator, new SgMessage(SgMessageType.Actuator, ++actSeq, (ulong)(start / 1000), u).Encode());
        var line = string.Join(",",
            release / 1000, k, F(y, 3), fresh ? 1 : 0, F(uPrev, 4), F(u, 4), mode,
            F(dout[1], 3), F(dout[0], 4), F(dout[2], 3), F(dout[3], 3), F(dout[4], 4), F(dout[5], 4), F(dout[6], 4),
            c.Phys ? alarm : 0,
            rxSnap[0], rxSnap[2], rxSnap[3], rxSnap[4], rxSnap[1],
            exec, rt, dExec, pn, psum, pmax);
        await Publish(Topics.Telemetry, Encoding.UTF8.GetBytes(line));

        lock (gate)
        {
            st.Jobs++;
            if (rt > 100_000) st.Misses++;
            if (!fresh) st.Stale++;
            if (mode == 1) st.Hold++;
            if (mode == 2) st.Safe++;
            st.Wcrt = Math.Max(st.Wcrt, rt);
            st.ExecMax = Math.Max(st.ExecMax, exec);
            st.ExecSum += exec;
            st.DetJobs++;
            st.DetMax = Math.Max(st.DetMax, dExec);
            st.DetSum += dExec;
        }
    }
}
catch (OperationCanceledException) { }
return;

static string F(float v, int d) => float.IsNaN(v) ? "nan" : v.ToString("F" + d, CultureInfo.InvariantCulture);

void OnSensor(byte[] buf)
{
    lock (gate)
    {
        long a = NowUs();
        int verdict = Native.sgw_proto_check(proto, cfg.Seq ? 1 : 0, cfg.Fresh ? 1 : 0, cfg.Mac ? 1 : 0,
            buf, buf.Length, a, SgMac.Verify(buf) ? 1 : 0, out float value);
        if (verdict == 0) latest = (value, ++rxId, epoch);
        long dt = NowUs() - a;
        rx[verdict]++;
        st.ProtoN++; st.ProtoSum += dt; st.ProtoMax = Math.Max(st.ProtoMax, dt);
        ppN++; ppSum += dt; ppMax = Math.Max(ppMax, dt);
    }
}

void OnConfig(string text)
{
    var kv = text.Split(' ', StringSplitOptions.RemoveEmptyEntries)
        .Select(t => t.Split('=')).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1]);
    float Fl(string k, float d) => kv.TryGetValue(k, out var v) ? float.Parse(v, CultureInfo.InvariantCulture) : d;
    bool B(string k, bool d) => kv.TryGetValue(k, out var v) ? v == "1" : d;
    uint run = kv.TryGetValue("run", out var r) ? uint.Parse(r) : 0;
    lock (gate)
    {
        cfg = new Cfg(run, B("seq", false), B("fresh", false), B("mac", false), B("phys", false),
                      B("mitigate", true), Fl("k", 0.05f), Fl("h", 4f), Fl("integ", 0f));
        epoch++;
        Native.sgw_proto_reset(proto);
        latest = null;
        Array.Clear(rx);
        st = new Stats();
    }
    _ = Publish(Topics.ConfigAck, Encoding.UTF8.GetBytes($"run={run} epoch={epoch} mac_ok=1"));
    Console.WriteLine($"{DateTime.Now:HH:mm:ss} config {text}");
}

async Task Publish(string topic, byte[] payload)
{
    if (!mqtt.IsConnected) return;
    try { await mqtt.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic).WithPayload(payload).Build()); }
    catch (Exception) { }
}

async Task KeepConnected(CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        if (!mqtt.IsConnected)
        {
            try
            {
                await mqtt.ConnectAsync(new MqttClientOptionsBuilder()
                    .WithTcpServer("localhost", Ports.Link).WithClientId("sg-controller")
                    .WithProtocolVersion(MQTTnet.Formatter.MqttProtocolVersion.V311).Build(), ct);   // like esp-mqtt
                await mqtt.SubscribeAsync(factory.CreateSubscribeOptionsBuilder()
                    .WithTopicFilter(Topics.Sensor)
                    .WithTopicFilter(Topics.Config, MQTTnet.Protocol.MqttQualityOfServiceLevel.AtLeastOnce).Build(), ct);
                Console.WriteLine($"{DateTime.Now:HH:mm:ss} connected via :{Ports.Link}");
            }
            catch (Exception) { }
        }
        await Task.Delay(500, ct).ContinueWith(_ => { });
    }
}

async Task StatsLoop(CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        await Task.Delay(10_000, ct).ContinueWith(_ => { });
        string json;
        lock (gate)
        {
            var s = st;
            json = $"{{\"t_ms\":{NowUs() / 1000},\"run\":{cfg.Run},\"mac_ok\":1,\"jobs\":{s.Jobs},\"misses\":{s.Misses}," +
                   $"\"stale\":{s.Stale},\"hold\":{s.Hold},\"safe\":{s.Safe},\"wcrt_us\":{s.Wcrt},\"exec_max_us\":{s.ExecMax}," +
                   $"\"exec_avg_us\":{(s.Jobs > 0 ? s.ExecSum / s.Jobs : 0)},\"det_jobs\":{s.DetJobs},\"det_misses\":0," +
                   $"\"det_exec_max_us\":{s.DetMax},\"det_exec_avg_us\":{(s.DetJobs > 0 ? s.DetSum / s.DetJobs : 0)}," +
                   $"\"rx_accept\":{rx[0]},\"rej_mac\":{rx[2]},\"rej_seq\":{rx[3]},\"rej_fresh\":{rx[4]},\"rej_parse\":{rx[1]}," +
                   $"\"proto_n\":{s.ProtoN},\"proto_max_us\":{s.ProtoMax},\"proto_avg_us\":{(s.ProtoN > 0 ? s.ProtoSum / s.ProtoN : 0)}," +
                   $"\"tx_lat_max_us\":0,\"tx_drops\":0,\"free_heap\":0,\"host_standin\":1}}";
        }
        await Publish(Topics.Stats, Encoding.UTF8.GetBytes(json));
    }
}

record Cfg(uint Run, bool Seq, bool Fresh, bool Mac, bool Phys, bool Mitigate, float K, float H, float Integ)
{
    public static readonly Cfg Default = new(0, false, false, false, false, true, 0.05f, 4f, 0f);
}

class Stats
{
    public long Jobs, Misses, Stale, Hold, Safe, Wcrt, ExecMax, ExecSum, DetJobs, DetMax, DetSum, ProtoN, ProtoSum, ProtoMax;
}

static partial class Native
{
    [DllImport("sghost")] public static extern IntPtr sgw_proto_new();
    [DllImport("sghost")] public static extern void sgw_proto_reset(IntPtr s);
    [DllImport("sghost")] public static extern void sgw_free(IntPtr p);
    [DllImport("sghost")] public static extern int sgw_proto_check(IntPtr st, int seq, int fresh, int mac, byte[] buf, int len,
                                                                   long nowUs, int macValid, out float value);
    [DllImport("sghost")] public static extern IntPtr sgw_det_new(float dt, float k, float h);
    [DllImport("sghost")] public static extern int sgw_det_step(IntPtr det, float y, int fresh, float uPrev, [Out] float[] o);
    [DllImport("sghost")] public static extern float sgw_pi_step(ref float integ, float kp, float ki, float sp, float y, float dt);
}
