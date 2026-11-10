// Local MQTT broker for the LoopShield lab, on port 1884. The plant and the
// harness connect here directly. The Wokwi ESP32 connects to port 1883,
// which is the attacker's on-path proxy (see attacker/), which forwards here.
using MQTTnet.Server;
using LoopShield.Shared;

int port = args.Length > 0 && int.TryParse(args[0], out var p) ? p : Ports.Broker;

var factory = new MqttServerFactory();
var options = factory.CreateServerOptionsBuilder()
    .WithDefaultEndpoint()
    .WithDefaultEndpointPort(port)
    .Build();

using var server = factory.CreateMqttServer(options);

server.ClientConnectedAsync += e =>
{
    Log($"connected     {e.ClientId} from {e.RemoteEndPoint}");
    return Task.CompletedTask;
};
server.ClientDisconnectedAsync += e =>
{
    Log($"disconnected  {e.ClientId} ({e.DisconnectType})");
    return Task.CompletedTask;
};
server.ClientSubscribedTopicAsync += e =>
{
    Log($"subscribed    {e.ClientId} -> {e.TopicFilter.Topic}");
    return Task.CompletedTask;
};

await server.StartAsync();
Log($"broker listening on 0.0.0.0:{port}  (Ctrl+C to stop)");

var stop = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.TrySetResult(); };
await stop.Task;
await server.StopAsync();

static void Log(string msg) => Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {msg}");
