using System.Text;

namespace LoopShield.Attacker;

/// <summary>Minimal MQTT 3.1.1 framing: enough to read whole packets off a
/// TCP stream, recognise PUBLISH, and build QoS 0 PUBLISH packets.</summary>
public sealed class MqttFrame
{
    public byte Header { get; }
    public byte[] Body { get; }   // everything after the remaining-length field

    public MqttFrame(byte header, byte[] body) { Header = header; Body = body; }

    public int PacketType => Header >> 4;
    public bool IsPublish => PacketType == 3;
    public int Qos => (Header >> 1) & 3;

    /// <summary>Reads one packet; null on clean end of stream.</summary>
    public static async Task<MqttFrame?> ReadAsync(Stream s, CancellationToken ct)
    {
        var one = new byte[1];
        if (await s.ReadAsync(one, ct) == 0) return null;
        byte header = one[0];

        int len = 0, mult = 1;
        for (int i = 0; ; i++)
        {
            if (i == 4) throw new InvalidDataException("bad MQTT remaining length");
            await s.ReadExactlyAsync(one, ct);
            len += (one[0] & 0x7F) * mult;
            if ((one[0] & 0x80) == 0) break;
            mult *= 128;
        }
        var body = new byte[len];
        await s.ReadExactlyAsync(body, ct);
        return new MqttFrame(header, body);
    }

    public byte[] ToBytes()
    {
        var ms = new MemoryStream(Body.Length + 5);
        ms.WriteByte(Header);
        int len = Body.Length;
        do
        {
            byte b = (byte)(len % 128);
            len /= 128;
            if (len > 0) b |= 0x80;
            ms.WriteByte(b);
        } while (len > 0);
        ms.Write(Body);
        return ms.ToArray();
    }

    /// <summary>MQTT protocol level from a CONNECT packet: 4 = 3.1.1, 5 = 5.0.</summary>
    public int ConnectProtocolLevel()
    {
        int nameLen = Body[0] << 8 | Body[1];
        return Body[2 + nameLen];
    }

    /// <summary>Topic and payload of a PUBLISH packet. MQTT 5 adds a
    /// properties block (varint length + properties) before the payload.</summary>
    public (string Topic, byte[] Payload) ParsePublish(bool v5)
    {
        int topicLen = Body[0] << 8 | Body[1];
        string topic = Encoding.UTF8.GetString(Body, 2, topicLen);
        int off = 2 + topicLen + (Qos > 0 ? 2 : 0);
        if (v5)
        {
            int propLen = 0, mult = 1;
            byte b;
            do
            {
                b = Body[off++];
                propLen += (b & 0x7F) * mult;
                mult *= 128;
            } while ((b & 0x80) != 0);
            off += propLen;
        }
        return (topic, Body[off..]);
    }

    public static MqttFrame Publish(string topic, byte[] payload, bool v5)
    {
        var t = Encoding.UTF8.GetBytes(topic);
        int props = v5 ? 1 : 0;     // MQTT 5: empty properties block
        var body = new byte[2 + t.Length + props + payload.Length];
        body[0] = (byte)(t.Length >> 8);
        body[1] = (byte)t.Length;
        t.CopyTo(body, 2);
        payload.CopyTo(body, 2 + t.Length + props);
        return new MqttFrame(0x30, body);   // PUBLISH, QoS 0, no retain
    }
}
