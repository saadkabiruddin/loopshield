using System.Buffers.Binary;

namespace LoopShield.Shared;

public enum SgMessageType : byte
{
    Sensor = 1,
    Actuator = 2,
}

/// <summary>
/// LoopShield wire format: 28 bytes, little-endian. Mirrors firmware/main/sg_msg.h;
/// change both together.
/// </summary>
public readonly record struct SgMessage(
    SgMessageType Type,
    uint Seq,
    ulong TimestampMs,
    float Value,
    ushort Flags = 0,
    ulong Mac = 0)
{
    public const byte Version = 1;
    public const int Length = 28;
    public const int MacOffset = 20;
    public const int MacLength = 8;
    public const ushort FlagMac = 0x0001;

    public byte[] Encode()
    {
        var buf = new byte[Length];
        buf[0] = Version;
        buf[1] = (byte)Type;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(2), Flags);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4), Seq);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(8), TimestampMs);
        BinaryPrimitives.WriteSingleLittleEndian(buf.AsSpan(16), Value);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(MacOffset), Mac);
        return buf;
    }

    public static bool TryDecode(ReadOnlySpan<byte> buf, out SgMessage msg)
    {
        msg = default;
        if (buf.Length != Length || buf[0] != Version)
        {
            return false;
        }
        msg = new SgMessage(
            Type: (SgMessageType)buf[1],
            Seq: BinaryPrimitives.ReadUInt32LittleEndian(buf[4..]),
            TimestampMs: BinaryPrimitives.ReadUInt64LittleEndian(buf[8..]),
            Value: BinaryPrimitives.ReadSingleLittleEndian(buf[16..]),
            Flags: BinaryPrimitives.ReadUInt16LittleEndian(buf[2..]),
            Mac: BinaryPrimitives.ReadUInt64LittleEndian(buf[MacOffset..]));
        return true;
    }
}

public static class Topics
{
    public const string Sensor = "sg/sensor";
    public const string Actuator = "sg/actuator";
    public const string Stats = "sg/stats";
    public const string Telemetry = "sg/telem";
    public const string Config = "sg/config";
    public const string ConfigAck = "sg/cfgack";
}

public static class Ports
{
    /// <summary>What the controller connects to: the attacker's on-path proxy.</summary>
    public const int Link = 1883;
    /// <summary>The real broker, behind the proxy. Plant and harness connect here directly.</summary>
    public const int Broker = 1884;
}

/// <summary>Column order of sg/telem lines; must match tx_task() in firmware/main/sg_control.c.</summary>
public static class Telemetry
{
    public const string Columns =
        "t_ms,k,y,fresh,u_prev,u,mode,t_hat,r,s_pos,s_neg,slope,lo,hi,alarm," +
        "rx_accept,rej_mac,rej_seq,rej_fresh,rej_parse," +
        "ctl_exec_us,ctl_rt_us,det_exec_us,proto_n,proto_sum_us,proto_max_us";
}
