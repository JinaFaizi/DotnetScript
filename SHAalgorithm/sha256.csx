using System;

public class Sha256
{
    private const int HASH_LENGTH = 32;
    private const int BLOCK_LENGTH = 64;

    private const byte HMAC_IPAD = 0x36;
    private const byte HMAC_OPAD = 0x5C;

    private static readonly uint[] InitialState =
    {
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19
    };

    private static readonly uint[] K =
    {
        0x428A2F98, 0x71374491, 0xB5C0FBCF,
        0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
        0x923F82A4, 0xAB1C5ED5, 0xD807AA98,
        0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7,
        0xC19BF174, 0xE49B69C1, 0xEFBE4786,
        0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F,
        0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8,
        0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
        0x06CA6351, 0x14292967, 0x27B70A85,
        0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E,
        0x92722C85, 0xA2BFE8A1, 0xA81A664B,
        0xC24B8B70, 0xC76C51A3, 0xD192E819,
        0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C,
        0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
        0x5B9CCA4F, 0x682E6FF3, 0x748F82EE,
        0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7,
        0xC67178F2
    };

    private readonly uint[] state = new uint[8];
    private readonly uint[] buffer = new uint[64];
    private readonly byte[] block = new byte[BLOCK_LENGTH];

    private readonly byte[] keyBuffer = new byte[BLOCK_LENGTH];
    private readonly byte[] innerHash = new byte[HASH_LENGTH];

    private ulong byteCount;
    private int bufferOffset;

    public void Init()
    {
        Array.Copy(InitialState, state, 8);

        byteCount = 0;
        bufferOffset = 0;

        Array.Clear(block, 0, block.Length);
        Array.Clear(buffer, 0, buffer.Length);
    }

    private static uint RotateRight(uint value, int bits)
    {
        return (value >> bits) | (value << (32 - bits));
    }

    private static uint Ch(uint x, uint y, uint z)
    {
        return (x & y) ^ (~x & z);
    }

    private static uint Maj(uint x, uint y, uint z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static uint BigSigma0(uint x)
    {
        return RotateRight(x, 2)
             ^ RotateRight(x, 13)
             ^ RotateRight(x, 22);
    }

    private static uint BigSigma1(uint x)
    {
        return RotateRight(x, 6)
             ^ RotateRight(x, 11)
             ^ RotateRight(x, 25);
    }

    private static uint SmallSigma0(uint x)
    {
        return RotateRight(x, 7)
             ^ RotateRight(x, 18)
             ^ (x >> 3);
    }

    private static uint SmallSigma1(uint x)
    {
        return RotateRight(x, 17)
             ^ RotateRight(x, 19)
             ^ (x >> 10);
    }

    private void AddUncounted(byte data)
    {
        block[bufferOffset] = data;
        bufferOffset++;

        if (bufferOffset == BLOCK_LENGTH)
        {
            HashBlock();
            bufferOffset = 0;
        }
    }

    public void Write(byte data)
    {
        byteCount++;
        AddUncounted(data);
    }

    public void Write(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        foreach (byte b in data)
        {
            Write(b);
        }
    }

    public void Write(string text)
    {
        if (text == null)
            throw new ArgumentNullException(nameof(text));

        Write(System.Text.Encoding.UTF8.GetBytes(text));
    }

    private void PrepareMessageSchedule()
    {
        for (int i = 0; i < 16; i++)
        {
            int offset = i * 4;

            buffer[i] =
                ((uint)block[offset] << 24)
                | ((uint)block[offset + 1] << 16)
                | ((uint)block[offset + 2] << 8)
                | block[offset + 3];
        }

        for (int i = 16; i < 64; i++)
        {
            buffer[i] =
                SmallSigma1(buffer[i - 2])
                + buffer[i - 7]
                + SmallSigma0(buffer[i - 15])
                + buffer[i - 16];
        }
    }

    private void HashBlock()
    {
        unchecked
        {
            PrepareMessageSchedule();

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];
            uint f = state[5];
            uint g = state[6];
            uint h = state[7];

            for (int i = 0; i < 64; i++)
            {
                uint t1 =
                    h
                    + BigSigma1(e)
                    + Ch(e, f, g)
                    + K[i]
                    + buffer[i];

                uint t2 =
                    BigSigma0(a)
                    + Maj(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }
    }

    private void Pad()
    {
        AddUncounted(0x80);

        while (bufferOffset != 56)
        {
            AddUncounted(0x00);
        }

        ulong bitLength = unchecked(byteCount * 8);

        AddUncounted((byte)(bitLength >> 56));
        AddUncounted((byte)(bitLength >> 48));
        AddUncounted((byte)(bitLength >> 40));
        AddUncounted((byte)(bitLength >> 32));
        AddUncounted((byte)(bitLength >> 24));
        AddUncounted((byte)(bitLength >> 16));
        AddUncounted((byte)(bitLength >> 8));
        AddUncounted((byte)bitLength);
    }

    public byte[] Result()
    {
        Pad();

        byte[] result = new byte[HASH_LENGTH];

        for (int i = 0; i < 8; i++)
        {
            result[i * 4] = (byte)(state[i] >> 24);
            result[i * 4 + 1] = (byte)(state[i] >> 16);
            result[i * 4 + 2] = (byte)(state[i] >> 8);
            result[i * 4 + 3] = (byte)state[i];
        }

        return result;
    }

    public string ResultHex()
    {
        return Convert.ToHexString(Result());
    }

    public static byte[] Compute(byte[] data)
    {
        Sha256 sha = new Sha256();

        sha.Init();
        sha.Write(data);

        return sha.Result();
    }

    public static string ComputeHex(string text)
    {
        Sha256 sha = new Sha256();

        sha.Init();
        sha.Write(text);

        return sha.ResultHex();
    }

    public void InitHmac(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        Array.Clear(keyBuffer, 0, keyBuffer.Length);

        if (key.Length > BLOCK_LENGTH)
        {
            Init();

            Write(key);

            byte[] hashedKey = Result();

            Array.Copy(
                hashedKey,
                0,
                keyBuffer,
                0,
                HASH_LENGTH
            );
        }
        else
        {
            Array.Copy(
                key,
                0,
                keyBuffer,
                0,
                key.Length
            );
        }

        Init();

        for (int i = 0; i < BLOCK_LENGTH; i++)
        {
            Write((byte)(keyBuffer[i] ^ HMAC_IPAD));
        }
    }

    public byte[] ResultHmac()
    {
        byte[] innerResult = Result();

        Array.Copy(
            innerResult,
            0,
            innerHash,
            0,
            HASH_LENGTH
        );

        Init();

        for (int i = 0; i < BLOCK_LENGTH; i++)
        {
            Write((byte)(keyBuffer[i] ^ HMAC_OPAD));
        }

        Write(innerHash);

        return Result();
    }

    public static byte[] ComputeHmac(byte[] key, byte[] data)
    {
        Sha256 sha = new Sha256();

        sha.InitHmac(key);
        sha.Write(data);

        return sha.ResultHmac();
    }

    public static string ComputeHmacHex(byte[] key, byte[] data)
    {
        return Convert.ToHexString(
            ComputeHmac(key, data)
        );
    }
}