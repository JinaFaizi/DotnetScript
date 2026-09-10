using System;

public class AesManual
{
    private const int Nb = 4;
    private readonly int Nk;
    private readonly int Nr;
    private readonly byte[] expandedKey;

    private static readonly byte[] SBox =
    {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
        0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
        0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
        0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
        0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
        0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
        0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
        0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
        0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
        0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
        0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
        0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
        0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
        0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
        0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
        0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
        0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    private static readonly byte[] InvSBox =
    {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
        0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
        0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
        0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
        0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
        0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
        0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
        0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
        0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
        0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
        0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
        0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
        0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
        0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
        0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
        0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
        0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

   
    private static byte GAdd(byte a, byte b)
    {
        return (byte)(a ^ b);
    }


    private static byte GSub(byte a, byte b)
    {
        return (byte)(a ^ b);
    }

  
    private static byte GMult(byte a, byte b)
    {
        byte p = 0;

        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0)
                p ^= a;

            bool highBit = (a & 0x80) != 0;

            a = (byte)(a << 1);

            if (highBit)
                a ^= 0x1B;

            b >>= 1;
        }

        return p;
    }

    private static byte[] CoefAdd(byte[] a, byte[] b)
    {
        return new byte[]
        {
            GAdd(a[0], b[0]),
            GAdd(a[1], b[1]),
            GAdd(a[2], b[2]),
            GAdd(a[3], b[3])
        };
    }

    private static byte[] CoefMult(byte[] a, byte[] b)
    {
        return new byte[]
        {
            (byte)(
                GMult(a[0], b[0]) ^
                GMult(a[3], b[1]) ^
                GMult(a[2], b[2]) ^
                GMult(a[1], b[3])
            ),

            (byte)(
                GMult(a[1], b[0]) ^
                GMult(a[0], b[1]) ^
                GMult(a[3], b[2]) ^
                GMult(a[2], b[3])
            ),

            (byte)(
                GMult(a[2], b[0]) ^
                GMult(a[1], b[1]) ^
                GMult(a[0], b[2]) ^
                GMult(a[3], b[3])
            ),

            (byte)(
                GMult(a[3], b[0]) ^
                GMult(a[2], b[1]) ^
                GMult(a[1], b[2]) ^
                GMult(a[0], b[3])
            )
        };
    }

    private static byte[] Rcon(byte i)
    {
        byte[] result = { 0x02, 0x00, 0x00, 0x00 };

        if (i == 1)
        {
            result[0] = 0x01;
        }
        else if (i > 1)
        {
            i--;

            while (i > 1)
            {
                result[0] = GMult(result[0], 0x02);
                i--;
            }
        }

        return result;
    }

    public AesManual(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        if (key.Length != 16 &&
            key.Length != 24 &&
            key.Length != 32)
        {
            throw new ArgumentException(
                "AES key must be 16, 24, or 32 bytes."
            );
        }

        if (key.Length == 16)
        {
            Nk = 4;
            Nr = 10;
        }
        else if (key.Length == 24)
        {
            Nk = 6;
            Nr = 12;
        }
        else
        {
            Nk = 8;
            Nr = 14;
        }

        expandedKey = KeyExpansion(key);
    }

    private void AddRoundKey(byte[] state, int round)
    {
        for (int c = 0; c < Nb; c++)
        {
            state[0 * Nb + c] ^= expandedKey[4 * Nb * round + 4 * c + 0];
            state[1 * Nb + c] ^= expandedKey[4 * Nb * round + 4 * c + 1];
            state[2 * Nb + c] ^= expandedKey[4 * Nb * round + 4 * c + 2];
            state[3 * Nb + c] ^= expandedKey[4 * Nb * round + 4 * c + 3];
        }
    }

    private static void MixColumns(byte[] state)
    {
        byte[] matrix = { 0x02, 0x01, 0x01, 0x03 };

        for (int column = 0; column < Nb; column++)
        {
            byte[] current =
            {
                state[0 * Nb + column],
                state[1 * Nb + column],
                state[2 * Nb + column],
                state[3 * Nb + column]
            };

            byte[] result = CoefMult(matrix, current);

            for (int row = 0; row < 4; row++)
                state[row * Nb + column] = result[row];
        }
    }

    private static void InvMixColumns(byte[] state)
    {
        byte[] matrix = { 0x0E, 0x09, 0x0D, 0x0B };

        for (int column = 0; column < Nb; column++)
        {
            byte[] current =
            {
                state[0 * Nb + column],
                state[1 * Nb + column],
                state[2 * Nb + column],
                state[3 * Nb + column]
            };

            byte[] result = CoefMult(matrix, current);

            for (int row = 0; row < 4; row++)
                state[row * Nb + column] = result[row];
        }
    }

    private static void ShiftRows(byte[] state)
    {
        for (int row = 1; row < 4; row++)
        {
            for (int shift = 0; shift < row; shift++)
            {
                byte temp = state[row * Nb];

                for (int column = 1; column < Nb; column++)
                {
                    state[row * Nb + column - 1] =
                        state[row * Nb + column];
                }

                state[row * Nb + Nb - 1] = temp;
            }
        }
    }

    private static void InvShiftRows(byte[] state)
    {
        for (int row = 1; row < 4; row++)
        {
            for (int shift = 0; shift < row; shift++)
            {
                byte temp = state[row * Nb + Nb - 1];

                for (int column = Nb - 1; column > 0; column--)
                {
                    state[row * Nb + column] =
                        state[row * Nb + column - 1];
                }

                state[row * Nb] = temp;
            }
        }
    }

    private static void SubBytes(byte[] state)
    {
        for (int i = 0; i < state.Length; i++)
            state[i] = SBox[state[i]];
    }

    private static void InvSubBytes(byte[] state)
    {
        for (int i = 0; i < state.Length; i++)
            state[i] = InvSBox[state[i]];
    }

    private static void SubWord(byte[] word)
    {
        for (int i = 0; i < 4; i++)
            word[i] = SBox[word[i]];
    }

    private static void RotWord(byte[] word)
    {
        byte temp = word[0];

        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
    }

    private byte[] KeyExpansion(byte[] key)
    {
        int totalWords = Nb * (Nr + 1);

        byte[] w = new byte[totalWords * 4];

        for (int i = 0; i < Nk; i++)
        {
            w[4 * i] = key[4 * i];
            w[4 * i + 1] = key[4 * i + 1];
            w[4 * i + 2] = key[4 * i + 2];
            w[4 * i + 3] = key[4 * i + 3];
        }

        for (int i = Nk; i < totalWords; i++)
        {
            byte[] temp =
            {
                w[4 * (i - 1)],
                w[4 * (i - 1) + 1],
                w[4 * (i - 1) + 2],
                w[4 * (i - 1) + 3]
            };

            if (i % Nk == 0)
            {
                RotWord(temp);
                SubWord(temp);

                byte[] rcon = Rcon((byte)(i / Nk));

                temp = CoefAdd(temp, rcon);
            }
            else if (Nk > 6 && i % Nk == 4)
            {
                SubWord(temp);
            }

            for (int j = 0; j < 4; j++)
            {
                w[4 * i + j] =
                    (byte)(w[4 * (i - Nk) + j] ^ temp[j]);
            }
        }

        return w;
    }

    public byte[] EncryptBlock(byte[] input)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        if (input.Length != 16)
            throw new ArgumentException(
                "AES block size must be exactly 16 bytes."
            );

        byte[] state = new byte[16];

        
        for (int row = 0; row < 4; row++)
        {
            for (int column = 0; column < 4; column++)
            {
                state[row * Nb + column] =
                    input[row + 4 * column];
            }
        }

       
        AddRoundKey(state, 0);

        for (int round = 1; round < Nr; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, round);
        }

      
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, Nr);

        
        byte[] output = new byte[16];

        for (int row = 0; row < 4; row++)
        {
            for (int column = 0; column < 4; column++)
            {
                output[row + 4 * column] =
                    state[row * Nb + column];
            }
        }

        return output;
    }

    public byte[] DecryptBlock(byte[] input)
    {
        if (input == null)
            throw new ArgumentNullException(nameof(input));

        if (input.Length != 16)
            throw new ArgumentException(
                "AES block size must be exactly 16 bytes."
            );

        byte[] state = new byte[16];

        for (int row = 0; row < 4; row++)
        {
            for (int column = 0; column < 4; column++)
            {
                state[row * Nb + column] =
                    input[row + 4 * column];
            }
        }

        
        AddRoundKey(state, Nr);

        for (int round = Nr - 1; round >= 1; round--)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, round);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, 0);

        byte[] output = new byte[16];

        for (int row = 0; row < 4; row++)
        {
            for (int column = 0; column < 4; column++)
            {
                output[row + 4 * column] =
                    state[row * Nb + column];
            }
        }

        return output;
    }

    public static byte[] HexToBytes(string hex)
    {
        if (hex == null)
            throw new ArgumentNullException(nameof(hex));

        if (hex.Length % 2 != 0)
            throw new ArgumentException(
                "Hex string must have an even number of characters."
            );

        byte[] result = new byte[hex.Length / 2];

        for (int i = 0; i < result.Length; i++)
        {
            result[i] = Convert.ToByte(
                hex.Substring(i * 2, 2),
                16
            );
        }

        return result;
    }

    public static string BytesToHex(byte[] data)
    {
        return Convert.ToHexString(data);
    }
}



byte[] key = AesManual.HexToBytes(
    "000102030405060708090A0B0C0D0E0F"
);

byte[] plaintext = AesManual.HexToBytes(
    "00112233445566778899AABBCCDDEEFF"
);

AesManual aes = new AesManual(key);

byte[] encrypted = aes.EncryptBlock(plaintext);

Console.WriteLine("Encrypted:");
Console.WriteLine(AesManual.BytesToHex(encrypted));

byte[] decrypted = aes.DecryptBlock(encrypted);

Console.WriteLine();
Console.WriteLine("Decrypted:");
Console.WriteLine(AesManual.BytesToHex(decrypted));