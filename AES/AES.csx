using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

var keyPair = Rsa.GenerateKeyPair(primeBitLength: 256);

Console.WriteLine("n = " + keyPair.Modulus);
Console.WriteLine("e = " + keyPair.PublicExponent);
Console.WriteLine("d = " + keyPair.PrivateExponent);
Console.WriteLine();

string message = "Hello RSA";
var cipherBlocks = Rsa.Encrypt(message, keyPair.PublicExponent, keyPair.Modulus);

Console.WriteLine("Encrypted blocks:");
foreach (var block in cipherBlocks)
    Console.WriteLine(block);
Console.WriteLine();

string decrypted = Rsa.Decrypt(cipherBlocks, keyPair.PrivateExponent, keyPair.Modulus);
Console.WriteLine("Decrypted: " + decrypted);

public static class Rsa
{
    public static bool IsProbablyPrime(BigInteger candidateNumber, int rounds = 20)
    {
        if (candidateNumber < 2) return false;
        if (candidateNumber == 2 || candidateNumber == 3) return true;
        if (candidateNumber.IsEven) return false;

        BigInteger oddRemainder = candidateNumber - 1;
        int exponentOfTwo = 0;
        while (oddRemainder.IsEven)
        {
            oddRemainder /= 2;
            exponentOfTwo++;
        }

        for (int round = 0; round < rounds; round++)
        {
            BigInteger witness = GetRandomBigIntegerInRange(2, candidateNumber - 2);
            BigInteger x = ModularExponentiation(witness, oddRemainder, candidateNumber);

            if (x == 1 || x == candidateNumber - 1)
                continue;

            bool composite = true;
            for (int i = 0; i < exponentOfTwo - 1; i++)
            {
                x = ModularExponentiation(x, 2, candidateNumber);
                if (x == candidateNumber - 1)
                {
                    composite = false;
                    break;
                }
            }

            if (composite)
                return false;
        }

        return true;
    }

    public static BigInteger GenerateLargePrime(int bitLength)
    {
        while (true)
        {
            BigInteger candidate = GetRandomBigIntegerWithBitLength(bitLength);
            candidate |= 1;

            if (IsProbablyPrime(candidate))
                return candidate;
        }
    }

    public static BigInteger ModularExponentiation(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
    {
        if (modulus == 1) return 0;

        BigInteger result = 1;
        baseValue %= modulus;

        while (exponent > 0)
        {
            if ((exponent & 1) == 1)
                result = (result * baseValue) % modulus;

            exponent >>= 1;
            baseValue = (baseValue * baseValue) % modulus;
        }

        return result;
    }

    private static BigInteger ExtendedEuclidean(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
    {
        if (b == 0)
        {
            x = 1;
            y = 0;
            return a;
        }

        BigInteger gcd = ExtendedEuclidean(b, a % b, out BigInteger x1, out BigInteger y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return gcd;
    }

    public static BigInteger ModularInverse(BigInteger e, BigInteger lambda)
    {
        BigInteger gcd = ExtendedEuclidean(e, lambda, out BigInteger x, out _);
        if (gcd != 1)
            throw new ArgumentException("e and lambda(n) are not coprime.");

        BigInteger d = x % lambda;
        if (d < 0) d += lambda;
        return d;
    }

    private static BigInteger Lcm(BigInteger a, BigInteger b)
    {
        return BigInteger.Abs(a * b) / BigInteger.GreatestCommonDivisor(a, b);
    }

    public readonly struct RsaKeyPair
    {
        public BigInteger Modulus { get; }
        public BigInteger PublicExponent { get; }
        public BigInteger PrivateExponent { get; }

        public RsaKeyPair(BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent)
        {
            Modulus = modulus;
            PublicExponent = publicExponent;
            PrivateExponent = privateExponent;
        }
    }

    public static RsaKeyPair GenerateKeyPair(int primeBitLength = 1024)
    {
        BigInteger p = GenerateLargePrime(primeBitLength);
        BigInteger q;
        do
        {
            q = GenerateLargePrime(primeBitLength);
        } while (q == p);

        BigInteger n = p * q;
        BigInteger lambda = Lcm(p - 1, q - 1);

        BigInteger e = 65537;
        if (BigInteger.GreatestCommonDivisor(e, lambda) != 1)
        {
            e = 3;
            while (BigInteger.GreatestCommonDivisor(e, lambda) != 1)
                e += 2;
        }

        BigInteger d = ModularInverse(e, lambda);

        return new RsaKeyPair(n, e, d);
    }

    public static BigInteger[] Encrypt(string plainText, BigInteger e, BigInteger n)
    {
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

        int modulusByteLength = n.ToByteArray().Length;
        int blockSizeInBytes = Math.Max(1, modulusByteLength - 2);

        int blockCount = (int)Math.Ceiling(plainTextBytes.Length / (double)blockSizeInBytes);
        BigInteger[] cipherBlocks = new BigInteger[blockCount];

        for (int i = 0; i < blockCount; i++)
        {
            int offset = i * blockSizeInBytes;
            int length = Math.Min(blockSizeInBytes, plainTextBytes.Length - offset);

            byte[] blockBytes = new byte[length + 1];
            Array.Copy(plainTextBytes, offset, blockBytes, 0, length);
            blockBytes[length] = 0;

            BigInteger m = new BigInteger(blockBytes);
            cipherBlocks[i] = ModularExponentiation(m, e, n);
        }

        return cipherBlocks;
    }

    public static string Decrypt(BigInteger[] cipherBlocks, BigInteger d, BigInteger n)
    {
        using var resultBytes = new System.IO.MemoryStream();

        foreach (BigInteger c in cipherBlocks)
        {
            BigInteger m = ModularExponentiation(c, d, n);
            byte[] blockBytes = m.ToByteArray();

            int usableLength = blockBytes.Length;
            if (usableLength > 0 && blockBytes[usableLength - 1] == 0)
                usableLength--;

            resultBytes.Write(blockBytes, 0, usableLength);
        }

        return Encoding.UTF8.GetString(resultBytes.ToArray());
    }

    private static BigInteger GetRandomBigIntegerWithBitLength(int bitLength)
    {
        int byteCount = (bitLength + 7) / 8;
        byte[] randomBytes = new byte[byteCount + 1];
        RandomNumberGenerator.Fill(new Span<byte>(randomBytes, 0, byteCount));

        randomBytes[byteCount] = 0;
        randomBytes[byteCount - 1] |= 0x80;

        return new BigInteger(randomBytes);
    }

    private static BigInteger GetRandomBigIntegerInRange(BigInteger minimumValue, BigInteger maximumValue)
    {
        BigInteger range = maximumValue - minimumValue + 1;
        byte[] rangeBytes = range.ToByteArray();

        byte[] randomBytes = new byte[rangeBytes.Length];
        RandomNumberGenerator.Fill(randomBytes);
        randomBytes[randomBytes.Length - 1] &= 0x7F;

        BigInteger result = new BigInteger(randomBytes) % range;
        if (result < 0) result += range;

        return minimumValue + result;
    }
}