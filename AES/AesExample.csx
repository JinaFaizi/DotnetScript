using System;
using System.Security.Cryptography;
using System.Text;

string message = "Hello world!";

using (Aes aes = Aes.Create())
{
    aes.KeySize = 256;

    byte[] plaintext = Encoding.UTF8.GetBytes(message);

    using (ICryptoTransform encryptor = aes.CreateEncryptor())
    {
        byte[] ciphertext = encryptor.TransformFinalBlock(
            plaintext,
            0,
            plaintext.Length
        );

        Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");
        Console.WriteLine($"Key: {Convert.ToHexString(aes.Key)}");
        Console.WriteLine($"IV: {Convert.ToHexString(aes.IV)}");
    }
}