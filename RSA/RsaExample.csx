using System;
using System.Security.Cryptography;
using System.Text;

string message = "Hello world!";
byte[] data = Encoding.UTF8.GetBytes(message);

using (RSA rsa = RSA.Create(2048))
{
    
    byte[] encrypted = rsa.Encrypt(
        data,
        RSAEncryptionPadding.OaepSHA256
    );

    Console.WriteLine($"Encrypted: {Convert.ToHexString(encrypted)}");

    
    byte[] decrypted = rsa.Decrypt(
        encrypted,
        RSAEncryptionPadding.OaepSHA256
    );

    Console.WriteLine($"Decrypted: {Encoding.UTF8.GetString(decrypted)}");
}