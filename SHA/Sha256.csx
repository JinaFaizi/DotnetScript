using System;
using System.Security.Cryptography;
using System.Text;

string message = "Hello world!";
byte[] messageBytes = Encoding.UTF8.GetBytes(message);

using (SHA256 sha256 = SHA256.Create())
{
    byte[] hash = sha256.ComputeHash(messageBytes);

    Console.WriteLine($"SHA256: {Convert.ToHexString(hash)}");
    Console.WriteLine($"Output length: {hash.Length} bytes");
}
