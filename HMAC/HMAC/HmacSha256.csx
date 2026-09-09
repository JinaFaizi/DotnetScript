using System;
using System.Security.Cryptography;
using System.Text;

string message = "Hello world!";
string secretKey = "my-secret-key";

byte[] messageBytes = Encoding.UTF8.GetBytes(message);
byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);

using (HMACSHA256 hmac = new HMACSHA256(keyBytes))
{
    byte[] hash = hmac.ComputeHash(messageBytes);

    Console.WriteLine($"HMAC-SHA256: {Convert.ToHexString(hash)}");
    Console.WriteLine($"Output length: {hash.Length} bytes");
}