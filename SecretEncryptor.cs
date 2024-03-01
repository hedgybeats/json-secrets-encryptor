using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace BDO_Perform.WebApi.Infrastructure.Secrets;

public static class SecretEncryptor
{
    /// <summary>
    /// Ensures that all Configuration Secrets are encrypted.
    /// </summary>
    /// <typeparam name="T">The class representing the settings to be encrypted.</typeparam>
    /// <param name="physicalPath">Path to the JSON file to be encrypted.</param>
    /// <param name="sectionName">Name of the section in the JSON file to target.</param>
    public static void EncryptSecrets<T>(string physicalPath, string sectionName)
     where T : class, new()
    {
        var jObject = JsonConvert.DeserializeObject<JObject>(File.ReadAllText(physicalPath));

        if (jObject == null) return;

        var settings = jObject.TryGetValue(sectionName, out JToken? section) ?
            JsonConvert.DeserializeObject<T>(section.ToString()) : new T();

        var secretProperties = typeof(T).GetProperties().Where(p => p.PropertyType == typeof(ConfigurationSecret));

        if (!secretProperties.Any()) return;

        foreach (var property in secretProperties)
        {
            ConfigurationSecret? currentValue = property.GetValue(settings) is { } obj ? (ConfigurationSecret)obj : null;

            if (currentValue != null && currentValue.Value != string.Empty)
            {
                currentValue.Encrypt();
            }
        }

        jObject[sectionName] = JObject.Parse(JsonConvert.SerializeObject(settings));
        File.WriteAllText(physicalPath, JsonConvert.SerializeObject(jObject, Newtonsoft.Json.Formatting.Indented));
    }
}

/// <summary>
/// A secret configuration which allows encryption and decryption using Windows DPAPI.
/// </summary>
public class ConfigurationSecret
{
    /// <summary>
    /// Gets or sets the unencrypted value.
    /// This value will be deleted once encrypted.
    /// </summary>
    /// <value>
    /// The initial, unencrypted value.
    /// </value>
    public string? Value { get; set; }

    /// <summary>
    /// Gets or sets the encrypted secret value.
    /// This is set by calling the <see cref="Encrypt"/> method.
    /// Get the decrypted value by using <see cref="Decrypt"/>.
    /// </summary>
    /// <value>
    /// The encrypted secret value.
    /// </value>
    public string? Secret { get; set; }

    /// <summary>
    /// Decrypts the secret value.
    /// </summary>
    /// <returns>
    /// The decrypted string.
    /// </returns>
    public string Decrypt()
    {
        try
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) throw new Exception();

            byte[] decryptedData = ProtectedData.Unprotect(
                Convert.FromBase64String(Secret ?? string.Empty),
                Encoding.UTF8.GetBytes(UniqueMachineIdentifier()),
                DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(decryptedData);
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Encrypts the value.
    /// </summary>
    public void Encrypt()
    {
        if (string.IsNullOrEmpty(Value) || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        byte[] encrypted = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(Value),
            Encoding.UTF8.GetBytes(UniqueMachineIdentifier()),
            DataProtectionScope.LocalMachine);

        Secret = Convert.ToBase64String(encrypted);
        Value = string.Empty;
    }

    /// <summary>
    /// Gets a unique machine identifier for the current machine.
    /// </summary>
    /// <returns>A unique machine identifier.</returns>
    private static string UniqueMachineIdentifier()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) throw new Exception();

        StringBuilder sb = new();

        // Get processor ID
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
        {
            foreach (var mo in searcher.Get())
            {
                sb.Append(mo["ProcessorId"].ToString());
            }
        }

        // Get motherboard ID
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
        {
            foreach (var mo in searcher.Get())
            {
                sb.Append(mo["SerialNumber"].ToString());
            }
        }

        // Get physical media serial number
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_PhysicalMedia"))
        {
            foreach (var mo in searcher.Get())
            {
                sb.Append(mo["SerialNumber"].ToString());
            }
        }

        // Compute hash of the concatenated hardware identifiers
        using SHA256 sha256 = SHA256.Create();
        byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
        return BitConverter.ToString(hashBytes).Replace("-", string.Empty);
    }

}
