
//csc -r:"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\System.Net.Http.dll" .\TransactionInquiry.cs

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;

public class TransactionInquiry
{
    public static void Main()
    {
        string transactionId = "XXXXX";
        var interswitch = new Interswitch();

        if (true) // Replace with your actual condition if needed
        {
            string result = Task.Run(() => interswitch.TransactionInquiry(transactionId)).GetAwaiter().GetResult();
            Console.WriteLine(result);
        }
    }
}

public class Interswitch
{
    private const string CLIENT_ID = "XXXXXX";
    private const string CLIENT_SECRET = "XXXXXX";
    private const string TERMINAL_ID = "3XXXX0001";
    private const string SVA_BASE_URL = "https://X.X.X/api/v1A/svapayments/";
    private const string SIGNATURE_METHOD = "sha256";

    public string HTTP_METHOD   = "GET";

    private string GetAuth(string resourceUrl, string additionalParameters)
    {
        return InterswitchAuth.GenerateInterswitchAuth(HTTP_METHOD, resourceUrl, CLIENT_ID, CLIENT_SECRET,
            additionalParameters, SIGNATURE_METHOD, TERMINAL_ID);
    }

    public async Task<string> TransactionInquiry(string requestReference)
    {
        string inquiryUrl = SVA_BASE_URL + "transactions/" + requestReference;
        string additionalParameters = "";
        string headers = GetAuth(inquiryUrl, additionalParameters);
        string data = "";
        string response = await  PostHTTP(inquiryUrl, headers, data, HTTP_METHOD);
        return response;
    }

    private async Task<string> PostHTTP(string url, string headers, string data, string httpMethod)
    {
        using (HttpClient client = new HttpClient())
        {
            HttpRequestMessage request = new HttpRequestMessage(new HttpMethod(httpMethod), url);
            // request.Content = new StringContent(data, Encoding.UTF8, "application/json");

            string[] headerLines = headers.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string header in headerLines)
            {
                string[] headerParts = header.Split(':');
                if (headerParts.Length == 2)
                {
                    request.Headers.Add(headerParts[0].Trim(), headerParts[1].Trim());
                }
            }

            HttpResponseMessage httpResponse = await client.SendAsync(request);
            string responseBody = await httpResponse.Content.ReadAsStringAsync();
            return responseBody;
        }
    }
}

public static class InterswitchAuth
{
    private const string AUTHORIZATION_REALM = "InterswitchAuth";

    public static string GenerateInterswitchAuth(string httpMethod, string resourceUrl, string clientId, string clientSecretKey,
        string additionalParameters, string signatureMethod, string terminalId)
    {
        string timestamp = GenerateTimestamp().ToString();
        string nonce = GenerateNonce();
        string clientIdBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId));
        string authorization = AUTHORIZATION_REALM + " " + clientIdBase64;

        string signature = GenerateSignature(clientId, clientSecretKey,
            resourceUrl, httpMethod, timestamp, nonce, additionalParameters);

        Dictionary<string, string> interswitchAuth = new Dictionary<string, string>
        {
            { "Authorization", authorization },
            { "Timestamp", timestamp },
            { "Nonce", nonce },
            { "Signature", signature },
            { "SignatureMethod", signatureMethod },
            { "TerminalId", terminalId }
        };

        // Construct headers as a single string with each key-value pair on a new line
        StringBuilder headers = new StringBuilder();
        foreach (var pair in interswitchAuth)
        {
            headers.Append(pair.Key + ":" + pair.Value + "\r\n");
        }

        return headers.ToString();
    }

    private static string GenerateSignature(string clientId, string clientSecretKey, string resourceUrl, string httpMethod, string timestamp,
        string nonce, string transactionParams)
    {
        string encodedUrl = Uri.EscapeDataString(resourceUrl);
        string signatureCipher = httpMethod + "&" + encodedUrl + "&" + timestamp + "&" + nonce + "&" +
            clientId + "&" + clientSecretKey;

        if (!string.IsNullOrEmpty(transactionParams))
        {
            signatureCipher += "&" + transactionParams;
        }

        byte[] keyBytes = Encoding.UTF8.GetBytes(clientSecretKey);
        HMACSHA256 hmac = new HMACSHA256(keyBytes);
        byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureCipher));
        string signature = Convert.ToBase64String(signatureBytes);
        return signature;
    }

    private static string GenerateNonce()
    {
        return Guid.NewGuid().ToString("N");
    }

    private static long GenerateTimestamp()
    {
        // return DateTimeOffset.UtcNow.ToUnixTimeSeconds(); // Uncomment for Unix timestamp in seconds
        return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); // Unix timestamp in milliseconds
    }
}
