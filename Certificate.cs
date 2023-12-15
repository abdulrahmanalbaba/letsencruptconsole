using System;
using System.IO;
using Microsoft.Extensions.Logging;
using Certes;
using Certes.Acme;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Extensions.DependencyInjection;
using System.Security;

namespace letsencruptconsole;

public class Certificate
{
    private readonly ILogger _logger;

    public Certificate(ILogger<Certificate> logger)
    {
        _logger = logger;
    }

    public async Task<bool> Generate(
        string email,
        string domain,
         string[] subjectAlternativeNames,
         string certificateSecret,
         string pfxPassowrd,
        string azureDnsClientId,
        string azureDnsClientSecret,
        string azureDnsSubscriptionId,
        string azureDnsResourceGroup,
        string azureDnsZoneName
        )
    {
        _logger.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");

        // if (myTimer.ScheduleStatus is not null)
        // {
        //     _logger.LogInformation($"Next timer schedule at: {myTimer.ScheduleStatus.Next}");
        // }

        // string email = req.Query["email"];
        // string domain = req.Query["domain"];

        // if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(domain))
        // {
        //     log.LogError("Invalid input: Please provide email and domain parameters");
        //     return;
        // }


        try
        {
            _logger.LogInformation($"Attempting to generate/renew certificate for email: {email}, domain: {domain}");

            X509Certificate2 certificate = await GetCertificate(email, domain, subjectAlternativeNames, certificateSecret, pfxPassowrd, azureDnsClientId, azureDnsClientSecret, azureDnsSubscriptionId, azureDnsResourceGroup, azureDnsZoneName, _logger);


            _logger.LogInformation($"Certificate generated/renewed successfully: {certificate.Thumbprint}");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error generating/renewing certificate: {ex.Message}");
            return false;
        }
    }

    private async Task<X509Certificate2> GetCertificate(string email, string domain, string[] subjectAlternativeNames, string certificateSecret, string pfxPassowrd, string azureDnsClientId, string azureDnsClientSecret, string azureDnsSubscriptionId, string azureDnsResourceGroup, string azureDnsZoneName, ILogger log)
    {
        var acme = new AcmeContext(WellKnownServers.LetsEncryptV2);
        var account = await acme.NewAccount(email, true);

        var order = await acme.NewOrder(new[] { domain });

        var authz = (await order.Authorizations()).First();
        var dnsChallenge = await authz.Dns();
        var txtRecordValue = acme.AccountKey.DnsTxt(dnsChallenge.Token);
        var txtRecordName = "_acme-challenge.";

        _logger.LogInformation($"DNS-01 challenge received. Updating TXT record in Azure DNS for domain: {domain}, record name: {txtRecordName}, value: {txtRecordValue}");

        // Update TXT record in Azure DNS
        // await UpdateTxtRecordInAzureDns(azureDnsClientId, azureDnsClientSecret, azureDnsSubscriptionId, azureDnsResourceGroup, azureDnsZoneName, txtRecordName, txtRecordValue, log);

        await dnsChallenge.Validate();


        var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);

        var cert = await order.Generate(new CsrInfo
        {
            CountryName = "AE",
            State = "Dubai",
            CommonName = domain
        }, privateKey);

        var certPfx = cert.ToPfx(privateKey);
        var certPfxBytes = certPfx.Build("apneacentercertificate", pfxPassowrd);

        SecureString secureString = new SecureString();
        foreach (char c in pfxPassowrd.ToCharArray())
        {
            secureString.AppendChar(c);
        }

        var x509Certificate = new X509Certificate2(certPfxBytes, secureString, X509KeyStorageFlags.MachineKeySet);
        SubjectAlternativeNameBuilder builder = new SubjectAlternativeNameBuilder();
        foreach (var san in subjectAlternativeNames)
        {
            builder.AddDnsName(san);
        }
        x509Certificate.Extensions.Add(builder.Build());
        _logger.LogInformation($"Certificate generated successfully for domain: {domain}");

        // Save the certificate to Azure Key Vault
        // var keyVaultClient = new CertificateClient(new Uri(certificateSecret));
        // await keyVaultClient.ImportCertificateAsync(new ImportCertificateOptions(domain, certPfx));

        //This line is not tested yet
        File.WriteAllBytes("./certificate.pfx", x509Certificate.Export(X509ContentType.Pkcs12, secureString));

        return x509Certificate;
    }

    // private static async Task UpdateTxtRecordInAzureDns(string clientId, string clientSecret, string subscriptionId, string resourceGroup, string zoneName, string recordName, string recordValue, ILogger log)
    // {
    //     var serviceClientCredentials = ApplicationTokenProvider.LoginSilentAsync("common", clientId, clientSecret).Result;

    //     using (var dnsClient = new DnsManagementClient(serviceClientCredentials) { SubscriptionId = subscriptionId })
    //     {
    //         var txtRecordSet = dnsClient.RecordSets.Get(resourceGroup, zoneName, recordName, RecordType.TXT);

    //         if (txtRecordSet == null)
    //         {
    //             txtRecordSet = new RecordSet
    //             {
    //                 TTL = 3600,
    //                 TxtRecords = new List<TxtRecord> { new TxtRecord(new List<string> { recordValue }) }
    //             };

    //             await dnsClient.RecordSets.CreateOrUpdateAsync(resourceGroup, zoneName, recordName, RecordType.TXT, txtRecordSet);

    //             _logger.LogInformation($"TXT record created in Azure DNS for record name: {recordName}, value: {recordValue}");
    //         }
    //         else
    //         {
    //             // Update the existing TXT record
    //             txtRecordSet.TxtRecords.First().Value.Add(recordValue);

    //             await dnsClient.RecordSets.CreateOrUpdateAsync(resourceGroup, zoneName, recordName, RecordType.TXT, txtRecordSet);

    //             _logger.LogInformation($"Existing TXT record updated in Azure DNS for record name: {recordName}, value: {recordValue}");
    //         }
    //     }
    // }

}