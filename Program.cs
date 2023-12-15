using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace letsencruptconsole;

class Program
{
    static void Main(string[] args)
    {
        // Set up DI container
        var serviceProvider = new ServiceCollection()
            .AddLogging(builder => builder.AddConsole())
            .AddSingleton<Certificate>()
            .BuildServiceProvider();

        Certificate certificate = serviceProvider.GetService<Certificate>();
         string [] subjectAlternativeNames = new[]
            {
                "*.apnea.center",
                "apnea.center"
            };


        var result =  certificate.Generate("abdurrahman.albaba@gmail.com","*.apnea.center",subjectAlternativeNames,String.Empty,"p@ssw0rd1!",String.Empty,String.Empty,String.Empty,String.Empty,String.Empty).Result;
        return;
    }
}
