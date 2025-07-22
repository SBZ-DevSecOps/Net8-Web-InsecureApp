using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace InsecureAppWebNet8.Data
{
    public class ProductDbContextFactory : IDesignTimeDbContextFactory<ProductDbContext>
    {
        public ProductDbContext CreateDbContext(string[] args)
        {
            // Charge la configuration depuis appsettings.json à la racine du projet
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory()) // Assure-toi d’être dans le bon dossier
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            // Récupère la chaîne de connexion PostgreSQL
            string connectionString = configuration.GetConnectionString("NpgConnection");

            var optionsBuilder = new DbContextOptionsBuilder<ProductDbContext>();
            optionsBuilder.UseNpgsql(connectionString);

            return new ProductDbContext(optionsBuilder.Options);
        }
    }
}
