using Microsoft.EntityFrameworkCore;
using System;
using InsecureAppWebNet8.Models;

namespace InsecureAppWebNet8.Data
{
    public class ProductDbContext : DbContext
    {
        public DbSet<Product> Products { get; set; }

        public ProductDbContext(DbContextOptions<ProductDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Product>().HasData(
                new Product { Id = 1, Name = "canapé", Description = "canapé bleu en tissu" },
                new Product { Id = 2, Name = "ventilateur", Description = "ventilateur sur pied en chrome" },
                new Product { Id = 3, Name = "wok", Description = "wok traditionnel en acier" }
            );
        }
    }
}
