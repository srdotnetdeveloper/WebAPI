using External_BearerTokenImplementation.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace External_BearerTokenImplementation
{
    public class MyDbContext : DbContext
    {
        public MyDbContext():base("MyTestTokenConnection")
        {
            Database.SetInitializer<MyDbContext>(new CreateDatabaseIfNotExists<MyDbContext>());


        }
        public DbSet<UserMasters> UserMasters { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Configurations.Add(new UserMasterDAL());
        }
        public class DatabaseInitializer : CreateDatabaseIfNotExists<MyDbContext>
        {
            protected override void Seed(MyDbContext context)
            {
                base.Seed(context);

            }
            
        }
    }
}