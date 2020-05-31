using External_BearerTokenImplementation.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity.ModelConfiguration;
using System.Linq;
using System.Web;

namespace External_BearerTokenImplementation
{
    public class UserMasterDAL : EntityTypeConfiguration<UserMasters>
    {
        public UserMasterDAL()
        {
            Property(p => p.UserID);
            Property(p => p.UserName);
            Property(p => p.UserPassword);
            Property(p => p.UserRoles);
            Property(p => p.UserEmailID);
        }
    }
}