using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ad
{
    internal class user
    {
        public string Name { get; set; } = "";
        public string Email { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string SecondName { get; set; } = "";
        public string PhoneNumber { get; set; } = "";
        public string office { get; set; } = "";
        public string userPrincipalName { get; set; } = "";
        public string department { get; set; } = "";
        public string company { get; set; } = "";
        public string title { get; set; } = "";
        public string dist { get; set; } = "";
        public string div { get; set; } = "";
        public string hom { get; set; } = "";
        public string Sid { get; set; } = "";
        public Byte[] Photo { get; set; }
        public DateTime LastLogon { get; set; }
        public string lastModify { get; set; } = "";
        public string whenCreated { get; set; } = "";
        public string AccountStatus { get; set; } = "";
    }
}
