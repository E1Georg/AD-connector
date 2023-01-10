using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.AccountManagement;
using System.Management;
using CommandLine;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace ad
{
    [Flags()]
    public enum UserAccountControl : int
    {
        SCRIPT = 0x00000001,
        ACCOUNTDISABLE = 0x00000002,
        HOMEDIR_REQUIRED = 0x00000008,
        LOCKOUT = 0x00000010,
        PASSWD_NOTREQD = 0x00000020,
        PASSWD_CANT_CHANGE = 0x00000040,
        ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
        TEMP_DUPLICATE_ACCOUNT = 0x00000100,
        NORMAL_ACCOUNT = 0x00000200,
        INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
        WORKSTATION_TRUST_ACCOUNT = 0x00001000,
        SERVER_TRUST_ACCOUNT = 0x00002000,
        Unused1 = 0x00004000,
        Unused2 = 0x00008000,
        DONT_EXPIRE_PASSWD = 0x00010000,
        MNS_LOGON_ACCOUNT = 0x00020000,
        SMARTCARD_REQUIRED = 0x00040000,
        TRUSTED_FOR_DELEGATION = 0x00080000,
        NOT_DELEGATED = 0x00100000,
        USE_DES_KEY_ONLY = 0x00200000,
        DONT_REQUIRE_PREAUTH = 0x00400000,
        PASSWORD_EXPIRED = 0x00800000,
        TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
        PARTIAL_SECRETS_ACCOUNT = 0x04000000,
        USE_AES_KEYS = 0x08000000
    }

    internal class Program
    {
        public static string userDirPath = "";
        public static string computerDirPath = "";
        public static string domain = "";
        public static string searchGroup = "";
        public static string organizationUnity = "";
        public static string timeFilter = "";
        
        public class Options 
        {
            [Option('v', "validate", Required = false, HelpText = "validate user. Example: --validate --user AccountName --password AccountPass --searchGroup Security")]
            public bool Validate { get; set; }

            [Option('u', "user", Required = false, HelpText = "Need for validate user.")]
            public string user { get; set; } = "";

            [Option('p', "password", Required = false, HelpText = "Need for validate user.")]
            public string password { get; set; } = "";

            [Option('s',"sync", Required = false, HelpText = "synchronization with AD. Example with filter: --sync --organizationUnity OU=***,DC=*** ")]
            public bool Sync { get; set; }

            [Option("param", Required = false, HelpText = "Necessary for passing parameters to the function. Example: --param val_1-val_2-val_3")]
            public string param { get; set; } = "";

            [Option("getUserInfo", Required = false, HelpText = "get info about user by network name. Example: --getUserInfo AccountName")]
            public string UserInfo { get; set; } = "";

            [Option("getAllUserInfo", Required = false, HelpText = "get info about all users. May be use with Filter. Example with filter: --getAllUserInfo --organizationUnity OU=***,DC=***")]
            public bool AllUserInfo { get; set; }

            [Option("getGroupUsers", Required = false, HelpText = "get all users in group. Example: --getGroupUsers security")]
            public string GroupUsers { get; set; } = "";

            [Option("getPCInfo", Required = false, HelpText = "get info about pc by network name.")]
            public string PCInfo { get; set; } = "";           

            [Option("userDirPath", Required = false, HelpText = "Set user directory.")]
            public string userDirPath { get; set; } = "";

            [Option("computerDirPath", Required = false, HelpText = "Set computer directory.")]
            public string computerDirPath { get; set; } = "";

            [Option("searchGroup", Required = false, HelpText = "Set name of group for search user in certain directory.")]
            public string searchGroup { get; set; } = "";

            [Option("domain", Required = false, HelpText = "Set domain. If domainString is empty - domain will found automatically")]
            public string domain { get; set; } = "";

            [Option("organizationUnity", Required = false, HelpText = "Set filter(organizationUnity). Use with --getAllUserInfo or --sync")]
            public string organizationUnity { get; set; } = "";

            [Option('m',"mac", Required = false, HelpText = "get mac by ip")]
            public string getMAC { get; set; } = "";

            [Option("process", Required = false, HelpText = "get process by ip")]
            public string getProcess { get; set; } = "";

            [Option('q', "query", Required = false, HelpText = "get query to Win32 by ip")]
            public string getQuery { get; set; } = "";

            [Option("getSoft", Required = false, HelpText = "get soft by ip")]
            public string getSoft { get; set; } = "";

            [Option("getService", Required = false, HelpText = "get service by ip")]
            public string getService { get; set; } = "";

            [Option("getCPU", Required = false, HelpText = "get CPU by ip")]
            public string getCPU { get; set; } = "";

            [Option("getGPU", Required = false, HelpText = "get CPU by ip")]
            public string getGPU { get; set; } = "";

            [Option("getRAM", Required = false, HelpText = "get RAM by ip")]
            public string getRAM { get; set; } = "";

            [Option("getAccountInRemotePC", Required = false, HelpText = "get Account in remote PC by ip")]
            public string getAccountInRemotePC { get; set; } = "";
            
            [Option("getShareFolder", Required = false, HelpText = "get share Folder by ip")]
            public string getShareFolder { get; set; } = "";

            [Option("getMB", Required = false, HelpText = "get mother board by ip")]
            public string getMB { get; set; } = "";

            [Option("getDisk", Required = false, HelpText = "get disk by ip")]
            public string getDisk { get; set; } = "";

            [Option("ip", Required = false, HelpText = "set ip for query")]
            public string ip { get; set; } = "localhost";

            [Option("timeFilter", Required = false, HelpText = "set Filter on time if you need filtering users by the date of editing profiles")]
            public string timeFilter { get; set; } = "";

            [Option("getStructureAD", Required = false, HelpText = "get all organization units in AD")]
            public bool getStructureAD { get; set; }

            [Option("getPCfromAD", Required = false, HelpText = "get all PC record from AD")]
            public bool getPCfromAD { get; set; }

            [Option("getAllGroups", Required = false, HelpText = "get all groups exists in AD")]
            public bool getAllGroups { get; set; }

            [Option("getAllUserWithGroupFilter", Required = false, HelpText = "get all user sorted by groups")]
            public bool getAllUserWithGroupFilter { get; set; }

            [Option("getUserWithInfinityPass", Required = false, HelpText = "get all user wich have non-expiring password")]
            public bool getUserWithInfinityPass { get; set; }

            [Option("getEventsFromPC", Required = false, HelpText = "get events from security log from user's PC. Necessary parameters: IP, EventCode, EventType, Period in hours. Example: --getEventsFromPC 192.168.0.101 --param 4624-2-48")]
            public string getEventsFromPC { get; set; } = "";

            [Option("checkUserSession", Required = false, HelpText = "get an EntryEvent and an associated ExitEvent from security log. Necessary host IP and Period in hours. Example: --checkUserSession 192.168.0.101 --param 48")]
            public string checkUserSession { get; set; } = "";

        }
        
        static void Main(string[] args)
        {
            try
            {
                Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
                    {
                        Console.OutputEncoding = Encoding.UTF8;
                        if (o.organizationUnity.Length > 0)
                            organizationUnity = o.organizationUnity;

                        if (o.domain.Length > 0)
                            domain = o.domain;

                        if (o.timeFilter.Length > 0)
                            timeFilter = o.timeFilter;

                        if (o.Validate)
                        {                          
                            if (o.userDirPath.Length > 0)
                                userDirPath = o.userDirPath;
                            
                            if (o.computerDirPath.Length > 0)
                                computerDirPath = o.computerDirPath;                           

                            if (o.user.Length == 0 || o.password.Length == 0)
                            {
                                Console.WriteLine("no user or password");
                                Environment.Exit(-3);
                            }
                            else
                            {
                                if (validate(o.user, o.password))
                                    if (checkStayGroup(searchGroup, o.user))
                                        GetUserInfo(o.user);
                                    else
                                    {
                                        Console.WriteLine("Пользователь не является администратором ИБ!");
                                        Environment.Exit(-1);
                                    }
                                else
                                {
                                    Console.WriteLine("Пользователь не прошёл аутентификацию!");
                                    Environment.Exit(-1);
                                }                                    
                            }
                        }
                        
                        if (o.Sync)
                            Sync();
                        
                        if (o.UserInfo.Length > 0)
                            GetUserInfo(o.UserInfo);
                        
                        if (o.GroupUsers.Length > 0)
                            GetGroupUsers(o.GroupUsers);
                        
                        if (o.AllUserInfo)
                            getAllUsers();
                        
                        if (o.getQuery.Length > 0)
                            GetQuery(o.ip, o.getQuery, new string[]{});
                        
                        if (o.getMAC.Length > 0)
                            GetMACByIp(o.getMAC);
                        
                        if (o.getProcess.Length > 0)
                            GetProcess(o.getProcess);
                        
                        if (o.getService.Length > 0)
                            getService(o.getService);
                        
                        if (o.getSoft.Length > 0)
                            getSoft(o.getSoft);
                        
                        if (o.PCInfo.Length > 0)
                            GetPCInfo(o.PCInfo);
                        
                        if (o.getCPU.Length > 0)
                            getCPU(o.getCPU);
                        
                        if (o.getMB.Length > 0)
                            getMB(o.getMB);
                        
                        if (o.getGPU.Length > 0)
                            getGPU(o.getGPU);

                        if (o.getAccountInRemotePC.Length > 0)
                            getAccountInRemotePC(o.getAccountInRemotePC);
                        
                        if (o.getRAM.Length > 0)
                            getRAM(o.getRAM);

                        if (o.getShareFolder.Length > 0)
                            getShareFolder(o.getShareFolder);

                        if (o.getDisk.Length > 0)
                            getDisk(o.getDisk);
                        
                        if (o.getStructureAD)
                            GetStructureAD();

                        if (o.getPCfromAD)
                            getPCfromAD();
                        
                        if (o.getAllGroups)
                            getAllGroups();

                        if (o.getAllUserWithGroupFilter)
                            getAllUserWithGroupFilter();

                        if (o.getUserWithInfinityPass)
                            getUserWithInfinityPass();

                        if (o.getEventsFromPC.Length > 0)
                            getEventsFromPC(o.getEventsFromPC, o.param);

                        if (o.checkUserSession.Length > 0)
                            checkUserSession(o.checkUserSession, o.param);
                    });              
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
                Console.WriteLine(ex.TargetSite);        
            }
        }

        public static bool validate(string user, string password)
        {
            try
            {
                LdapConnection connection = new LdapConnection(domain);
                NetworkCredential credential = new NetworkCredential(user, password);
                connection.Credential = credential;
                connection.Bind();
                return true;                
            }
            catch (LdapException lexc)
            {
                string error = lexc.ServerErrorMessage;
                Console.WriteLine("ERROR: " + lexc);
                Console.WriteLine("authentification failed");
                return false;
            }
            catch(Exception  exc)
            {
                Console.WriteLine("ERROR: " + exc);
                return false;
            }
        }

        public static void getAllUsers()
        {   
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                if (organizationUnity != "")
                {
                    string path = "LDAP://" + organizationUnity;
                    entry.Path = path;
                }
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.Filter = $"(userPrincipalName=*)";

                var users = searcher.FindAll();
                foreach (System.DirectoryServices.SearchResult user in users)
                {
                    Console.WriteLine("------------------------------------");
                    foreach (string property in user.GetDirectoryEntry().Properties.PropertyNames)
                    {
                        string value = user.GetDirectoryEntry().Properties[property][0].ToString();
                        Console.WriteLine(property + ":" + value);
                    }          
                    Console.WriteLine("------------------------------------");

                }
                Environment.Exit(0);
            }
            catch(Exception exc)
            {
                Console.WriteLine("Error: " + exc.Message);
                Environment.Exit(-1);
            }
        }

        public static void Sync()
        {
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                if (organizationUnity != "")
                {
                    string path = "LDAP://" + organizationUnity;  // + ",DC = corp,DC=podzem-remont,DC=gazprom,DC=ru"; //DN ERROR
                    entry.Path = path;
                }
                
                DirectorySearcher searcher = new DirectorySearcher(entry);
                List<user> output = new List<user> { };
                List<user> output_withCheckLastLogon = new List<user> { };
                user user;                                
                         
                var ctime = DateTime.UtcNow.AddYears(-50).ToString("yyyyMMddHHmmss.0Z");
                bool timeflag = false;

                if (timeFilter != "")
                {
                    timeflag = true;
                    timeFilter = timeFilter.Replace("/", " ");                    
                    DateTime time = Convert.ToDateTime(timeFilter);
                    ctime = time.ToString("yyyyMMddHHmmss.0Z");                    
                }                
                searcher.PageSize = 1000;
                searcher.Filter = $"(&(userPrincipalName=*)(whenChanged>={ctime}))";
                searcher.PropertiesToLoad.AddRange(new[] { "sAMAccountName", "mail", "givenName", "sn", "telephoneNumber", "physicalDeliveryOfficeName", "userPrincipalName", "department", "company", "title", "DistinguishedName", "Division", "HomeDirectory", "objectSid", "lastLogon", "thumbnailPhoto", "whenChanged", "whenCreated", "userAccountControl"});

                DateTime lastDate1 = DateTime.MinValue;
                DateTime lastDate2 = DateTime.MinValue;
                DateTime myDate = DateTime.MinValue;

                foreach (SearchResult searchResult in searcher.FindAll())
                {
                    user = new user();

                    if (searchResult.Properties.Contains("sAMAccountName"))
                        user.Name = searchResult.Properties["sAMAccountName"][0].ToString();

                    if (searchResult.Properties.Contains("mail"))
                        user.Email = searchResult.Properties["mail"][0].ToString();

                    if (searchResult.Properties.Contains("givenName"))
                        user.FirstName = searchResult.Properties["givenName"][0].ToString();

                    if (searchResult.Properties.Contains("sn"))
                        user.SecondName = searchResult.Properties["sn"][0].ToString();

                    if (searchResult.Properties.Contains("telephoneNumber"))
                        user.PhoneNumber = searchResult.Properties["telephoneNumber"][0].ToString();

                    if (searchResult.Properties.Contains("physicalDeliveryOfficeName"))
                        user.office = searchResult.Properties["physicalDeliveryOfficeName"][0].ToString();

                    if (searchResult.Properties.Contains("userPrincipalName"))
                        user.userPrincipalName = searchResult.Properties["userPrincipalName"][0].ToString();

                    if (searchResult.Properties.Contains("department"))
                        user.department = searchResult.Properties["department"][0].ToString();

                    if (searchResult.Properties.Contains("company"))
                        user.company = searchResult.Properties["company"][0].ToString();

                    if (searchResult.Properties.Contains("title"))
                        user.title = searchResult.Properties["title"][0].ToString();

                    if (searchResult.Properties.Contains("DistinguishedName"))
                        user.dist = searchResult.Properties["DistinguishedName"][0].ToString();

                    if (searchResult.Properties.Contains("Division"))
                        user.div = searchResult.Properties["Division"][0].ToString();

                    if (searchResult.Properties.Contains("HomeDirectory"))
                        user.hom = searchResult.Properties["HomeDirectory"][0].ToString();

                    if (searchResult.Properties.Contains("objectSid"))
                    {
                        Byte[] SIDBytes = (Byte[])searchResult.Properties["objectSid"][0];
                        System.Security.Principal.SecurityIdentifier SID = new System.Security.Principal.SecurityIdentifier(SIDBytes, 0);
                        user.Sid = SID.ToString();
                    }

                    if (searchResult.Properties.Contains("lastLogon"))
                        user.LastLogon = DateTime.FromFileTime((long)searchResult.Properties["lastLogon"][0]);

                    if (searchResult.Properties.Contains("thumbnailPhoto"))
                    {
                        Byte[] temp = (Byte[])searchResult.Properties["thumbnailPhoto"][0];
                        user.Photo = temp;
                    }

                    if (searchResult.Properties.Contains("whenChanged"))
                        user.lastModify = searchResult.Properties["whenChanged"][0].ToString();

                    if (searchResult.Properties.Contains("whenCreated"))
                        user.whenCreated = searchResult.Properties["whenCreated"][0].ToString();

                    if (searchResult.Properties.Contains("userAccountControl"))
                    {
                        int userAccountControl = Convert.ToInt32(searchResult.Properties["userAccountControl"][0]);
                        bool disabled = ((userAccountControl & 2) > 0);
                        user.AccountStatus = disabled == false ? "Enabled" : "Disabled";
                    }

                    myDate = DateTime.MinValue;

                    if (user.lastModify != "")
                        myDate = DateTime.ParseExact(user.lastModify, "d.M.yyyy H:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

                    if (myDate > lastDate1)
                        lastDate1 = myDate;                    

                    output.Add(user);
                }

                timeflag = true;

                if (timeflag)
                {                    
                    var lastTime = DateTime.Now.AddDays(-90).ToFileTime();
                    searcher.Filter = $"(&(userPrincipalName=*)(lastLogon<={lastTime}))";

                    foreach (SearchResult searchResult in searcher.FindAll())
                    {
                        user = new user();

                        if (searchResult.Properties.Contains("userAccountControl"))
                        {
                            int userAccountControl = Convert.ToInt32(searchResult.Properties["userAccountControl"][0]);
                            bool disabled = ((userAccountControl & 2) > 0);
                            user.AccountStatus = disabled == false ? "Enabled" : "Disabled";
                        }

                        if (user.AccountStatus == "Enabled")
                        {
                            if (searchResult.Properties.Contains("sAMAccountName"))
                                user.Name = searchResult.Properties["sAMAccountName"][0].ToString();

                            if (searchResult.Properties.Contains("givenName"))
                                user.FirstName = searchResult.Properties["givenName"][0].ToString();

                            if (searchResult.Properties.Contains("sn"))
                                user.SecondName = searchResult.Properties["sn"][0].ToString();

                            if (searchResult.Properties.Contains("userPrincipalName"))
                                user.userPrincipalName = searchResult.Properties["userPrincipalName"][0].ToString();

                            if (searchResult.Properties.Contains("DistinguishedName"))
                                user.dist = searchResult.Properties["DistinguishedName"][0].ToString();

                            if (searchResult.Properties.Contains("objectSid"))
                            {
                                Byte[] SIDBytes = (Byte[])searchResult.Properties["objectSid"][0];
                                System.Security.Principal.SecurityIdentifier SID = new System.Security.Principal.SecurityIdentifier(SIDBytes, 0);
                                user.Sid = SID.ToString();
                            }

                            if (searchResult.Properties.Contains("lastLogon"))
                                user.LastLogon = DateTime.FromFileTime((long)searchResult.Properties["lastLogon"][0]);

                            if (searchResult.Properties.Contains("whenChanged"))
                                user.lastModify = searchResult.Properties["whenChanged"][0].ToString();

                            myDate = DateTime.MinValue;

                            if (user.lastModify != "")
                                myDate = DateTime.ParseExact(user.lastModify, "d.M.yyyy H:mm:ss", System.Globalization.CultureInfo.InvariantCulture);                              
            
                            if (myDate > lastDate2)
                                lastDate2 = myDate;

                            output_withCheckLastLogon.Add(user);
                        }
                    }                                        
                }

                var answer_1 = new { lastModify = lastDate1, data = output };
                var answer_2 = new { lastModify = lastDate2, data = output_withCheckLastLogon };                

                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject( new { standartAccounts = answer_1, accountsWitchCheck = answer_2 })}");
                Environment.Exit(0);
            }
            catch(Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error Sync()");
                Environment.Exit(-1);
            }
        }

        public static void getUserWithInfinityPass()
        {
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(entry);
                var output = new List<Tuple<string, string>>().Select(t => new { name = t.Item1, dist = t.Item2 }).ToList();
                bool passwordStatus = false;

                searcher.PageSize = 1000;
                searcher.Filter = "(&(userPrincipalName=*))";
                searcher.PropertiesToLoad.AddRange(new[] { "sAMAccountName", "DistinguishedName", "userAccountControl" });

                string name = "";
                string dist = "";

                foreach (SearchResult searchResult in searcher.FindAll())
                {

                    if (searchResult.Properties.Contains("userAccountControl"))
                    {
                        int userAccountControl = Convert.ToInt32(searchResult.Properties["userAccountControl"][0]);
                        passwordStatus = ((userAccountControl & 65536) > 0);

                        if (passwordStatus)
                        {
                            if (searchResult.Properties.Contains("sAMAccountName"))
                                name = searchResult.Properties["sAMAccountName"][0].ToString();

                            if (searchResult.Properties.Contains("DistinguishedName"))
                                dist = searchResult.Properties["DistinguishedName"][0].ToString();

                            output.Add(new { name = name, dist = dist });
                        }

                    }
                }

                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(output)}");
                Environment.Exit(0);
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error getUserWithInfinityPass()");
                Environment.Exit(-1);
            }
        }

        public static void getFullMembers(string lastModify, IEnumerable<dynamic> groups)
        {
            try
            {
                var data = new List<Tuple<string, string, List<string>, List<string>>>().Select(t => new { group = t.Item1, sid = t.Item2, users = t.Item3, insideGroups = t.Item4 }).ToList();
                var main = new List<Tuple<string, string>>().Select(t => new { group = t.Item1, sid = t.Item2 }).ToList();


                foreach (var item in groups)
                {
                    string group_A = item.group;
                    string sid_A = item.sid;
                    main.Add(new { group = group_A, sid = sid_A });
                }

                foreach (var element in main)
                {
                    var groupname = element.group;
                    var members_person = new List<string>();
                    var members_group = new List<string>();

                    DirectoryEntry entry = new DirectoryEntry();
                    var searcher = new DirectorySearcher(entry);

                    searcher.Filter = "(&(objectCategory=group)(objectClass=group)(cn=" + groupname + "))";
                    searcher.PropertiesToLoad.Add("member");

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        foreach (var member in result.Properties["member"])
                        {
                            DirectoryEntry entry2 = new DirectoryEntry();
                            entry2.Path = "LDAP://" + member;
                            DirectorySearcher searcher2 = new DirectorySearcher(entry2);

                            searcher2.PropertiesToLoad.AddRange(new[] { "sAMAccountName" });

                            // Список входящих пользователей
                            searcher2.Filter = "(&(objectClass=user)(objectCategory=person))";
                            SearchResult results = searcher2.FindOne();

                            if (results != null)
                                if (results.Properties.Contains("sAMAccountName"))
                                {
                                    string person = results.Properties["sAMAccountName"][0].ToString();
                                    members_person.Add(person);
                                }

                            // Список входящих групп
                            searcher2.Filter = "(&(objectClass=group)(objectCategory=group))";
                            SearchResult results2 = searcher2.FindOne();

                            if (results2 != null)
                                if (results2.Properties.Contains("sAMAccountName"))
                                {
                                    string group = results2.Properties["sAMAccountName"][0].ToString();
                                    members_group.Add(group);
                                }
                        }
                    }
                    data.Add(new { group = groupname, sid = element.sid, users = members_person, insideGroups = members_group });
                }
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(new { lastModify = lastModify, groups = data })}");
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error getFullMembers()");
                Environment.Exit(-1);
            }
        }

        public static void getAllUserWithGroupFilter()
        {
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.Filter = $"(objectClass=group)";
                searcher.PropertiesToLoad.AddRange(new[] { "name", "whenChanged", "objectSid" });

                var groups = new List<Tuple<string, string>>().Select(t => new { group = t.Item1, sid = t.Item2 }).ToList();

                string lastModify = "";
                string nameGroup = "";
                string sid = "";
                DateTime lastDate = DateTime.MinValue;
                DateTime myDate = DateTime.MinValue;

                foreach (SearchResult searchResult in searcher.FindAll())
                {
                    if (searchResult.Properties.Contains("name"))
                    {
                        nameGroup = searchResult.Properties["name"][0].ToString();

                        if (searchResult.Properties.Contains("objectSid"))
                        {
                            Byte[] SIDBytes = (Byte[])searchResult.Properties["objectSid"][0];
                            System.Security.Principal.SecurityIdentifier SID = new System.Security.Principal.SecurityIdentifier(SIDBytes, 0);
                            sid = SID.ToString();

                            groups.Add(new { group = nameGroup, sid = sid });
                        }
                    }

                    if (searchResult.Properties.Contains("whenChanged"))
                        lastModify = searchResult.Properties["whenChanged"][0].ToString();

                    myDate = DateTime.MinValue;

                    if (lastModify != "")
                        myDate = DateTime.ParseExact(lastModify, "d.M.yyyy H:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

                    if (myDate > lastDate)
                        lastDate = myDate;
                }

                getFullMembers(lastDate.ToString(), groups);
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error getAllUserWithGroupFilter()");
                Environment.Exit(-1);
            }           
        }
        
        static void getEventsFromPC(string ip, string param)
        {
            var output_logon = new List<Tuple<string, string, DateTime, string, string, string, string>>().Select(t => new { ComputerName = t.Item1, AccountName = t.Item2, TimeGenerated = t.Item3, SourceName = t.Item4, EventCode = t.Item5, logon_ID = t.Item6, AdditionalInfo = t.Item7 }).ToList();
            int EventCode = 0, EventType = 2, Hours = 48;

            string pattern_EventType = @"\d+";
            string pattern_EventTypeString = @"Тип входа:\s*\d+";
            string pattern_logonUID = @"Код входа:\s*\w+";
            string pattern_AccountName = @"Имя учетной записи:\s*\w+";
            string pattern_param = @"\d+-\d+-\d+";

            Regex regex_EventType = new Regex(pattern_EventType);
            Regex regex_EventTypeString = new Regex(pattern_EventTypeString);
            Regex regex_AccountName = new Regex(pattern_AccountName);
            Regex regex_logonUID = new Regex(pattern_logonUID);
            Regex regex_param = new Regex(pattern_param);
            MatchCollection matches;

            matches = regex_param.Matches(param);
            if (matches.Count > 0)
            {
                Match match = matches[0];
                string[] words = match.Value.Split('-');
                EventCode = Convert.ToInt32(words[0]);
                EventType = Convert.ToInt32(words[1]);
                Hours = Convert.ToInt32(words[2]);
            }
            else
            {
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(new { error = "Incorrect param string" })}");
                return;
            }

            try
            {
                ConnectionOptions oConn = new ConnectionOptions();
                oConn.Impersonation = ImpersonationLevel.Impersonate;
                oConn.EnablePrivileges = true;

                List<string> arrComputers = new List<string> { }; // Задел на то, если потребуется собрать Events сразу с нескольких ПК
                arrComputers.Add(ip);

                var d = DateTimeOffset.Now.AddHours(-1 * Hours);
                var wmiDate = String.Format("{0:yyyyMMddHHmmss.ffffff}{1}", d, d.Offset.TotalMinutes);

                foreach (string strComputer in arrComputers)
                {

                    ManagementObjectSearcher searcher = new ManagementObjectSearcher
                    (
                       new ManagementScope("\\\\" + strComputer + "\\root\\CIMV2", oConn),
                       new ObjectQuery(@"SELECT * FROM Win32_NTLogEvent WHERE EventIdentifier = " + EventCode + " AND Logfile = 'Security' AND TimeGenerated >='" + wmiDate + "'")
                    );


                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        matches = regex_EventTypeString.Matches(queryObj["Message"].ToString());
                        if (matches.Count > 0)
                        {
                            foreach (Match match in matches)
                            {
                                var matches2 = regex_EventType.Matches(match.Value);
                                if (matches2.Count > 0)
                                    foreach (Match match2 in matches2)
                                    {
                                        int type = Convert.ToInt32(match2.Value);
                                        if (type == EventType)
                                        {
                                            DateTime dt = System.Management.ManagementDateTimeConverter.ToDateTime(queryObj["TimeGenerated"].ToString());

                                            var index_start = queryObj["Message"].ToString().IndexOf("Новый вход:");
                                            var index_end = queryObj["Message"].ToString().IndexOf("GUID");
                                            string message = queryObj["Message"].ToString().Substring(index_start, index_end);
                                            var matches3 = regex_AccountName.Matches(message);
                                            var matches4 = regex_logonUID.Matches(message);
                                            string temp_account = "";
                                            string temp_additionalInfo = "";
                                            string temp = "";
                                            string logon_id = "";

                                            if (matches3.Count > 0)
                                            {
                                                Match match3 = matches3[0];
                                                temp_account = match3.Value;
                                                temp_account = temp_account.Substring(19);
                                                temp_account = temp_account.Trim();
                                            }
                                            else
                                                temp_account = "-";

                                            if (matches4.Count > 0)
                                            {
                                                Match match4 = matches4[0];
                                                logon_id = match4.Value;
                                                logon_id = logon_id.Substring(10);
                                                logon_id = logon_id.Trim();
                                            }
                                            else
                                                logon_id = "undefined";

                                            index_end = queryObj["Message"].ToString().IndexOf("Субъект:");
                                            temp_additionalInfo = queryObj["Message"].ToString().Substring(0, index_end);

                                            temp = EventCode + "-" + match2.Value;
                                            output_logon.Add(new { ComputerName = queryObj["ComputerName"].ToString(), AccountName = temp_account, TimeGenerated = dt, SourceName = queryObj["SourceName"].ToString(), EventCode = temp, logon_ID = logon_id, AdditionalInfo = temp_additionalInfo.Trim() });
                                        }
                                        else
                                            continue;
                                    }

                                else
                                    continue;
                            }
                        }
                        else
                            continue;
                    }
                }
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(output_logon)}");
            }
            catch (ManagementException err)
            {
                string error = "An error occurred while querying for WMI data: " + err.Message;
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(new { error = error })}");
            }

        }

        static void checkUserSession(string ip, string param)
        {
            var output_logon = new List<Tuple<string, string, DateTime, string, string, string, string>>().Select(t => new { ComputerName = t.Item1, AccountName = t.Item2, TimeGenerated = t.Item3, SourceName = t.Item4, EventCode = t.Item5, logon_ID = t.Item6, AdditionalInfo = t.Item7 }).ToList();
            int EventCode = 0, EventType=2, Hours=48;

            string pattern_EventType = @"\d+";
            string pattern_EventTypeString = @"Тип входа:\s*\d+";
            string pattern_logonUID = @"Код входа:\s*\w+";
            string pattern_AccountName = @"Имя учетной записи:\s*\w+";
            string pattern_param = @"\d+-\d+-\d+";

            Regex regex_EventType = new Regex(pattern_EventType);
            Regex regex_EventTypeString = new Regex(pattern_EventTypeString);
            Regex regex_AccountName = new Regex(pattern_AccountName);
            Regex regex_logonUID = new Regex(pattern_logonUID);
            Regex regex_param = new Regex(pattern_param);
            MatchCollection matches;

            matches = regex_param.Matches(param);
            if (matches.Count > 0)
            {
                Match match = matches[0];
                string[] words = match.Value.Split('-');
                EventCode = Convert.ToInt32(words[0]);
                EventType = Convert.ToInt32(words[1]);
                Hours = Convert.ToInt32(words[2]);
            }
            else
            { 
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(new { error = "Incorrect param string" })}"); 
                return;
            }

            try
            {
                ConnectionOptions oConn = new ConnectionOptions();
                oConn.Impersonation = ImpersonationLevel.Impersonate;
                oConn.EnablePrivileges = true;

                List <string> arrComputers = new List<string>{ }; // Задел на то, что если потребуется собрать Events сразу с нескольких ПК
                arrComputers.Add(ip);

                var d = DateTimeOffset.Now.AddHours(-1 * Hours);
                var wmiDate = String.Format("{0:yyyyMMddHHmmss.ffffff}{1}", d, d.Offset.TotalMinutes);

                foreach (string strComputer in arrComputers)
                {

                    ManagementObjectSearcher searcher = new ManagementObjectSearcher
                    (
                       new ManagementScope("\\\\" + strComputer + "\\root\\CIMV2", oConn),
                       new ObjectQuery(@"SELECT * FROM Win32_NTLogEvent WHERE EventIdentifier = " + EventCode + " AND Logfile = 'Security' AND TimeGenerated >='" + wmiDate + "'")
                    );


                    foreach (ManagementObject queryObj in searcher.Get())
                    {                        
                        matches = regex_EventTypeString.Matches(queryObj["Message"].ToString());
                        if (matches.Count > 0)
                        {
                            foreach (Match match in matches)
                            {
                                var matches2 = regex_EventType.Matches(match.Value);
                                if (matches2.Count > 0)
                                    foreach (Match match2 in matches2)
                                    {
                                        int type = Convert.ToInt32(match2.Value);
                                        if (type == EventType)
                                        {
                                            DateTime dt = System.Management.ManagementDateTimeConverter.ToDateTime(queryObj["TimeGenerated"].ToString());
                                         
                                            var index_start = queryObj["Message"].ToString().IndexOf("Новый вход:");
                                            var index_end = queryObj["Message"].ToString().IndexOf("GUID");
                                            string message = queryObj["Message"].ToString().Substring(index_start, index_end);
                                            var matches3 = regex_AccountName.Matches(message);
                                            var matches4 = regex_logonUID.Matches(message);
                                            string temp_account = "";
                                            string temp_additionalInfo = "";
                                            string temp = "";
                                            string logon_id = "";

                                            if (matches3.Count > 0)
                                            {
                                                Match match3 = matches3[0];
                                                temp_account = match3.Value;
                                                temp_account = temp_account.Substring(19);
                                                temp_account = temp_account.Trim();
                                            }
                                            else
                                                temp_account = "-";

                                            if (matches4.Count > 0)
                                            {
                                                Match match4 = matches4[0];
                                                logon_id = match4.Value;
                                                logon_id = logon_id.Substring(10);
                                                logon_id = logon_id.Trim();
                                            }
                                            else
                                                logon_id = "undefined";

                                            index_end = queryObj["Message"].ToString().IndexOf("Субъект:");
                                            temp_additionalInfo = queryObj["Message"].ToString().Substring(0, index_end);

                                            temp = EventCode + "-" + match2.Value;
                                            output_logon.Add(new { ComputerName = queryObj["ComputerName"].ToString(), AccountName = temp_account, TimeGenerated = dt, SourceName = queryObj["SourceName"].ToString(), EventCode = temp, logon_ID = logon_id, AdditionalInfo = temp_additionalInfo.Trim() });
                                        }
                                        else
                                            continue;
                                    }

                                else
                                    continue;
                            }
                        }
                        else
                            continue;
                    }
                }

                // EventExit
                var output_logoff = new List<Tuple<string, DateTime, string>>().Select(t => new { logon_ID = t.Item1, TimeGenerated = t.Item2, AdditionalInfo = t.Item3 }).ToList();

                if ((EventType == 2) && (EventCode == 4624))
                {
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher
                    (
                       new ManagementScope("\\\\" + ip + "\\root\\CIMV2", oConn),
                       new ObjectQuery(@"SELECT * FROM Win32_NTLogEvent WHERE EventIdentifier = " + 4647 + " AND Logfile = 'Security' AND TimeGenerated >='" + wmiDate + "'")
                    );

                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        try
                        {
                            DateTime dt = System.Management.ManagementDateTimeConverter.ToDateTime(queryObj["TimeGenerated"].ToString());

                            var index_start = queryObj["Message"].ToString().IndexOf("Субъект:");
                            var index_end = queryObj["Message"].ToString().IndexOf("Данное событие");
                            string message = queryObj["Message"].ToString().Substring(index_start, index_end);
                            string code = "";
                            var matches5 = regex_logonUID.Matches(message);
                            if (matches5.Count > 0)
                            {
                                Match match5 = matches5[0];
                                code = match5.Value;
                                code = code.Substring(10);
                                code = code.Trim();
                            }
                            else
                                code = "undefined";                         

                            output_logoff.Add(new { logon_ID = code, TimeGenerated = dt, AdditionalInfo = "" });
                        }
                        catch(Exception err)
                        {
                            output_logoff.Add(new { logon_ID = "Exception", TimeGenerated = DateTime.Now, AdditionalInfo = err.Message });
                            continue;
                        }                       
                    }

                    // calculating duration
                    bool exist = false;
                    var answer = new List<Tuple<string, string, string, string, string, string, string>>().Select(t => new { ComputerName = t.Item1, AccountName = t.Item2, TimeGeneratedLogon = t.Item3, TimeGeneratedLogoff = t.Item4, duration = t.Item5, SourceName = t.Item6, EventCode = t.Item7 }).ToList();
                   
                    foreach (var item in output_logon)
                    {
                        exist = false;
                        for (int i = 0; i < output_logoff.Count; i++)
                            if (item.logon_ID == output_logoff[i].logon_ID)
                            {
                                TimeSpan duration = DateTime.Parse(output_logoff[i].TimeGenerated.ToString()).Subtract(DateTime.Parse(item.TimeGenerated.ToString()));
                                answer.Add(new { ComputerName = item.ComputerName, AccountName = item.AccountName, TimeGeneratedLogon = item.TimeGenerated.ToString(), TimeGeneratedLogoff = output_logoff[i].TimeGenerated.ToString(), duration = duration.ToString(), SourceName = item.SourceName, EventCode = (item.EventCode + "-" + "4634") });
                                exist = true;
                            }
                        if (exist) continue;
                        else
                            answer.Add(new { ComputerName = item.ComputerName, AccountName = item.AccountName, TimeGeneratedLogon = item.TimeGenerated.ToString(), TimeGeneratedLogoff = "undefined", duration = "undefined", SourceName = item.SourceName, EventCode = item.EventCode });
                    }


                    Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(answer)}");
                }
                else
                    Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(output_logon)}");

            }
            catch (ManagementException err)
            {
                string error = "An error occurred while querying for WMI data: " + err.Message;
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(new {error = error})}");   
            }
        }

        public static void getAllGroups()
        {
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(entry);
                searcher.Filter = $"(objectClass=group)";
                searcher.PropertiesToLoad.AddRange(new[] { "name", "objectSid", "whenChanged" });
                var data = new List<Tuple<string, string, string>>().Select(t => new { name = t.Item1, SID = t.Item2, lastModify = t.Item3 }).ToList();
                DateTime lastDate = DateTime.MinValue;

                foreach (SearchResult searchResult in searcher.FindAll())
                {
                    string name = "";
                    string Sid = "";
                    string lastModify = "";

                    if (searchResult.Properties.Contains("name"))
                        name = searchResult.Properties["name"][0].ToString();

                    if (searchResult.Properties.Contains("objectSid"))
                    {
                        Byte[] SIDBytes = (Byte[])searchResult.Properties["objectSid"][0];
                        System.Security.Principal.SecurityIdentifier SID = new System.Security.Principal.SecurityIdentifier(SIDBytes, 0);
                        Sid = SID.ToString();
                    }

                    if (searchResult.Properties.Contains("whenChanged"))
                        lastModify = searchResult.Properties["whenChanged"][0].ToString();

                    DateTime myDate = DateTime.MinValue;

                    if (lastModify != "")
                    {
                        try
                        {
                            myDate = DateTime.ParseExact(lastModify, "d.M.yyyy H:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
                        }
                        catch
                        {
                            myDate = DateTime.Now;

                        }
                    }

                    if (myDate > lastDate)
                        lastDate = myDate;

                    data.Add(new { name = name, SID = Sid, lastModify = lastModify });
                }

                var answer = new { lastModify = lastDate, data = data };
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(answer)}");
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error getAllGroups()");
                Environment.Exit(-1);
            }
        }

        public static void GetUserInfo(string user)
        {
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                if (organizationUnity != "")
                {
                    string path = "LDAP://" + organizationUnity;  // + ",DC = corp,DC=podzem-remont,DC=gazprom,DC=ru"; 
                    entry.Path = path;
                }

                DirectorySearcher searcher = new DirectorySearcher(entry);

                searcher.PageSize = 1000;
                searcher.Filter = $"(sAMAccountName={user})";
                searcher.PropertiesToLoad.AddRange(new[] { "sAMAccountName", "mail", "givenName", "sn", "telephoneNumber", "userPrincipalName", "lastLogon", "thumbnailPhoto" });
                SearchResult searchResult = searcher.FindOne();
                var data = new
                {
                    Name = searchResult.Properties["userPrincipalName"],
                    Email = searchResult.Properties["mail"],
                    FirstName = searchResult.Properties["givenName"],
                    SecondName = searchResult.Properties["sn"],
                    PhoneNumber = searchResult.Properties["telephoneNumber"],
                    LastLogon = searchResult.Properties["lastLogon"],
                    Photo = searchResult.Properties["thumbnailPhoto"]
                };

                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(data)}");
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error GetUserInfo()");
                Environment.Exit(-1);
            }
        }
        
        public static void GetStructureAD()
        {
            try
            {
                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(entry);
                var orgUnits = new List<Tuple<int, string, string>>().Select(t => new { Count = t.Item1, Path = t.Item2, UID = t.Item3 }).ToList();
                searcher.Filter = "(objectCategory=organizationalUnit)";
                searcher.PropertiesToLoad.AddRange(new[] { "distinguishedName", "objectGUID" });

                int counter = 0;
                string path = "";
                string guid = "";

                foreach (SearchResult res in searcher.FindAll())
                {
                    if (res.Properties.Contains("distinguishedName"))
                        path = res.Properties["distinguishedName"][0].ToString();

                    if (res.Properties.Contains("objectGUID"))
                        guid = (new Guid((Byte[])(Array)res.Properties["objectGUID"][0])).ToString();

                    orgUnits.Add(new { Count = counter, Path = path, UID = guid });
                    counter++;
                }
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(orgUnits)}"); 
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error GetUserInfo()");
                Environment.Exit(-1);

            }
        }

        public static void GetGroupUsers(string group)
        {
            try
            {
                PrincipalContext entry = new PrincipalContext(ContextType.Domain);
                if (domain.Length > 0)
                    entry = new PrincipalContext(ContextType.Domain, domain);            

                GroupPrincipal grp = GroupPrincipal.FindByIdentity(entry, group);
                PrincipalSearchResult<Principal> lstMembers = grp.GetMembers(true);
                var data = new List<Tuple<string>>().Select(t => new { name = t.Item1 }).ToList();
                string name = "";

                foreach (Principal member in lstMembers)
                {
                    if (member.StructuralObjectClass.Equals("user"))
                    {
                        name = member.SamAccountName.ToString();
                        data.Add(new { name = name });
                    }

                }
                Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(data)}");
            }
            catch (Exception exc) { Console.WriteLine(exc.Message); }
        }

        public static bool checkStayGroup(string group, string user)
        {
            try
            {
                PrincipalContext entry = new PrincipalContext(ContextType.Domain);
                if (domain.Length > 0)
                    entry = new PrincipalContext(ContextType.Domain, domain);

                GroupPrincipal grp = GroupPrincipal.FindByIdentity(entry, group);
                PrincipalSearchResult<Principal> lstMembers = grp.GetMembers(true);
                bool found = false;
                foreach (Principal member in lstMembers)
                {
                    if (member.StructuralObjectClass.Equals("user"))
                    {
                        if (member.SamAccountName.Equals(user))
                            found = true;
                    }
                }
                return found;
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error checkStayGroup()");
                Environment.Exit(-1);
                return false;
            }
        }

        public static void GetPCInfo(string ip)
        {            
            getCPU(ip);
            getGPU(ip);
            getMB(ip);
            getRAM(ip);
            getDisk(ip);
            GetMACByIp(ip);
            getShareFolder(ip);
        }

        public static void getPCfromAD()
        {
            //CW() внутри функции
            var temp = GetComputers();
            Console.WriteLine($"{Newtonsoft.Json.JsonConvert.SerializeObject(temp)}");
            Environment.Exit(0);
        }

        public static List<computer> GetComputers()
        {
            try
            {
                List<string> ComputerNames = new List<string>();

                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher mySearcher = new DirectorySearcher(entry);
                mySearcher.Filter = $"(objectClass=computer)";
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                mySearcher.PropertiesToLoad.AddRange(new[] { "cn", "objectSid", "lastLogon", "userAccountControl", "DistinguishedName" });
                List<computer> output = new List<computer> { };

                foreach (SearchResult searchResult in mySearcher.FindAll())
                {
                    computer computer = new computer();

                    if (searchResult.Properties.Contains("cn"))
                        computer.Name = searchResult.Properties["cn"][0].ToString();

                    if (searchResult.Properties.Contains("objectSid"))
                    {
                        Byte[] SIDBytes = (Byte[])searchResult.Properties["objectSid"][0];
                        System.Security.Principal.SecurityIdentifier SID = new System.Security.Principal.SecurityIdentifier(SIDBytes, 0);
                        computer.Sid = SID.ToString();
                    }
                    else
                    {
                        computer.Sid = "undefined";
                    }

                    if (searchResult.Properties.Contains("lastLogon"))
                        computer.LastLogon = DateTime.FromFileTime((long)searchResult.Properties["lastLogon"][0]);

                    if (searchResult.Properties.Contains("userAccountControl"))
                    {
                        int userAccountControl = Convert.ToInt32(searchResult.Properties["userAccountControl"][0]);
                        bool disabled = ((userAccountControl & 2) > 0);
                        computer.AccountStatus = disabled == false ? "Enabled" : "Disabled";
                    }

                    if (searchResult.Properties.Contains("DistinguishedName"))
                        computer.DistinguishedName = searchResult.Properties["DistinguishedName"][0].ToString();

                    output.Add(computer);
                }

                mySearcher.Dispose();
                entry.Dispose();
                return output;
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
                Console.WriteLine("Error GetComputers()");
                Environment.Exit(-1);
                return null;

            }          
        }

        public static void GetMACByIp(string ip)
        {
            GetQuery(ip, "select * from Win32_NetworkAdapter", new string[] { "name", "MACAddress", "Speed" });
        }

        public static void GetProcess(string ip)
        {
            GetQuery(ip, "select * from Win32_Process");
        }

        public static void getSoft(string ip)
        {
            GetQuery(ip, "select * from Win32_Product");
        }

        public static void getService(string ip)
        {
            GetQuery(ip, "select * from Win32_Service");
        }

        public static void getCPU(string ip)
        {
            GetQuery(ip, "select * from Win32_Processor");
        }

        public static void getGPU(string ip)
        {
            GetQuery(ip, "select * from Win32_VideoController");
        }

        public static void getRAM(string ip)
        {
            GetQuery(ip, "select * from Win32_PhysicalMemory", new string[] { "Capacity" });
        }

        public static void getDisk(string ip)
        {
            GetQuery(ip, "select * from Win32_DiskDrive", new string[] { "Size" });
        }

        public static void getMB(string ip)
        {
            GetQuery(ip, "select * from Win32_BaseBoard", new string[] { "Product" });
        }

        public static void getAccountInRemotePC(string ip)
        {
            GetQuery(ip, "select * from Win32_UserAccount", new string[] { "Name" });
        }

        public static void getShareFolder(string ip)
        {
            GetQuery(ip, "select * from Win32_Share", new string[] { "Path", "Name", "Caption" });
        }

        public static void GetQuery(string ip, string query, string[] fields = null)
        {
            try
            {
                // Осуществляем подключение к пространству имен root\cimv2 удаленной машины
                ManagementScope scope = new ManagementScope(@"\\" + ip + @"\root\cimv2");
                scope.Connect();
                if (scope.IsConnected)
                {
                    ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"\\" + ip + @"\root\cimv2", query);

                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if(fields != null)
                        {
                            if (fields.Length > 0)
                                for (int i = 0; i < fields.Length; i++)
                                    Console.WriteLine($"{fields[i]}:\t{obj[fields[i]]}");
                        }
                        else
                            Console.WriteLine(obj["name"]);
                    }                    
                }
                else
                {
                    Console.WriteLine("Не удалось подключиться к машине!");
                    Environment.Exit(-1);
                }             
            }
            catch (Exception ex)
            {
                Console.WriteLine("Во время работы метода произошла ошибка: {0}", ex.Message);
                Environment.Exit(-1);
            }
        }       
    }
}
