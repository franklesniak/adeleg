using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using adeleg.engine;

namespace adeleg.engine.connector
{
    class LdapLiveConnector : IConnector
    {
        public static readonly int DEFAULT_PAGE_SIZE = 999;
        private readonly string server = null;
        private NetworkCredential creds = null; 
        private LdapConnection connection = null;
        public string schemaNC = null;
        public string configurationNC = null;
        public string rootDomainNC = null;
        public string[] partitionDNs = new string[0];
        public Dictionary<string, SecurityIdentifier> domainSidPerPartitionDn = new Dictionary<string, SecurityIdentifier>();
        public Dictionary<string, CommonSecurityDescriptor> adminSDHolderPerPartitionDn = new Dictionary<string, CommonSecurityDescriptor>();

        public LdapLiveConnector(string server, ushort port, NetworkCredential creds = null)
        {
            this.server = server;
            this.creds = creds;

            var srv = new LdapDirectoryIdentifier(server, port, false, false);
            Log.Info($"Connecting to LDAP server {server}:{port}");
            if (creds == null)
            {
                this.connection = new LdapConnection(srv);
            }
            else
            {
                this.connection = new LdapConnection(srv, creds, AuthType.Negotiate);
            }
            this.connection.SessionOptions.ProtocolVersion = 3;
            this.connection.SessionOptions.Sealing = true;
            this.connection.SessionOptions.Signing = true;

            this.connection.Bind();
            Log.Info($"LDAP Bind() successful to {server}:{port}");
            Log.Verbose(creds == null ? "Using Windows integrated authentication" : "Using explicit credentials");

            this.PrefetchRootDseInformation();
            this.PrefetchDomainSIDs();
            this.PrefetchDomainAdminSDHolders();
        }

        private IEnumerable<SearchResultEntry> GetLdapRecords(string baseDN, SearchScope scope, string filter, string[] attrs)
        {
            byte[] previousCookie = null;

            do
            {
                DirectoryRequest req = new SearchRequest(baseDN, filter, scope, attrs);
                if (previousCookie is null)
                    req.Controls.Add(new PageResultRequestControl(DEFAULT_PAGE_SIZE));
                else
                    req.Controls.Add(new PageResultRequestControl(previousCookie));

                if (attrs.Contains("nTSecurityDescriptor"))
                    req.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Owner | SecurityMasks.Dacl));

                DirectoryResponse resp = this.connection.SendRequest(req);
                if (resp.ResultCode != ResultCode.Success)
                    throw new LdapException((int)resp.ResultCode, $"LDAP request on {scope} {baseDN} for {filter} failed with code {resp.ResultCode}");

                foreach (DirectoryControl control in resp.Controls)
                {
                    if (control is PageResultResponseControl paging)
                    {
                        previousCookie = paging.Cookie;
                        break;
                    }
                }
                SearchResponse res = (SearchResponse)resp;
                foreach (SearchResultEntry entry in res.Entries)
                {
                    yield return entry;
                }
            }
            while (previousCookie != null && previousCookie.Length > 0);
        }

        private void PrefetchRootDseInformation()
        {
            var res = GetLdapRecords(schemaNC, SearchScope.Base,
                         "(objectClass=*)",
                         new string[] { "schemaNamingContext", "configurationNamingContext", "rootDomainNamingContext", "namingContexts" }).FirstOrDefault();

            if (res == null)
            {
                throw new Exception("RootDSE query did not return any entries. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }

            var attrs = res.Attributes;

            if (attrs.Contains("schemaNamingContext"))
            {
                this.schemaNC = (string)attrs["schemaNamingContext"].GetValues(typeof(string)).FirstOrDefault();
            }
            else
            {
                throw new Exception("RootDSE did not return 'schemaNamingContext' attribute. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            if (string.IsNullOrEmpty(this.schemaNC))
            {
                throw new Exception("RootDSE returned a null or empty 'schemaNamingContext' value. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            Log.Verbose($"RootDSE schemaNamingContext = {this.schemaNC}");

            if (attrs.Contains("configurationNamingContext"))
            {
                this.configurationNC = (string)attrs["configurationNamingContext"].GetValues(typeof(string)).FirstOrDefault();
            }
            else
            {
                throw new Exception("RootDSE did not return 'configurationNamingContext' attribute. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            if (string.IsNullOrEmpty(this.configurationNC))
            {
                throw new Exception("RootDSE returned a null or empty 'configurationNamingContext' value. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            Log.Verbose($"RootDSE configurationNamingContext = {this.configurationNC}");

            if (attrs.Contains("rootDomainNamingContext"))
            {
                this.rootDomainNC = (string)attrs["rootDomainNamingContext"].GetValues(typeof(string)).FirstOrDefault();
            }
            else
            {
                throw new Exception("RootDSE did not return 'rootDomainNamingContext' attribute. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            if (string.IsNullOrEmpty(this.rootDomainNC))
            {
                throw new Exception("RootDSE returned a null or empty 'rootDomainNamingContext' value. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            Log.Verbose($"RootDSE rootDomainNamingContext = {this.rootDomainNC}");

            if (attrs.Contains("namingContexts"))
            {
                this.partitionDNs = (string[])attrs["namingContexts"].GetValues(typeof(string));
                this.partitionDNs = this.partitionDNs.Where(dn => !string.IsNullOrEmpty(dn)).ToArray();
            }
            else
            {
                throw new Exception("RootDSE did not return 'namingContexts' attribute. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            if (this.partitionDNs.Length == 0)
            {
                throw new Exception("RootDSE returned no valid 'namingContexts' entries. Ensure the domain controller is reachable and returns valid RootDSE information.");
            }
            for (int i = 0; i < this.partitionDNs.Length; i++)
                Log.Verbose($"RootDSE namingContext[{i}] = {this.partitionDNs[i]}");
        }

        private void PrefetchDomainSIDs()
        {
            foreach (string partitionDN in this.partitionDNs)
            {
                SearchResultEntry entry = GetLdapRecords(partitionDN, SearchScope.Base, "(objectSid=*)", new string[] { "objectSid" }).FirstOrDefault();
                if (entry != null)
                {
                    byte[] sidBytes = (byte[])entry.Attributes["objectSid"].GetValues(typeof(byte[]))[0];
                    SecurityIdentifier sid = new SecurityIdentifier(sidBytes, 0);
                    this.domainSidPerPartitionDn.Add(partitionDN, sid);
                    Log.Verbose($"Partition {partitionDN} has domain SID {sid}");
                }
                else
                {
                    Log.Verbose($"Partition {partitionDN} has no objectSid (not a domain partition)");
                }
            }
        }

        private void PrefetchDomainAdminSDHolders()
        {
            foreach (string partitionDN in this.domainSidPerPartitionDn.Keys)
            {
                SearchResultEntry res = GetLdapRecords("CN=AdminSDHolder,CN=System," + partitionDN, SearchScope.Base, "(ntSecurityDescriptor=*)", new string[] { "nTSecurityDescriptor" }).First();
                byte[] bytes = (byte[])res.Attributes["ntSecurityDescriptor"].GetValues(typeof(byte[]))[0];
                CommonSecurityDescriptor sd = new CommonSecurityDescriptor(true, true, bytes, 0);
                this.adminSDHolderPerPartitionDn.Add(partitionDN, sd);
                Log.Verbose($"Retrieved AdminSDHolder security descriptor for {partitionDN}");
            }
        }

        public Dictionary<Guid, string> GetSchemaClasses()
        {
            Dictionary<Guid, string> res = new Dictionary<Guid, string>();

            var entries = GetLdapRecords(schemaNC, SearchScope.Subtree,
                         "(objectClass=classSchema)",
                         new string[] { "lDAPDisplayName", "schemaIDGUID" });
            foreach (SearchResultEntry entry in entries)
            {
                string name = (string)entry.Attributes["lDAPDisplayName"].GetValues(typeof(string)).FirstOrDefault();
                byte[] guid = (byte[])entry.Attributes["schemaIDGUID"].GetValues(typeof(byte[])).FirstOrDefault();

                if (name == "" || guid.Length == 0)
                    throw new Exception("Unsupported schema extension: class has no name or guid");

                res.Add(new Guid(guid), name);
            }
            return res;
        }

        public Dictionary<Guid, string> GetSchemaAttributes()
        {
            Dictionary<Guid, string> res = new Dictionary<Guid, string>();

            var entries = GetLdapRecords(schemaNC, SearchScope.Subtree,
                         "(objectClass=attributeSchema)",
                         new string[] { "lDAPDisplayName", "schemaIDGUID" });
            foreach (SearchResultEntry entry in entries)
            {
                string name = (string)entry.Attributes["lDAPDisplayName"].GetValues(typeof(string)).FirstOrDefault();
                byte[] guid = (byte[])entry.Attributes["schemaIDGUID"].GetValues(typeof(byte[])).FirstOrDefault();

                if (name == "" || guid.Length == 0)
                    throw new Exception("Unsupported schema extension: attribute has no name or guid");

                res.Add(new Guid(guid), name);
            }
            return res;
        }

        public Dictionary<Guid, Tuple<string, HashSet<Guid>>> GetPropertySets()
        {
            Dictionary<Guid, string> namePerGuid = new Dictionary<Guid, string>();
            Dictionary<Guid, Tuple<string, HashSet<Guid>>> res = new Dictionary<Guid, Tuple<string, HashSet<Guid>>>();

            var entries = GetLdapRecords($"CN=Extended-Rights,{configurationNC}", SearchScope.Subtree,
                 "(&(objectClass=controlAccessRight)(validAccesses=48)(rightsGuid=*)(displayName=*))",
                 new string[] { "rightsGuid", "displayName" });
            foreach (SearchResultEntry entry in entries)
            {
                string propsetGuidStr = (string)entry.Attributes["rightsGuid"].GetValues(typeof(string)).FirstOrDefault();
                Guid propsetGuid = new Guid(propsetGuidStr);
                string name = (string)entry.Attributes["displayName"].GetValues(typeof(string)).FirstOrDefault();

                if (namePerGuid.ContainsKey(propsetGuid))
                    throw new Exception($"Unsupported schema extension: propset GUID {propsetGuid} collision");

                // Replace "xxx (yyy)" in name, which makes delegation labels unclear due to
                // multiple (remarks) in a row
                name = Regex.Replace(name.Trim(), "\\s*\\(.+\\)$", "");

                namePerGuid[propsetGuid] = name;
            }

            var entries2 = GetLdapRecords(schemaNC, SearchScope.Subtree,
                         "(&(objectClass=attributeSchema)(attributeSecurityGUID=*))",
                         new string[] { "schemaIDGUID", "attributeSecurityGUID" });
            foreach (SearchResultEntry entry in entries2)
            {
                byte[] attrGuidBytes = (byte[])entry.Attributes["schemaIDGUID"].GetValues(typeof(byte[])).FirstOrDefault();
                Guid attrGuid = new Guid(attrGuidBytes);
                byte[] propsetGuidBytes = (byte[])entry.Attributes["attributeSecurityGUID"].GetValues(typeof(byte[])).FirstOrDefault();
                Guid propsetGuid = new Guid(propsetGuidBytes);

                if (!res.ContainsKey(propsetGuid))
                {
                    string name;
                    if (!namePerGuid.TryGetValue(propsetGuid, out name))
                        name = propsetGuid.ToString();

                    res[propsetGuid] = Tuple.Create(name, new HashSet<Guid>());
                }

                res[propsetGuid].Item2.Add(attrGuid);
            }
            return res;
        }

        public Dictionary<Guid, string> GetControlAccessRights()
        {
            Dictionary<Guid, string> res = new Dictionary<Guid, string>();
            var entries = GetLdapRecords($"CN=Extended-Rights,{configurationNC}", SearchScope.Subtree,
                 "(&(objectClass=controlAccessRight)(validAccesses=256)(rightsGuid=*)(displayName=*))",
                 new string[] { "rightsGuid", "displayName" });
            foreach (SearchResultEntry entry in entries)
            {
                string controlGuidStr = (string)entry.Attributes["rightsGuid"].GetValues(typeof(string)).FirstOrDefault();
                Guid controlGuid = new Guid(controlGuidStr);
                string name = (string)entry.Attributes["displayName"].GetValues(typeof(string)).FirstOrDefault();

                if (res.ContainsKey(controlGuid))
                    throw new Exception($"Unsupported config extension: control access right GUID {controlGuid} collision");

                res[controlGuid] = name;
            }
            return res;
        }

        public Dictionary<string, string> GetDefaultSddlPerClass()
        {
            Dictionary<string, string> defaultSecurityDescriptors = new Dictionary<string, string>();
            var res = GetLdapRecords(schemaNC, SearchScope.Subtree,
                                     "(&(objectClass=classSchema)(defaultSecurityDescriptor=*))",
                                     new string[] { "lDAPDisplayName", "defaultSecurityDescriptor" });
            foreach (SearchResultEntry entry in res)
            {
                string name = (string)entry.Attributes["lDAPDisplayName"].GetValues(typeof(string)).FirstOrDefault();
                string sddl = (string)entry.Attributes["defaultSecurityDescriptor"].GetValues(typeof(string)).FirstOrDefault();

                defaultSecurityDescriptors.Add(name, sddl);
            }
            return defaultSecurityDescriptors;
        }

        public IEnumerable<ObjectRecord> ScanSecurityDescriptors(string baseDN, bool recurse)
        {
            string[] attrs = {
                 "nTSecurityDescriptor",
                 "objectClass",
                 "objectSID",
                 "adminCount",
                 "msDS-KrbTgtLinkBl",
                 "serverReference",
            };
            SearchScope scope = recurse ? SearchScope.Subtree : SearchScope.Base;
            foreach (SearchResultEntry entry in this.GetLdapRecords(baseDN, scope, "(objectClass=*)", attrs))
            {
                ObjectRecord record;

                record.distinguishedName = entry.DistinguishedName;

                byte[] bytes = (byte[])entry.Attributes["nTSecurityDescriptor"].GetValues(typeof(byte[])).First();
                record.securityDescriptor = new CommonSecurityDescriptor(true, true, bytes, 0);

                record.mostSpecificClass = (string)entry.Attributes["objectClass"].GetValues(typeof(string)).LastOrDefault();

                record.adminCount = false;
                if (entry.Attributes.Contains("adminCount") &&
                    (string)entry.Attributes["adminCount"].GetValues(typeof(string)).LastOrDefault() != "0")
                {
                    record.adminCount = true;
                }

                yield return record;
            }
        }

        public static string AutolocateDomainController()
        {
            try
            {
                var ctx = new DirectoryContext(DirectoryContextType.Domain);
                var dc = DomainController.FindOne(ctx, LocatorOptions.ForceRediscovery | LocatorOptions.WriteableRequired);
                Log.Info($"Auto-located domain controller: {dc.Name}");
                return dc.Name;
            }
            catch (Exception)
            {
                Log.Warn("Failed to auto-locate a domain controller via DC Locator");
                return null;
            }
        }

        public string GetRootDomainNC()
        {
            return this.rootDomainNC;
        }

        public string GetConfigurationNC()
        {
            return this.configurationNC;
        }

        public string GetSchemaNC()
        {
            return this.schemaNC;
        }

        public string[] GetPartitionDNs()
        {
            return this.partitionDNs;
        }

        public SecurityIdentifier GetDomainSidByPartitionDN(string partitionDN)
        {
            SecurityIdentifier domainSID;
            this.domainSidPerPartitionDn.TryGetValue(partitionDN, out domainSID);
            return domainSID;
        }

        public CommonSecurityDescriptor GetAdminSDHolderSDByPartitionDN(string partitionDN)
        {
            CommonSecurityDescriptor sd;
            this.adminSDHolderPerPartitionDn.TryGetValue(partitionDN, out sd);
            return sd;
        }

        internal static void CrawlDomainsAcrossTrusts(List<IConnector> dataSources, bool includeDomainsOutsideForest)
        {
            // Enumerate all DNS domains we already have
            Dictionary<string, LdapLiveConnector> dnsDomainsCovered = new Dictionary<string, LdapLiveConnector>(StringComparer.OrdinalIgnoreCase);
            foreach (LdapLiveConnector conn in dataSources.Cast<LdapLiveConnector>())
            {
                foreach (string partitionDN in conn.GetPartitionDNs())
                {
                    string dnsName = partitionDN.Replace(",", ".").Replace("DC=", "");
                    dnsDomainsCovered[dnsName] = conn;
                }
            }

            // Now, for each domain partition, enumerate trusts and crawl domains not already covered.
            // Use a for loop with index because new connectors may be added during iteration.
            for (int idx = 0; idx < dataSources.Count; idx++)
            {
                LdapLiveConnector dataSource = (LdapLiveConnector)dataSources[idx];
                foreach (string partitionDN in dataSource.GetPartitionDNs())
                {
                    // Skip non-domain partitions (schema, config, DNS app partitions) since
                    // trust objects only exist under CN=System in domain partitions.
                    if (partitionDN.Equals(dataSource.GetSchemaNC(), StringComparison.OrdinalIgnoreCase) ||
                        partitionDN.Equals(dataSource.GetConfigurationNC(), StringComparison.OrdinalIgnoreCase) ||
                        partitionDN.StartsWith("DC=DomainDnsZones,", StringComparison.OrdinalIgnoreCase) ||
                        partitionDN.StartsWith("DC=ForestDnsZones,", StringComparison.OrdinalIgnoreCase))
                    {
                        Log.Verbose($"Skipping non-domain partition {partitionDN} for trust enumeration");
                        continue;
                    }
                    var trusts = dataSource.GetLdapRecords("CN=System," + partitionDN, SearchScope.Subtree, "(trustPartner=*)", new string[] { "trustPartner", "trustType" });
                    foreach (SearchResultEntry trust in trusts)
                    {
                        string partner = (string)trust.Attributes["trustPartner"].GetValues(typeof(string)).FirstOrDefault();
                        TrustType type = (TrustType)Enum.Parse(typeof(TrustType), (string)trust.Attributes["trustType"].GetValues(typeof(string)).FirstOrDefault());

                        Log.Info($"Discovered trust partner: {partner} (type: {type})");

                        if (!includeDomainsOutsideForest && (type == TrustType.External || type == TrustType.Forest || type == TrustType.Kerberos))
                        {
                            Log.Verbose($"Skipping trust partner {partner} (external/forest trust, not crawling outside forest)");
                            continue;
                        }
                        if (dnsDomainsCovered.ContainsKey(partner))
                        {
                            Log.Verbose($"Skipping trust partner {partner} (already covered)");
                            continue;
                        }
                        var ctx2 = new DirectoryContext(DirectoryContextType.Domain, partner);
                        var dc = DomainController.FindOne(ctx2, LocatorOptions.ForceRediscovery | LocatorOptions.WriteableRequired);
                        Log.Info($"Connecting to trust partner {partner} via DC {dc.IPAddress}");
                        var newConnector = new LdapLiveConnector(dc.IPAddress, 389, dataSource.creds); // reuse same credentials as the trust party we already have
                        dataSources.Add(newConnector);
                        dnsDomainsCovered[partner] = newConnector;
                    }
                }
            }
        }

        public HashSet<string> GetDirectGroupMemberDNs(string groupDN)
        {
            HashSet<string> members = new HashSet<string>();
            SearchResultEntry res = GetLdapRecords(groupDN, SearchScope.Base, $"(objectClass=group)", new string[] { "member" }).First();
            if (res.Attributes.Contains("member"))
            {
                foreach (string memberDN in res.Attributes["member"].GetValues(typeof(string)).Cast<string>())
                {
                    members.Add(memberDN);
                }
            }
            return members;
        }

        public string GetMostSpecificObjectClassByDn(string dn)
        {
            SearchResultEntry res = GetLdapRecords(dn, SearchScope.Base, $"(objectClass=*)", new string[] { "objectClass" }).First();
            return ((string[])res.Attributes["objectClass"].GetValues(typeof(string)))[0];
        }

        public Tuple<ObjectClass, string, string> GetDnAndSamAccountNameBySid(SecurityIdentifier sid)
        {
            try
            {
                IEnumerable<SearchResultEntry> res = GetLdapRecords($"<sid={sid}>", SearchScope.Subtree, $"(objectClass=*)", new string[] { "distinguishedName", "objectClass", "samAccountName" });
                if (res.Count() != 0)
                {
                    string mostSpecificClass = (string)res.First().Attributes["objectClass"].GetValues(typeof(string)).Last();
                    string samAccountName = (string)res.First().Attributes["samAccountName"].GetValues(typeof(string)).Last();
                    return Tuple.Create(ObjectClassHelper.FromString(mostSpecificClass, true), res.First().DistinguishedName, samAccountName);
                }
            }
            catch (DirectoryOperationException e)
            {
                if (e.Response.ResultCode != ResultCode.NoSuchObject)
                {
                    throw;
                }
            }
            return Tuple.Create<ObjectClass, string, string>(ObjectClass.UnknownTrustee, null, null);
        }

        public SecurityIdentifier GetSidByDn(string principalDN)
        {
            IEnumerable<SearchResultEntry> res = GetLdapRecords(principalDN, SearchScope.Base, $"(objectSid=*)", new string[] { "objectSid" });
            if (res.Count() == 0)
            {
                return null;
            }
            byte[] sid = (byte[])res.First().Attributes["objectSid"].GetValues(typeof(byte[])).Last();
            return new SecurityIdentifier(sid, 0);
        }
    }
}
