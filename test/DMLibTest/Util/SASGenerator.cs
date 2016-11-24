using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Microsoft.WindowsAzure.Storage.Core;
using Microsoft.WindowsAzure.Storage.File;

namespace DMLibTest.Util
{
    internal static class SASGenerator
    {
        private const string SignedPermissions = "sp";

        private const string SignedStart = "st";

        private const string SignedExpiry = "se";

        private const string SignedResource = "sr";

        private const string SignedResourceTypes = "srt";

        private const string SignedServices = "ss";

        private const string SignedProtocols = "spr";

        private const string SignedIP = "sip";

        private const string SignedIdentifier = "si";

        private const string SignedKey = "sk";

        private const string SignedVersion = "sv";

        private const string Signature = "sig";

        private const string CacheControl = "rscc";

        private const string ContentType = "rsct";

        private const string ContentEncoding = "rsce";

        private const string ContentLanguage = "rscl";

        private const string ContentDisposition = "rscd";

        #region For blob service
        public static string GetSharedAccessSignature(CloudBlobContainer container,
            SharedAccessBlobPolicy policy,
            string groupPolicyIdentifier,
            SharedAccessProtocol? protocols,
            IPAddressOrRange ipAddressOrRange,
            string targetStorageVersion)
        {
            if (!container.ServiceClient.Credentials.IsSharedKey)
            {
                string errorMessage = string.Format(CultureInfo.CurrentCulture, "CannotCreateSASWithoutAccountKey");
                throw new InvalidOperationException(errorMessage);
            }

            string resourceName = GetCanonicalName(container, targetStorageVersion);

            string signature = GetHash(policy,
                null /* headers */,
                groupPolicyIdentifier,
                resourceName,
                targetStorageVersion,
                protocols,
                ipAddressOrRange,
                container.ServiceClient.Credentials.ExportKey());

            // Future resource type changes from "c" => "container"
            UriQueryBuilder builder = GetSignature(policy, null /* headers */, groupPolicyIdentifier, "c", signature, null, targetStorageVersion, protocols, ipAddressOrRange);

            return builder.ToString();
        }

        public static string GetSharedAccessSignature(
            CloudBlob blob,
            SharedAccessBlobPolicy policy,
            SharedAccessBlobHeaders headers,
            string groupPolicyIdentifier,
            SharedAccessProtocol? protocols,
            IPAddressOrRange ipAddressOrRange,
            string accountKey,
            string targetStorageVersion)
        {
            if (!blob.ServiceClient.Credentials.IsSharedKey)
            {
                string errorMessage = string.Format(CultureInfo.CurrentCulture, "CannotCreateSASWithoutAccountKey");
                throw new InvalidOperationException(errorMessage);
            }

            string resourceName = GetCanonicalName(blob, targetStorageVersion);

            string signature = GetHash(policy,
                headers,
                groupPolicyIdentifier,
                resourceName,
                targetStorageVersion,
                protocols,
                ipAddressOrRange,
                blob.ServiceClient.Credentials.ExportKey());

            // Future resource type changes from "c" => "container"
            UriQueryBuilder builder = GetSignature(policy, headers, groupPolicyIdentifier, "b", signature, null, targetStorageVersion, protocols, ipAddressOrRange);

            return builder.ToString();
        }

        private static string GetCanonicalName(CloudBlobContainer container, string targetStorageVersion)
        {
            if (targetStorageVersion.StartsWith("2012"))
            {
                return "/" + container.ServiceClient.Credentials.AccountName + container.Uri.AbsolutePath;
            }

            string accountName = container.ServiceClient.Credentials.AccountName;
            string containerName = container.Name;

            string canonicalNameFormat = "/{0}/{1}/{2}";

            return string.Format(CultureInfo.InvariantCulture, canonicalNameFormat, "blob", accountName, containerName);
        }

        private static string GetCanonicalName(CloudBlob blob, string targetStorageVersion)
        {
            string accountName = blob.ServiceClient.Credentials.AccountName;
            string containerName = blob.Container.Name;

            // Replace \ with / for uri compatibility when running under .net 4.5. 
            string blobName = blob.Name.Replace('\\', '/');
            string canonicalName = null;

            if (targetStorageVersion.StartsWith("2012"))
            {
                canonicalName = string.Format(CultureInfo.InvariantCulture, "/{0}/{1}/{2}", accountName, containerName, blobName);
            }
            else
            {
                string canonicalNameFormat = "/{0}/{1}/{2}/{3}";
                canonicalName = string.Format(CultureInfo.InvariantCulture, canonicalNameFormat, "blob", accountName, containerName, blobName);
            }

            return canonicalName;
        }

        internal static UriQueryBuilder GetSignature(
          SharedAccessBlobPolicy policy,
          SharedAccessBlobHeaders headers,
          string accessPolicyIdentifier,
          string resourceType,
          string signature,
          string accountKeyName,
          string sasVersion,
          SharedAccessProtocol? protocols,
          IPAddressOrRange ipAddressOrRange)
        {

            UriQueryBuilder builder = new UriQueryBuilder();

            AddEscapedIfNotNull(builder, SignedVersion, sasVersion);
            AddEscapedIfNotNull(builder, SignedResource, resourceType);
            AddEscapedIfNotNull(builder, SignedIdentifier, accessPolicyIdentifier);
            AddEscapedIfNotNull(builder, SignedKey, accountKeyName);
            AddEscapedIfNotNull(builder, Signature, signature);
            AddEscapedIfNotNull(builder, SignedProtocols, GetProtocolString(protocols));
            AddEscapedIfNotNull(builder, SignedIP, ipAddressOrRange == null ? null : ipAddressOrRange.ToString());

            if (policy != null)
            {
                AddEscapedIfNotNull(builder, SignedStart, GetDateTimeOrNull(policy.SharedAccessStartTime));
                AddEscapedIfNotNull(builder, SignedExpiry, GetDateTimeOrNull(policy.SharedAccessExpiryTime));

                string permissions = SharedAccessBlobPolicy.PermissionsToString(policy.Permissions);
                if (!string.IsNullOrEmpty(permissions))
                {
                    AddEscapedIfNotNull(builder, SignedPermissions, permissions);
                }
            }

            if (headers != null)
            {
                AddEscapedIfNotNull(builder, CacheControl, headers.CacheControl);
                AddEscapedIfNotNull(builder, ContentType, headers.ContentType);
                AddEscapedIfNotNull(builder, ContentEncoding, headers.ContentEncoding);
                AddEscapedIfNotNull(builder, ContentLanguage, headers.ContentLanguage);
                AddEscapedIfNotNull(builder, ContentDisposition, headers.ContentDisposition);
            }

            return builder;
        }

        internal static string GetHash(
           SharedAccessBlobPolicy policy,
           SharedAccessBlobHeaders headers,
           string accessPolicyIdentifier,
           string resourceName,
           string sasVersion,
           SharedAccessProtocol? protocols,
           IPAddressOrRange ipAddressOrRange,
           byte[] keyValue)
        {
            string permissions = null;
            DateTimeOffset? startTime = null;
            DateTimeOffset? expiryTime = null;
            if (policy != null)
            {
                permissions = SharedAccessBlobPolicy.PermissionsToString(policy.Permissions);
                startTime = policy.SharedAccessStartTime;
                expiryTime = policy.SharedAccessExpiryTime;
            }

            string cacheControl = null;
            string contentDisposition = null;
            string contentEncoding = null;
            string contentLanguage = null;
            string contentType = null;
            if (headers != null)
            {
                cacheControl = headers.CacheControl;
                contentDisposition = headers.ContentDisposition;
                contentEncoding = headers.ContentEncoding;
                contentLanguage = headers.ContentLanguage;
                contentType = headers.ContentType;
            }

            string stringToSign = null;

            if (sasVersion.StartsWith("2012"))
            {
                stringToSign = string.Format(
                            CultureInfo.InvariantCulture,
                            "{0}\n{1}\n{2}\n{3}\n{4}\n{5}",
                            permissions,
                            GetDateTimeOrEmpty(startTime),
                            GetDateTimeOrEmpty(expiryTime),
                            resourceName,
                            accessPolicyIdentifier,
                            sasVersion);
            }
            else
            {
                stringToSign = string.Format(
                                        CultureInfo.InvariantCulture,
                                        "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n{7}\n{8}\n{9}\n{10}\n{11}\n{12}",
                                        permissions,
                                        GetDateTimeOrEmpty(startTime),
                                        GetDateTimeOrEmpty(expiryTime),
                                        resourceName,
                                        accessPolicyIdentifier,
                                        ipAddressOrRange == null ? string.Empty : ipAddressOrRange.ToString(),
                                        GetProtocolString(protocols),
                                        sasVersion,
                                        cacheControl,
                                        contentDisposition,
                                        contentEncoding,
                                        contentLanguage,
                                        contentType);
            }

            return ComputeHmac256(keyValue, stringToSign);
        }
        #endregion

        #region for file service

        public static string GetSharedAccessSignature(
            CloudFile file,
            SharedAccessFilePolicy policy,
            SharedAccessFileHeaders headers,
            string groupPolicyIdentifier,
            SharedAccessProtocol? protocols,
            IPAddressOrRange ipAddressOrRange,
            string targetStorageVersion)
        {
            if (!file.ServiceClient.Credentials.IsSharedKey)
            {
                string errorMessage = string.Format(CultureInfo.InvariantCulture, "CannotCreateSASWithoutAccountKey");
                throw new InvalidOperationException(errorMessage);
            }

            string resourceName = GetCanonicalName(file);
            string signature = GetHash(
                policy,
                headers,
                groupPolicyIdentifier,
                resourceName,
                targetStorageVersion,
                protocols,
                ipAddressOrRange,
                file.ServiceClient.Credentials.ExportKey());

            UriQueryBuilder builder =
                GetSignature(
                    policy,
                    headers,
                    groupPolicyIdentifier,
                    "f",
                    signature,
                    null,
                    targetStorageVersion,
                    protocols,
                    ipAddressOrRange);

            return builder.ToString();
        }

        private static string GetCanonicalName(CloudFile file)
        {
            string accountName = file.ServiceClient.Credentials.AccountName;
            string shareName = file.Share.Name;

            // Replace \ with / for uri compatibility when running under .net 4.5. 
            string fileAndDirectoryName = GetFileAndDirectoryName(file.Uri, true).Replace('\\', '/');
            return string.Format(CultureInfo.InvariantCulture, "/{0}/{1}/{2}/{3}", "file", accountName, shareName, fileAndDirectoryName);
        }

        internal static string GetFileAndDirectoryName(Uri fileAddress, bool? usePathStyleUris)
        {
            return null;
        }

        internal static string GetHash(
            SharedAccessFilePolicy policy,
            SharedAccessFileHeaders headers,
            string accessPolicyIdentifier,
            string resourceName,
            string sasVersion,
            SharedAccessProtocol? protocols,
            IPAddressOrRange ipAddressOrRange,
            byte[] keyValue)
        {
            string permissions = null;
            DateTimeOffset? startTime = null;
            DateTimeOffset? expiryTime = null;
            if (policy != null)
            {
                permissions = SharedAccessFilePolicy.PermissionsToString(policy.Permissions);
                startTime = policy.SharedAccessStartTime;
                expiryTime = policy.SharedAccessExpiryTime;
            }

            string cacheControl = null;
            string contentDisposition = null;
            string contentEncoding = null;
            string contentLanguage = null;
            string contentType = null;
            if (headers != null)
            {
                cacheControl = headers.CacheControl;
                contentDisposition = headers.ContentDisposition;
                contentEncoding = headers.ContentEncoding;
                contentLanguage = headers.ContentLanguage;
                contentType = headers.ContentType;
            }

            string stringToSign = string.Format(
                                    CultureInfo.InvariantCulture,
                                    "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n{7}\n{8}\n{9}\n{10}\n{11}\n{12}",
                                    permissions,
                                    GetDateTimeOrEmpty(startTime),
                                    GetDateTimeOrEmpty(expiryTime),
                                    resourceName,
                                    accessPolicyIdentifier,
                                    ipAddressOrRange == null ? string.Empty : ipAddressOrRange.ToString(),
                                    GetProtocolString(protocols),
                                    sasVersion,
                                    cacheControl,
                                    contentDisposition,
                                    contentEncoding,
                                    contentLanguage,
                                    contentType);

            return ComputeHmac256(keyValue, stringToSign);
        }

        internal static UriQueryBuilder GetSignature(
            SharedAccessFilePolicy policy,
            SharedAccessFileHeaders headers,
            string accessPolicyIdentifier,
            string resourceType,
            string signature,
            string accountKeyName,
            string sasVersion,
            SharedAccessProtocol? protocols,
            IPAddressOrRange ipAddressOrRange)
        {
            UriQueryBuilder builder = new UriQueryBuilder();

            AddEscapedIfNotNull(builder, SignedVersion, sasVersion);
            AddEscapedIfNotNull(builder, SignedResource, resourceType);
            AddEscapedIfNotNull(builder, SignedIdentifier, accessPolicyIdentifier);
            AddEscapedIfNotNull(builder, SignedKey, accountKeyName);
            AddEscapedIfNotNull(builder, Signature, signature);
            AddEscapedIfNotNull(builder, SignedProtocols, GetProtocolString(protocols));
            AddEscapedIfNotNull(builder, SignedIP, ipAddressOrRange == null ? null : ipAddressOrRange.ToString());

            if (policy != null)
            {
                AddEscapedIfNotNull(builder, SignedStart, GetDateTimeOrNull(policy.SharedAccessStartTime));
                AddEscapedIfNotNull(builder, SignedExpiry, GetDateTimeOrNull(policy.SharedAccessExpiryTime));

                string permissions = SharedAccessFilePolicy.PermissionsToString(policy.Permissions);
                if (!string.IsNullOrEmpty(permissions))
                {
                    AddEscapedIfNotNull(builder, SignedPermissions, permissions);
                }
            }

            if (headers != null)
            {
                AddEscapedIfNotNull(builder, CacheControl, headers.CacheControl);
                AddEscapedIfNotNull(builder, ContentType, headers.ContentType);
                AddEscapedIfNotNull(builder, ContentEncoding, headers.ContentEncoding);
                AddEscapedIfNotNull(builder, ContentLanguage, headers.ContentLanguage);
                AddEscapedIfNotNull(builder, ContentDisposition, headers.ContentDisposition);
            }

            return builder;
        }
        #endregion

        #region general signing       

        private static string ComputeHmac256(byte[] key, string message)
        {
            using (HashAlgorithm hashAlgorithm = new HMACSHA256(key))
            {
                byte[] messageBuffer = Encoding.UTF8.GetBytes(message);
                return Convert.ToBase64String(hashAlgorithm.ComputeHash(messageBuffer));
            }
        }

        private static string GetDateTimeOrEmpty(DateTimeOffset? value)
        {
            string result = GetDateTimeOrNull(value) ?? string.Empty;
            return result;
        }

        private static string GetDateTimeOrNull(DateTimeOffset? value)
        {
            string result = value != null ? value.Value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) : null;
            return result;
        }

        private static string GetProtocolString(SharedAccessProtocol? protocols)
        {
            if (!protocols.HasValue)
            {
                return null;
            }

            if ((protocols.Value != SharedAccessProtocol.HttpsOnly) && (protocols.Value != SharedAccessProtocol.HttpsOrHttp))
            {
                throw new ArgumentException(String.Format(CultureInfo.InvariantCulture, "InvalidProtocolsInSAS", protocols.Value));
            }

            return protocols.Value == SharedAccessProtocol.HttpsOnly ? "https" : "https,http";
        }
        private static void AddEscapedIfNotNull(UriQueryBuilder builder, string name, string value)
        {
            if (value != null)
            {
                builder.Add(name, value);
            }
        }
        #endregion
    }
}
