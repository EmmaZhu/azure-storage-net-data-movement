﻿//------------------------------------------------------------------------------
// <copyright file="SubDirectoryTransfer.cs" company="Microsoft">
//    Copyright (c) Microsoft Corporation
// </copyright>
//------------------------------------------------------------------------------

namespace Microsoft.Azure.Storage.DataMovement
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.WindowsAzure.Storage.Blob;
    using Microsoft.Azure.Storage.DataMovement.TransferEnumerators;
    using Microsoft.WindowsAzure.Storage.File;
    using Microsoft.WindowsAzure.Storage;

    /// <summary>
    /// Represents a sub-directory transfer under a hierarchy directory transfer.
    /// </summary>
#if BINARY_SERIALIZATION
    [Serializable]
#else
    [DataContract]
#endif // BINARY_SERIALIZATION
    class SubDirectoryTransfer : JournalItem
#if BINARY_SERIALIZATION
        , ISerializable
#endif // BINARY_SERIALIZATION
    {
        private const string SubDirListContinuationTokenName = "SubDirListContinuationToken";
        private const string SubDirRelativePathName = "SubDirRelativePath";

        /// <summary>
        /// Base <see cref="HierarchyDirectoryTransfer"/> instance which this <see cref="SubDirectoryTransfer"/> instance belongs to.
        /// <see cref="SubDirectoryTransfer"/> instance returns its listed directories and files to <see cref="HierarchyDirectoryTransfer"/> with callbacks.
        /// </summary>
        private HierarchyDirectoryTransfer baseDirectoryTransfer = null;
        private ITransferEnumerator transferEnumerator = null;

#if !BINARY_SERIALIZATION
        [DataMember]
#endif
        private string relativePath = null;

#if !BINARY_SERIALIZATION
        [DataMember]
#endif
        private SerializableListContinuationToken enumerateContinuationToken = null;

        private TransferLocation source;
        private TransferLocation dest;

        public SubDirectoryTransfer(
            HierarchyDirectoryTransfer baseDirectoryTransfer,
            string relativePath)
        {
            this.enumerateContinuationToken = new SerializableListContinuationToken(null);
            this.baseDirectoryTransfer = baseDirectoryTransfer;
            this.relativePath = relativePath;
            this.baseDirectoryTransfer.GetSubDirLocation(this.relativePath, out this.source, out this.dest);
            this.InitializeEnumerator();
        }

        public SubDirectoryTransfer(SubDirectoryTransfer other)
        {
            this.relativePath = other.relativePath;
            this.enumerateContinuationToken = other.enumerateContinuationToken;
        }

#if BINARY_SERIALIZATION
        /// <summary>
        /// Initializes a new instance of the <see cref="SubDirectoryTransfer"/> class.
        /// </summary>
        /// <param name="info">Serialization information.</param>
        /// <param name="context">Streaming context.</param>
        protected SubDirectoryTransfer(SerializationInfo info, StreamingContext context)
        {
            this.relativePath = info.GetString(SubDirRelativePathName);

            if (!(context.Context is StreamJournal))
            {
                this.enumerateContinuationToken = (SerializableListContinuationToken)info.GetValue(SubDirListContinuationTokenName, typeof(SerializableListContinuationToken));
            }
        }

        /// <summary>
        /// Serializes the object.
        /// </summary>
        /// <param name="info">Serialization info object.</param>
        /// <param name="context">Streaming context.</param>
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
            {
                throw new ArgumentNullException("info");
            }

            info.AddValue(SubDirRelativePathName, this.relativePath, typeof(string));

            if (!(context.Context is StreamJournal))
            {
                // serialize continuation token
                info.AddValue(SubDirListContinuationTokenName, this.enumerateContinuationToken, typeof(SerializableListContinuationToken));
            }
        }
#endif // BINARY_SERIALIZATION

        public SerializableListContinuationToken ListContinuationToken
        {
            get
            {
                return this.enumerateContinuationToken;
            }

            set
            {
                this.enumerateContinuationToken = value;
            }
        }

        public async Task ExecuteAsync(CancellationToken cancellationToken)
        {
            await Task.Yield();

            this.CreateDestinationDirectory(cancellationToken);

            this.baseDirectoryTransfer.ProgressTracker.AddNumberOfDirectoriesCreated(1);

            var enumerator = this.transferEnumerator.EnumerateLocation(cancellationToken).GetEnumerator();

            while (true)
            {
                if (!enumerator.MoveNext())
                {
                    break;
                }

                TransferEntry entry = enumerator.Current;
                ErrorEntry errorEntry = entry as ErrorEntry;
                if (errorEntry != null)
                {
                    TransferException exception = errorEntry.Exception as TransferException;
                    if (null != exception)
                    {
                        throw exception;
                    }
                    else
                    {
                        throw new TransferException(
                            TransferErrorCode.FailToEnumerateDirectory,
                            errorEntry.Exception.GetExceptionMessage(),
                            errorEntry.Exception);
                    }
                }

                if (entry.IsDirectory)
                {
                    this.baseDirectoryTransfer.AddSubDir(entry.RelativePath, () =>
                    {
                        var currentContinuationToken = new SerializableListContinuationToken(entry.ContinuationToken);
                        currentContinuationToken.Journal = this.enumerateContinuationToken.Journal;
                        currentContinuationToken.StreamJournalOffset = this.enumerateContinuationToken.StreamJournalOffset;
                        this.enumerateContinuationToken = currentContinuationToken;
                        return this.enumerateContinuationToken;
                    });
                }
                else
                {
                    SingleObjectTransfer transferItem = this.baseDirectoryTransfer.CreateTransfer(entry);
#if DEBUG
                    Utils.HandleFaultInjection(entry.RelativePath, transferItem);
#endif

                    this.CreateDestinationParentDirectoryRecursively(transferItem);

                    this.baseDirectoryTransfer.AddSingleObjectTransfer(transferItem, () =>
                    {
                        var currentContinuationToken = new SerializableListContinuationToken(entry.ContinuationToken);
                        currentContinuationToken.Journal = this.enumerateContinuationToken.Journal;
                        currentContinuationToken.StreamJournalOffset = this.enumerateContinuationToken.StreamJournalOffset;
                        this.enumerateContinuationToken = currentContinuationToken;
                        return this.enumerateContinuationToken;
                    });
                }
            }
        }

        public void Update(HierarchyDirectoryTransfer baseDirectoryTransferInstance)
        {
            this.baseDirectoryTransfer = baseDirectoryTransferInstance;
            this.baseDirectoryTransfer.GetSubDirLocation(this.relativePath, out this.source, out this.dest);
            this.InitializeEnumerator();
        }

        public void CreateDestinationParentDirectoryRecursively(SingleObjectTransfer transferItem)
        {
            switch (transferItem.Destination.Type)
            {
                case TransferLocationType.FilePath:
                    var filePath = (transferItem.Destination as FileLocation).FilePath;
                    Utils.ValidateDestinationPath(transferItem.Source.Instance.ConvertToString(), filePath);
                    Utils.CreateParentDirectoryIfNotExists(filePath);
                    break;
                case TransferLocationType.AzureFile:
                    var parent = (transferItem.Destination as AzureFileLocation).AzureFile.Parent;
                    CloudFileDirectory destDirectory = this.dest.Instance as CloudFileDirectory;

                    if (!string.Equals(parent.SnapshotQualifiedUri.AbsolutePath, destDirectory.SnapshotQualifiedUri.AbsolutePath))
                    {
                        if (this.baseDirectoryTransfer.IsForceOverwrite || !parent.ExistsAsync(Transfer_RequestOptions.DefaultFileRequestOptions, null).Result)
                        {
                            Utils.CreateCloudFileDirectoryRecursively(parent);
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        private void InitializeEnumerator()
        {
            if (this.source.Type == TransferLocationType.AzureFileDirectory)
            {
                var fileEnumerator = new AzureFileHierarchyEnumerator(this.source as AzureFileDirectoryLocation, this.baseDirectoryTransfer.Source.Instance as CloudFileDirectory);
                fileEnumerator.EnumerateContinuationToken = this.enumerateContinuationToken.ListContinuationToken;
                fileEnumerator.SearchPattern = this.baseDirectoryTransfer.SearchPattern;
                fileEnumerator.Recursive = this.baseDirectoryTransfer.Recursive;

                this.transferEnumerator = fileEnumerator;
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        private void CreateDestinationDirectory(CancellationToken cancellationToken)
        {
            if (this.dest.Type == TransferLocationType.LocalDirectory)
            {
                var localFileDestLocation = this.dest as DirectoryLocation;
                if (!LongPathDirectory.Exists(localFileDestLocation.DirectoryPath))
                {
                    LongPathDirectory.CreateDirectory(localFileDestLocation.DirectoryPath);
                }
            }
            else if (this.dest.Type == TransferLocationType.AzureFileDirectory)
            {
                AzureFileDirectoryLocation fileDirLocation = this.dest as AzureFileDirectoryLocation;

                var fileDirectory = fileDirLocation.FileDirectory;

                if (string.Equals(fileDirectory.SnapshotQualifiedUri.AbsolutePath, fileDirectory.Share.SnapshotQualifiedUri.AbsolutePath))
                {
                    return;
                }

                try
                {
                    CreateCloudFileDestinationDirectory(fileDirectory, cancellationToken);
                }
                catch (StorageException storageException)
                {
                    throw new TransferException(TransferErrorCode.FailToVadlidateDestination,
                        string.Format(CultureInfo.CurrentCulture,
                            Resources.FailedToValidateDestinationException,
                            storageException.ToErrorDetail()),
                        storageException);
                }
            }
        }

        private static void CreateCloudFileDestinationDirectory(CloudFileDirectory fileDirectory, CancellationToken cancellationToken)
        {
            bool parentNotExist = false;

            try
            {
                fileDirectory.CreateAsync(Transfer_RequestOptions.DefaultFileRequestOptions, null, cancellationToken).GetAwaiter().GetResult();
            }
            catch (StorageException ex)
            {
                if (null != ex.RequestInformation)
                {
                    if (string.Equals("ParentNotFound", ex.RequestInformation.ErrorCode))
                    {
                        parentNotExist = true;
                    }
                    else if (!string.Equals("ResourceAlreadyExists", ex.RequestInformation.ErrorCode))
                    {
                        throw;
                    }
                }
                else
                {
                    throw;
                }
            }

            if (parentNotExist)
            {
                Utils.CreateCloudFileDirectoryRecursively(fileDirectory);
            }
        }
    }
}