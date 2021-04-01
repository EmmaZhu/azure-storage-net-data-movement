//-----------------------------------------------------------------------------
// <copyright file="TransferStatus.cs" company="Microsoft">
//    Copyright (c) Microsoft Corporation
// </copyright>
//-----------------------------------------------------------------------------

namespace Microsoft.Azure.Storage.DataMovement
{
    using System;

    /// <summary>
    /// Transfer status
    /// </summary>
    public sealed class TransferStatus
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TransferStatus"/> class.
        /// </summary>
        public TransferStatus()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TransferStatus"/> class.
        /// </summary>
        /// <param name="bytesTransferred">Number of bytes that have been transferred.</param>
        /// <param name="numberOfFilesTransferred">Number of files that have been transferred.</param>
        /// <param name="numberOfFilesSkipped">Number of files that are skipped to be transferred.</param>
        /// <param name="numberOfFilesFailed">Number of files that are failed to be transferred.</param>
        /// <param name="numberOfDirectoriesCreated">Number of directories that are created.</param>
        public TransferStatus(long bytesTransferred, long numberOfFilesTransferred, long numberOfFilesSkipped, long numberOfFilesFailed, long numberOfDirectoriesCreated)
        {
            if (bytesTransferred < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesTransferred));
            }
            if (numberOfFilesTransferred < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(numberOfFilesTransferred));
            }
            if (numberOfFilesSkipped < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(numberOfFilesSkipped));
            }
            if (numberOfFilesFailed < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(numberOfFilesFailed));
            }
            if (numberOfDirectoriesCreated < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(numberOfDirectoriesCreated));
            }

            this.BytesTransferred = bytesTransferred;
            this.NumberOfFilesTransferred = numberOfFilesTransferred;
            this.NumberOfFilesSkipped = numberOfFilesSkipped;
            this.NumberOfFilesFailed = numberOfFilesFailed;
            this.NumberOfDirectoriesCreated = numberOfDirectoriesCreated;
        }

        /// <summary>
        /// Gets the number of bytes that have been transferred.
        /// </summary>
        public long BytesTransferred
        {
            get;
            internal set;
        }

        /// <summary>
        /// Gets the number of files that have been transferred.
        /// </summary>
        public long NumberOfFilesTransferred
        {
            get;
            internal set;
        }

        /// <summary>
        /// Gets the number of files that are skipped to be transferred.
        /// </summary>
        public long NumberOfFilesSkipped
        {
            get;
            internal set;
        }

        /// <summary>
        /// Gets the number of files that are failed to be transferred.
        /// </summary>
        public long NumberOfFilesFailed
        {
            get;
            internal set;
        }

        /// <summary>
        /// Gets the number of directories created.
        /// </summary>
        public long NumberOfDirectoriesCreated
        {
            get;
            internal set;
        }
    }
}
