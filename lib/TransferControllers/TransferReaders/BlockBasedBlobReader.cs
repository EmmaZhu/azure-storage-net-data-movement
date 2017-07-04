//------------------------------------------------------------------------------
// <copyright file="BlockBasedBlobReader.cs" company="Microsoft">
//    Copyright (c) Microsoft Corporation
// </copyright>
//------------------------------------------------------------------------------

namespace Microsoft.WindowsAzure.Storage.DataMovement.TransferControllers
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.WindowsAzure.Storage.Blob;

    internal sealed class BlockBasedBlobReader : TransferReaderWriterBase
    {
        /// <summary>
        /// Instance to represent source location.
        /// </summary>
        private AzureBlobLocation sourceLocation;

        /// <summary>
        /// Block/append blob instance to be downloaded from.
        /// </summary>
        private CloudBlob sourceBlob;

        /// <summary>
        /// Window to record unfinished chunks to be retransferred again.
        /// </summary>
        private Queue<long> lastTransferWindow;

        private TransferJob transferJob;

        /// <summary>
        /// Value to indicate whether the transfer is finished. 
        /// This is to tell the caller that the reader can be disposed,
        /// Both error happened or completed will be treated to be finished.
        /// </summary>
        private volatile bool isFinished = false;

        private volatile bool hasWork;

        private CountdownEvent downloadCountdownEvent;

        public BlockBasedBlobReader(
            TransferScheduler scheduler,
            SyncTransferController controller,
            CancellationToken cancellationToken)
            : base(scheduler, controller, cancellationToken)
        {
            this.transferJob = this.SharedTransferData.TransferJob;
            this.sourceLocation = this.transferJob.Source as AzureBlobLocation;
            this.sourceBlob = this.sourceLocation.Blob;

            Debug.Assert(
                (this.sourceBlob is CloudBlockBlob) ||(this.sourceBlob is CloudAppendBlob), 
            "Initializing BlockBlobReader while source location is not a block blob or an append blob.");

            this.hasWork = true;
        }

        public override bool IsFinished
        {
            get
            {
                return this.isFinished;
            }
        }

        public override bool HasWork
        {
            get 
            {
                return this.hasWork;
            }
        }

        public override async Task DoWorkInternalAsync()
        {
            try
            {
                if (!this.PreProcessed)
                {
                    await this.PreProcessAsync();
                }
                else
                {
                    await this.DownloadBlockBlobAsync();
                }
            }
            catch (Exception)
            {
                this.isFinished = true;
                throw;
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                if (null != this.downloadCountdownEvent)
                {
                    this.downloadCountdownEvent.Dispose();
                    this.downloadCountdownEvent = null;
                }
            }
        }

        private async Task PreProcessAsync()
        {
            this.hasWork = false;
            this.NotifyStarting();
            
            // Validate serialized check point before downloading
            if ((0 == this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset)
                && (null != this.SharedTransferData.TransferJob.CheckPoint.TransferWindow)
                && (0 != this.SharedTransferData.TransferJob.CheckPoint.TransferWindow.Count))
            {
                throw new InvalidOperationException(Resources.RestartableInfoCorruptedException);
            }
            
            this.lastTransferWindow = new Queue<long>(this.SharedTransferData.TransferJob.CheckPoint.TransferWindow);

            this.SharedTransferData.DisableContentMD5Validation =
                null != this.sourceLocation.BlobRequestOptions ?
                this.sourceLocation.BlobRequestOptions.DisableContentMD5Validation.HasValue ?
                this.sourceLocation.BlobRequestOptions.DisableContentMD5Validation.Value : false : false;

            try
            {
                // Try to download the first block (get range) which also gets back properties of the blob, to decrease one request
                // on fetching attributes.

                if ((this.lastTransferWindow.Count == 0)
                    && (0 == this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset))
                {
                    // To keep code simple, only try to download the first block when it's a totally new transfer
                    await TryDownloadFirstBlockAsync();
                }
                else
                {

                    AccessCondition accessCondition = Utils.GenerateIfMatchConditionWithCustomerCondition(
                        this.sourceLocation.ETag,
                        this.sourceLocation.AccessCondition,
                        this.sourceLocation.CheckedAccessCondition);

                    await this.sourceBlob.FetchAttributesAsync(
                        accessCondition,
                        Utils.GenerateBlobRequestOptions(this.sourceLocation.BlobRequestOptions),
                        Utils.GenerateOperationContext(this.Controller.TransferContext),
                        this.CancellationToken);

                    this.PostAttributesHandling();

                    this.SetFinish();
                    this.SetBlockDownloadHasWork();
                }
            }
#if EXPECT_INTERNAL_WRAPPEDSTORAGEEXCEPTION
            catch (Exception ex) when (ex is StorageException || ex.InnerException is StorageException)
            {
                var e = ex as StorageException ?? ex.InnerException as StorageException;
#else
            catch (StorageException e)
            {
#endif
                if (null != e.RequestInformation &&
                    e.RequestInformation.HttpStatusCode == (int)HttpStatusCode.NotFound)
                {
                    throw new InvalidOperationException(Resources.SourceBlobDoesNotExistException);
                }
                else
                {
                    throw;
                }
            }
        }

        private async Task TryDownloadFirstBlockAsync()
        {
            AccessCondition accessCondition = Utils.GenerateIfMatchConditionWithCustomerCondition(
                this.sourceLocation.ETag,
                this.sourceLocation.AccessCondition,
                this.sourceLocation.CheckedAccessCondition);

            byte[] memoryBuffer = this.Scheduler.MemoryManager.RequireBuffer();

            this.sourceLocation.CheckedAccessCondition = true;
            if (null != memoryBuffer)
            {
                // Download range
                using (ReadDataState asyncState = new ReadDataState
                {
                    MemoryBuffer = memoryBuffer,
                    BytesRead = 0,
                    StartOffset = 0,
                    Length = this.Scheduler.TransferOptions.BlockSize, // For now the block size is always less than or equals to length of memoryBuffer.
                    MemoryManager = this.Scheduler.MemoryManager,
                })
                {
                    // We're to download this block.
                    asyncState.MemoryStream =
                        new MemoryStream(
                            asyncState.MemoryBuffer,
                            0,
                            asyncState.Length);

                    try
                    {
                        await this.sourceBlob.DownloadRangeToStreamAsync(
                                    asyncState.MemoryStream,
                                    asyncState.StartOffset,
                                    asyncState.Length,
                                    accessCondition,
                                    Utils.GenerateBlobRequestOptions(this.sourceLocation.BlobRequestOptions),
                                    Utils.GenerateOperationContext(this.Controller.TransferContext),
                                    this.CancellationToken);
                    }
#if EXPECT_INTERNAL_WRAPPEDSTORAGEEXCEPTION
                    catch (Exception ex) when (ex is StorageException || ex.InnerException is StorageException)
                    {
                        var e = ex as StorageException ?? ex.InnerException as StorageException;
#else
                    catch (StorageException e)
                    {
#endif
                        if (null != e.RequestInformation &&
                            e.RequestInformation.HttpStatusCode == (int)HttpStatusCode.RequestedRangeNotSatisfiable)
                        {
                            await this.sourceBlob.FetchAttributesAsync(
                                accessCondition,
                                Utils.GenerateBlobRequestOptions(this.sourceLocation.BlobRequestOptions),
                                Utils.GenerateOperationContext(this.Controller.TransferContext),
                                this.CancellationToken);
                        }
                        else
                        {
                            throw;
                        }
                    }

                    if (this.sourceBlob.Properties.Length <= asyncState.Length)
                    {
                        asyncState.Length = (int)(this.sourceBlob.Properties.Length);
                    }

                    this.sourceLocation.ETag = this.sourceBlob.Properties.ETag;
                    
                    this.PostAttributesHandling();

                    if (this.sourceBlob.Properties.Length != 0)
                    {
                        this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset = Math.Min(this.sourceBlob.Properties.Length, this.Scheduler.TransferOptions.BlockSize);
                        this.SharedTransferData.TransferJob.CheckPoint.TransferWindow.Add(0);

                        TransferData transferData = new TransferData(this.Scheduler.MemoryManager)
                        {
                            StartOffset = asyncState.StartOffset,
                            Length = asyncState.Length,
                            MemoryBuffer = asyncState.MemoryBuffer
                        };

                        this.SharedTransferData.AvailableData.TryAdd(transferData.StartOffset, transferData);

                        // Set memory buffer to null. We don't want its dispose method to 
                        // be called once our asyncState is disposed. The memory should 
                        // not be reused yet, we still need to write it to disk.
                        asyncState.MemoryBuffer = null;
                    }

                    this.SetFinish();
                    this.SetBlockDownloadHasWork();
                }
            }
        }

        private void PostAttributesHandling()
        {
            this.sourceLocation.CheckedAccessCondition = true;

            if (this.sourceBlob.Properties.BlobType == BlobType.Unspecified)
            {
                throw new InvalidOperationException(Resources.FailedToGetBlobTypeException);
            }

            if (string.IsNullOrEmpty(this.sourceLocation.ETag))
            {
                if (0 != this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset)
                {
                    throw new InvalidOperationException(Resources.RestartableInfoCorruptedException);
                }

                this.sourceLocation.ETag = this.sourceBlob.Properties.ETag;
            }
            else if ((this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset > this.sourceBlob.Properties.Length)
                || (this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset < 0))
            {
                throw new InvalidOperationException(Resources.RestartableInfoCorruptedException);
            }
            
            this.SharedTransferData.DisableContentMD5Validation =
                null != this.sourceLocation.BlobRequestOptions ?
                this.sourceLocation.BlobRequestOptions.DisableContentMD5Validation.HasValue ?
                this.sourceLocation.BlobRequestOptions.DisableContentMD5Validation.Value : false : false;

            this.SharedTransferData.TotalLength = this.sourceBlob.Properties.Length;
            this.SharedTransferData.Attributes = Utils.GenerateAttributes(this.sourceBlob);            

            int downloadCount = this.lastTransferWindow.Count +
                (int)Math.Ceiling((double)(this.sourceBlob.Properties.Length - this.SharedTransferData.TransferJob.CheckPoint.EntryTransferOffset) / this.SharedTransferData.BlockSize);

            this.downloadCountdownEvent = new CountdownEvent(downloadCount + 1);

            this.PreProcessed = true;
        }

        private async Task DownloadBlockBlobAsync()
        {
            this.hasWork = false;

            byte[][] memoryBuffer = this.Scheduler.MemoryManager.RequireBuffers(this.SharedTransferData.MemoryChunksRequiredEachTime);

            if (null != memoryBuffer)
            {
                long startOffset = 0;

                if (!this.IsTransferWindowEmpty())
                {
                    startOffset = this.lastTransferWindow.Dequeue();
                }
                else
                {
                    bool canRead = false;

                    lock (this.transferJob.CheckPoint.TransferWindowLock)
                    {
                        if (this.transferJob.CheckPoint.TransferWindow.Count < Constants.MaxCountInTransferWindow)
                        {
                            startOffset = this.transferJob.CheckPoint.EntryTransferOffset;

                            if (this.transferJob.CheckPoint.EntryTransferOffset < this.SharedTransferData.TotalLength)
                            {
                                this.transferJob.CheckPoint.TransferWindow.Add(startOffset);
                                this.transferJob.CheckPoint.EntryTransferOffset = Math.Min(
                                    this.transferJob.CheckPoint.EntryTransferOffset + this.SharedTransferData.BlockSize,
                                    this.SharedTransferData.TotalLength);

                                canRead = true;
                            }
                        }
                    }

                    if (!canRead)
                    {
                        this.hasWork = true;
                        this.Scheduler.MemoryManager.ReleaseBuffers(memoryBuffer);
                        return;
                    }
                }

                if ((startOffset > this.SharedTransferData.TotalLength)
                    || (startOffset < 0))
                {
                    this.Scheduler.MemoryManager.ReleaseBuffers(memoryBuffer);
                    throw new InvalidOperationException(Resources.RestartableInfoCorruptedException);
                }

                this.SetBlockDownloadHasWork();

                ReadDataState asyncState = new ReadDataState
                {
                    MemoryBuffer = memoryBuffer,
                    BytesRead = 0,
                    StartOffset = startOffset,
                    Length = (int)Math.Min(this.SharedTransferData.BlockSize, this.SharedTransferData.TotalLength - startOffset),
                    MemoryManager = this.Scheduler.MemoryManager,
                };

                using (asyncState)
                {
                    await this.DownloadChunkAsync(asyncState);
                }

                return;
            }

            this.SetBlockDownloadHasWork();
        }

        private async Task DownloadChunkAsync(ReadDataState asyncState)
        {
            Debug.Assert(null != asyncState, "asyncState object expected");

            // If a parallel operation caused the controller to be placed in
            // error state exit early to avoid unnecessary I/O.
            if (this.Controller.ErrorOccurred)
            {
                return;
            }

            AccessCondition accessCondition = Utils.GenerateIfMatchConditionWithCustomerCondition(
                 this.sourceBlob.Properties.ETag,
                 this.sourceLocation.AccessCondition);

            if (asyncState.MemoryBuffer.Length == 1)
            {
                // We're to download this block.
                asyncState.MemoryStream =
                    new MemoryStream(
                        asyncState.MemoryBuffer[0],
                        0,
                        asyncState.Length);
                await this.sourceBlob.DownloadRangeToStreamAsync(
                            asyncState.MemoryStream,
                            asyncState.StartOffset,
                            asyncState.Length,
                            accessCondition,
                            Utils.GenerateBlobRequestOptions(this.sourceLocation.BlobRequestOptions),
                            Utils.GenerateOperationContext(this.Controller.TransferContext),
                            this.CancellationToken);
            }
            else
            {
                var blockSize = Constants.DefaultBlockSize; // 4MB

                var startOffset = asyncState.StartOffset;
                var remainingLength = asyncState.Length;
                var index = 0;

                do
                {
                    var length = Math.Min(blockSize, remainingLength);

                    var memoryStream = new MemoryStream(asyncState.MemoryBuffer[index], 0, length);
                    await this.sourceBlob.DownloadRangeToStreamAsync(
                                memoryStream,
                                startOffset,
                                length,
                                accessCondition,
                                Utils.GenerateBlobRequestOptions(this.sourceLocation.BlobRequestOptions),
                                Utils.GenerateOperationContext(this.Controller.TransferContext),
                                this.CancellationToken);

                    index++;
                    startOffset += length;
                    remainingLength -= length;
                } while (remainingLength > 0);
            }
            
            TransferData transferData = new TransferData(this.Scheduler.MemoryManager)
            {
                StartOffset = asyncState.StartOffset,
                Length = asyncState.Length,
                MemoryBuffer = asyncState.MemoryBuffer
            };

            this.SharedTransferData.AvailableData.TryAdd(transferData.StartOffset, transferData);

            // Set memory buffer to null. We don't want its dispose method to 
            // be called once our asyncState is disposed. The memory should 
            // not be reused yet, we still need to write it to disk.
            asyncState.MemoryBuffer = null;

            this.SetFinish();
            this.SetBlockDownloadHasWork();
        }

        private void SetFinish()
        {
            if (this.downloadCountdownEvent.Signal())
            {
                this.isFinished = true;
            }
        }

        private void SetBlockDownloadHasWork()
        {
            if (this.HasWork)
            {
                return;
            }

            // Check if we have blocks available to download.
            if (!this.IsTransferWindowEmpty()
                || this.transferJob.CheckPoint.EntryTransferOffset < this.SharedTransferData.TotalLength)
            {
                this.hasWork = true;
                return;
            }
        }

        private bool IsTransferWindowEmpty()
        {
            return null == this.lastTransferWindow || this.lastTransferWindow.Count == 0;
        }
    }
}
