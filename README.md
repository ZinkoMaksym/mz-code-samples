### History service

This is a service created to store history of the objects generically. 
GetSnapshot is specific to each model and gather all the data that is related to this model in concurrent way

In this case history is generated based on object type and sharing the same interface. Also created separate task that will execute
in parallel in order to improve speed of execution.

```csharp
public class VersionService : IVersionService
{
    private readonly IVersionProvider _versionProvider;
    private readonly IServiceProvider _serviceProvider;
    public VersionService(IVersionProvider versionProvider, IServiceProvider serviceProvider)
    {
        _versionProvider = versionProvider;
        _serviceProvider = serviceProvider;
    }

    public async Task<ResultStatus> GetHistory(HistoryItemType itemType, long itemId, int skip, int take)
    {
        (long total, List<HistoryItem> data) = await _versionProvider.GetHistory(itemType, itemId, skip, take);
        ResultStatus result = new()
        {
            ResultData = new { total, data }
        };

        return result;
    }

    public async Task SaveHistory(HistoryItemType itemType, long itemId, long userId, dynamic additionalModels = null)
    {
        var extractor = GetHistoryExtractor(itemType);
        var data = await extractor.GetSnapshot(itemId, additionalModels);

        var version = await _versionProvider.GetLatestVersion(itemType, itemId);

        await _versionProvider.Save(new HistoryItem()
        {
            HistoryItemType = (byte)itemType,
            ItemId = itemId,
            Snapshot = data,
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            Version = version + 1
        });
    }

    private IHistoryExtractor GetHistoryExtractor(HistoryItemType itemType)
    {
        return itemType switch
        {
            HistoryItemType.Partner => _serviceProvider.GetService<PartnerHistoryExtractor>(),
            HistoryItemType.User => _serviceProvider.GetService<UserHistoryExtractor>(),
            _ => _serviceProvider.GetService<PartnerHistoryExtractor>(),
        };
    }
}

public partial class PartnerHistoryExtractor : IHistoryExtractor
{
  public async Task<byte[]> GetSnapshot(long itemId, dynamic additionalModels = null)
  {
      PartnerHistoryExtractorModel result = new();
  
      var getPartnerTask = _partnerProvider.GetPartnerDataById(itemId);
  
      var getPartnerIsoSponsorBanksTask = _partnerIsoSponsorBankProvider.GetPartnerIsoSponsorBanks(itemId);
  
      var getPartnerSponsorBankBinsTask = _partnerBINProvider.GetPartnerBINListByPartnerId(itemId);
  
      var getPartnerCommissionInfoTask = _partnerCommissionInfoProvider.GetCommissionInfoByPartnerId(itemId);
  
      var getPartnerRollUpTask =  _partnerRollUpFundingProvider.GetByPartnerId(itemId);
  
      await Task.WhenAll(getPartnerTask, getPartnerIsoSponsorBanksTask, getPartnerSponsorBankBinsTask, getPartnerCommissionInfoTask, getPartnerRollUpTask);
  
      result.Partner = await getPartnerTask;
      result.PartnerIsoSponsorBanks = await getPartnerIsoSponsorBanksTask;
      result.PartnerSponsorBankBins = await getPartnerSponsorBankBinsTask;
      result.PartnerCommissionInfo = await getPartnerCommissionInfoTask;
      result.PartnerRollUpFunding = await getPartnerRollUpTask;
  
      if(additionalModels is WhiteLabelingConfigurationsDto model)
      {
          result.WhiteLabelingConfigurations = model;
      }
  
      return JsonSerializer.SerializeToUtf8Bytes(result);
  }
}
```

### DocuSign webhook implementation and validation

DocuSign webhook was added with validation attribute that required Hash validation verification 
to check the authentity of the request.
Abstract class OkHandler is used in order to incapsulate base logic so it can be reused in any other webhooks.
Authorization attribute is checking if the payload is valid by comparing the hash of payload and signature header
using a secret provided by DocuSign.

```csharp
public class DocuSign : OKHandler<DocuSignWebhookMessage>
{
    private readonly IDocuSignWebhookService _docuSignWebhookService;
    private readonly IMapper _mapper;

    public DocuSign(
        IDocuSignWebhookService docuSignWebhookService, 
        IMapper mapper,
        IHttpContextAccessor contextAccessor) : base(contextAccessor)
    {
        _docuSignWebhookService = docuSignWebhookService;
        _mapper = mapper;
    }

    [DocuSignAuthorize]
    public override async Task Handle([FromBody] DocuSignWebhookMessage request)
    {
        var message = _mapper.Map<DocuSignWebhookMessageDto>(request);
        
        await _docuSignWebhookService.ProcessWebhookMessageAsync(message);
    }
}

internal class DocuSignAuthorizeAttribute : ActionFilterAttribute
{
    private const string DOCUSIGN_SIGNATURE_HEADER = "X-DocuSign-Signature-1";
    public override async void OnActionExecuting(ActionExecutingContext context)
    {
        var tenantProvider = context.HttpContext.RequestServices.GetService<ITenantProvider>();
        var tenantSettingsProvider = context.HttpContext.RequestServices.GetService<ITenantSettingsProvider>();

        var settings = await tenantSettingsProvider.GetESignatureSettingsAsync(tenantProvider.GetTenantName());
        var secret = settings.DocuSignCredentials.WebhookSecret;

        var payload = GetPayload(context);

        if (!TryGetHeaderValue(context, DOCUSIGN_SIGNATURE_HEADER, out string signature) || !HMACValidationHelper.HashIsValid(secret, payload, signature))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        base.OnActionExecuting(context);
    }
}
	
public static string ComputeHash(string secret, string payload)
{
    byte[] bytes = Encoding.UTF8.GetBytes(secret);
    HMAC hmac = new HMACSHA256(bytes);
    bytes = Encoding.UTF8.GetBytes(payload);

    return Convert.ToBase64String(hmac.ComputeHash(bytes));
}

public static bool HashIsValid(string secret, string payload, string verify)
{

    ReadOnlySpan<byte> hashBytes = Convert.FromBase64String(ComputeHash(secret, payload));
    ReadOnlySpan<byte> verifyBytes = Convert.FromBase64String(verify);

    return CryptographicOperations.FixedTimeEquals(hashBytes, verifyBytes);
}
```

### 3rd party integration auth handler

Authentication hander for external service that required additional JWT token generation and injection in request
along with Retry policy. Retry policy helps to reprocess request without additional user interactions to maintain project stability.
Request is intercepted and additional validation is added to it along with default credentials and added to header per external service requirement.

```csharp

public class ExternalServiceAuthHeaderHandler : DelegatingHandler
{
    private readonly ILogger<ExternalServiceAuthHeaderHandler> _logger;
    private readonly IExternalServiceAuthTokenManager _authTokenStore;
    private readonly ITenantSettingsProvider _settings;

    public ExternalServiceAuthHeaderHandler(ILogger<ExternalServiceAuthHeaderHandler> logger,
        IExternalServiceAuthTokenManager authTokenStore,
        ITenantSettingsProvider settings)
    {
        _logger = logger;
        _authTokenStore = authTokenStore;
        _settings = settings;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!request.Properties.ContainsKey(AppConstants.TENANT_PROPERTY_KEY))
        {
            throw new TenantNullException();
        }

        var tenant = request.Properties[AppConstants.TENANT_PROPERTY_KEY] as string;

        var credentials = await _settings.GetTelecomSettingsAsync(tenant);

        var cert = credentials?.SamsungKnoxCredentials.KeysPath;
        var clientId = credentials?.SamsungKnoxCredentials.ClientIdentifier;

        var signedClientId = TokenUtility.generateSignedClientIdentifierJWT(cert, clientId);
        var token = await _authTokenStore.GetTokenAsync(tenant, signedClientId, cancellationToken);
        var signedAccessToken = TokenUtility.generateSignedAccessTokenJWT(cert, token);

        request.Headers.Add("x-apitoken", signedAccessToken);

        // yes, we need this delay. In other case, we will get the unauthorazied error. 
        await Task.Delay(TimeSpan.FromMilliseconds(500));

        var retry = Policy.HandleResult<HttpResponseMessage>(r => r.StatusCode == HttpStatusCode.Unauthorized)
        .OrResult(r => r.StatusCode == HttpStatusCode.Forbidden)
        .WaitAndRetryAsync(1, x => TimeSpan.FromMilliseconds(300));

        return await retry.ExecuteAsync(async () =>
        {
            return await base.SendAsync(request, cancellationToken);
        });
    }
}
```

### Bank file pull and parse functionality

This code is responsible for pulling files from SFTP server of a bank, decrypting it,
 parsing csv file, saving file to AWS S3, saving parsed data in it and sending email notification.
 
 In this example we use one time processing  by saving lastest proccessed date to prevent old data reloading.
 PGP decryption is used to decrypt file with data and CsvReader is used to parse csv files. Also system is connected to
 multiple external sources like SFTP, AWS S3 and email system.

```csharp

public async Task ProcessBankDailyFiles(bool isLambda)
{
    var methodPrefix = $"[{nameof(ProcessbankDailyFiles)}]";
    var currentDate = StaticVariables.DateTimeNowEst().Date;
    var filePath = $"/users/{_mccSettings.bankSettings.SFTPUser}/outgoing";

    var dateTimeLastProcessed = await _systemConfigurationProvider.GetSystemConfiguration<DateTime>(SystemConfiguration.BalancesDateProcessed);
    var dateLastProcessed = dateTimeLastProcessed.Date;
    var daysDiff = (currentDate - dateLastProcessed).Days;
    _emailProcessor = new EmailProcessor(_mccSettings, _dbContext);

    for (var i = 1; i <= daysDiff; i++)
    {
        var iterationDate = dateLastProcessed.AddDays(i);
        if (iterationDate.DayOfWeek == DayOfWeek.Saturday || iterationDate.DayOfWeek == DayOfWeek.Sunday)
            continue;

        try
        {
            var generalFileName = $"TXNDDA_PAYVERSE_{iterationDate:yyyyMMdd}";

            await AddLog($"{methodPrefix} Start file download process for date {iterationDate:yyyy-MM-dd}.");

            _bankCommunicationService.CreateSftpClient(isLambda);

            var generalDownloadResult = await _bankCommunicationService.DownloadFile(filePath, generalFileName);

            await AddLog($@"{methodPrefix} TXN/DDA Download result - {generalDownloadResult.Success}");

            var bankCsvProcessor = new bankCsvProcessor(_mccSettings);

            if (generalDownloadResult.Success)
            {
                var file = (SFTP.SFTPFile)generalDownloadResult.ResultData;

                await AddLog($"{methodPrefix}TXN file saving for backup.");
                _s3Client = new AWS_S3(_mccSettings, _dbContext);

                var filePathToSaveBackup = $"Settlement/ACHFiles/bank_CUP/processed/{generalFileName}.csv.pgp";
                await using var memoryStream = new MemoryStream(file.FileByte);
                await _s3Client.UploadObject(filePathToSaveBackup, memoryStream);

                var balances = (await bankCsvProcessor.ConvertTxnDdaFileToObject(file.FileByte, isLambda))?.ToList();

                await AddLog($"{methodPrefix} TXN/DDA records were successfully parsed, count - {balances.Count}");

                if (!balances.Any())
                    continue;

                var existingRecords = await _bankAccountBalanceProvider
                    .Get($"PostedDate = '{balances.First().PostedDate.GetValueOrDefault().Date:yyyy-MM-dd}'");

                if (existingRecords is null || !existingRecords.Any())
                    continue;

                var insertRecords = balances.Where(x =>
                x.AvailableBalance is not null && x.PostedDate is not null).Select(x => new BankAccountBalance
                {
                    TransactionItem = x.TransactionItem,
                    DDAAccount = x.DDAAccount,
                    PostedDate = x.PostedDate,
                    TransactionCode = x.TransactionCode?.Trim(),
                    TransactionAmount = x.TransactionAmount,
                    TransactionDescription = x.TransactionDescription,
                    AvailableBalance = x.AvailableBalance,
                    TransactionTypeId = GetTransactionType(x.TransactionDescription)
                }).ToList();

                await _bankAccountBalanceProvider.InsertBulk(insertRecords);

                await AddLog($"{methodPrefix} Bank accounts balances inserted successfully. Count - {insertRecords.Count}");

                var returns = insertRecords.Where(x => x.TransactionTypeId == (int)BankAccountTransactionTypes.Returns).ToList();

                if (returns is not null && returns.Any())
                {
                    var date = insertRecords.First().PostedDate.GetValueOrDefault().Date.ToString("MM-dd-yyyy");
                    foreach (var returnRecord in returns)
                    {

                        var subject = $"Returns from bank on {date}, item: {returnRecord.TransactionItem}.";

                        var body = $@"Return from bank was received. Date: {date}; 
		                            Transaction item: {returnRecord.TransactionItem};
		                            Return Amount: {returnRecord.TransactionAmount}; 
		                            Description: {returnRecord.TransactionDescription}.";

                        var emailObj = new EmailQueue
                        {
                            Receiver = _mccSettings.EmailNotificationSettings.UrgentAlert,
                            Sender = _mccSettings.EmailNotificationSettings.NoReplyEmail,
                            Subject = subject,
                            Content = body
                        };

                        await _emailQueueProvider.InsertEmailQueue(emailObj);
                    }
                }

                var sourceFilePath = $"{filePath}/{generalFileName}";
                var destinationFilePath = $"{filePath}/processed/{generalFileName}";
                await _bankCommunicationService.MoveFile(sourceFilePath, destinationFilePath);
            }

        }
        catch (Exception ex)
        {
            await AddLog($"{methodPrefix}[{iterationDate:yyyMMdd}] Exception: {ex.Message}", true);

            //throw in order to not iterate again and hold the last successfull processed date
            throw;
        }

        await _systemConfigurationProvider.UpdateConfig(SystemConfiguration.BalancesDateProcessed, iterationDate.ToString());
    }
}


public async Task<IEnumerable<BankTxnDdaImportModel>> ConvertTxnDdaFileToObject(byte[] encryptedFileBytes, bool isLambda)
{
    using var fileStream = new MemoryStream(encryptedFileBytes);
    Stream keyStream;

    if (isLambda)
    {
        byte[] keyBytes = Convert.FromBase64String(_mccSettings.BankSettings.PGPDecPrivate);
        keyStream = new MemoryStream(keyBytes);
    }
    else
    {
        keyStream = File.OpenRead(_mccSettings.BankSettings.PGPDecPrivate);
    }

    var decryptedFile = PgpCryptoHelper.DecryptFile(fileStream, keyStream, _mccSettings.BankSettings.PGPDecPassphrase);

    var config = new CsvConfiguration(CultureInfo.InvariantCulture)
    {
        MissingFieldFound = null
    };

    TextReader reader = new StreamReader(decryptedFile);
    var csvReader = new CsvReader(reader, config);
    
    var records = csvReader.GetRecords<BankTxnDdaImportModel>().ToList();

    return records;
}
```
