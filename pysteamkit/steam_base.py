class EMsg:

    Invalid = 0
    Multi = 1
    
    BaseGeneral = 100
    GenericReply = 100
    DestJobFailed = 113
    Alert = 115
    SCIDRequest = 120
    SCIDResponse = 121
    JobHeartbeat = 123
    HubConnect = 124
    Subscribe = 126
    RouteMessage = 127
    RemoteSysID = 128
    AMCreateAccountResponse = 129
    WGRequest = 130
    WGResponse = 131
    KeepAlive = 132
    WebAPIJobRequest = 133
    WebAPIJobResponse = 134
    ClientSessionStart = 135
    ClientSessionEnd = 136
    ClientSessionUpdateAuthTicket = 137
    StatsDeprecated = 138
    Ping = 139
    PingResponse = 140
    Stats = 141
    RequestFullStatsBlock = 142
    LoadDBOCacheItem = 143
    LoadDBOCacheItemResponse = 144
    InvalidateDBOCacheItems = 145
    ServiceMethod = 146
    ServiceMethodResponse = 147
    
    BaseShell = 200
    AssignSysID = 200
    Exit = 201
    DirRequest = 202
    DirResponse = 203
    ZipRequest = 204
    ZipResponse = 205
    UpdateRecordResponse = 215
    UpdateCreditCardRequest = 221
    UpdateUserBanResponse = 225
    PrepareToExit = 226
    ContentDescriptionUpdate = 227
    TestResetServer = 228
    UniverseChanged = 229
    ShellConfigInfoUpdate = 230
    RequestWindowsEventLogEntries = 233
    ProvideWindowsEventLogEntries = 234
    ShellSearchLogs = 235
    ShellSearchLogsResponse = 236
    ShellCheckWindowsUpdates = 237
    ShellCheckWindowsUpdatesResponse = 238
    ShellFlushUserLicenseCache = 239
    
    BaseGM = 300
    Heartbeat = 300
    ShellFailed = 301
    ExitShells = 307
    ExitShell = 308
    GracefulExitShell = 309
    NotifyWatchdog = 314
    LicenseProcessingComplete = 316
    SetTestFlag = 317
    QueuedEmailsComplete = 318
    GMReportPHPError = 319
    GMDRMSync = 320
    PhysicalBoxInventory = 321
    UpdateConfigFile = 322
    TestInitDB = 323
    GMWriteConfigToSQL = 324
    GMLoadActivationCodes = 325
    GMQueueForFBS = 326
    GMSchemaConversionResults = 327
    GMSchemaConversionResultsResponse = 328
    GMWriteShellFailureToSQL = 329
    
    BaseAIS = 400
    AISRefreshContentDescription = 401
    AISRequestContentDescription = 402
    AISUpdateAppInfo = 403
    AISUpdatePackageInfo = 404
    AISGetPackageChangeNumber = 405
    AISGetPackageChangeNumberResponse = 406
    AISAppInfoTableChanged = 407
    AISUpdatePackageInfoResponse = 408
    AISCreateMarketingMessage = 409
    AISCreateMarketingMessageResponse = 410
    AISGetMarketingMessage = 411
    AISGetMarketingMessageResponse = 412
    AISUpdateMarketingMessage = 413
    AISUpdateMarketingMessageResponse = 414
    AISRequestMarketingMessageUpdate = 415
    AISDeleteMarketingMessage = 416
    AISGetMarketingTreatments = 419
    AISGetMarketingTreatmentsResponse = 420
    AISRequestMarketingTreatmentUpdate = 421
    AISTestAddPackage = 422
    AIGetAppGCFlags = 423
    AIGetAppGCFlagsResponse = 424
    AIGetAppList = 425
    AIGetAppListResponse = 426
    AIGetAppInfo = 427
    AIGetAppInfoResponse = 428
    AISGetCouponDefinition = 429
    AISGetCouponDefinitionResponse = 430
    
    BaseAM = 500
    AMUpdateUserBanRequest = 504
    AMAddLicense = 505
    AMBeginProcessingLicenses = 507
    AMSendSystemIMToUser = 508
    AMExtendLicense = 509
    AMAddMinutesToLicense = 510
    AMCancelLicense = 511
    AMInitPurchase = 512
    AMPurchaseResponse = 513
    AMGetFinalPrice = 514
    AMGetFinalPriceResponse = 515
    AMGetLegacyGameKey = 516
    AMGetLegacyGameKeyResponse = 517
    AMFindHungTransactions = 518
    AMSetAccountTrustedRequest = 519
    AMCompletePurchase = 521
    AMCancelPurchase = 522
    AMNewChallenge = 523
    AMFixPendingPurchaseResponse = 526
    AMIsUserBanned = 527
    AMRegisterKey = 528
    AMLoadActivationCodes = 529
    AMLoadActivationCodesResponse = 530
    AMLookupKeyResponse = 531
    AMLookupKey = 532
    AMChatCleanup = 533
    AMClanCleanup = 534
    AMFixPendingRefund = 535
    AMReverseChargeback = 536
    AMReverseChargebackResponse = 537
    AMClanCleanupList = 538
    AMGetLicenses = 539
    AMGetLicensesResponse = 540
    AllowUserToPlayQuery = 550
    AllowUserToPlayResponse = 551
    AMVerfiyUser = 552
    AMClientNotPlaying = 553
    ClientRequestFriendship = 554
    AMRelayPublishStatus = 555
    AMResetCommunityContent = 556
    AMPrimePersonaStateCache = 557
    AMAllowUserContentQuery = 558
    AMAllowUserContentResponse = 559
    AMInitPurchaseResponse = 560
    AMRevokePurchaseResponse = 561
    AMLockProfile = 562
    AMRefreshGuestPasses = 563
    AMInviteUserToClan = 564
    AMAcknowledgeClanInvite = 565
    AMGrantGuestPasses = 566
    AMClanDataUpdated = 567
    AMReloadAccount = 568
    AMClientChatMsgRelay = 569
    AMChatMulti = 570
    AMClientChatInviteRelay = 571
    AMChatInvite = 572
    AMClientJoinChatRelay = 573
    AMClientChatMemberInfoRelay = 574
    AMPublishChatMemberInfo = 575
    AMClientAcceptFriendInvite = 576
    AMChatEnter = 577
    AMClientPublishRemovalFromSource = 578
    AMChatActionResult = 579
    AMFindAccounts = 580
    AMFindAccountsResponse = 581
    AMSetAccountFlags = 584
    AMCreateClan = 586
    AMCreateClanResponse = 587
    AMGetClanDetails = 588
    AMGetClanDetailsResponse = 589
    AMSetPersonaName = 590
    AMSetAvatar = 591
    AMAuthenticateUser = 592
    AMAuthenticateUserResponse = 593
    AMGetAccountFriendsCount = 594
    AMGetAccountFriendsCountResponse = 595
    AMP2PIntroducerMessage = 596
    ClientChatAction = 597
    AMClientChatActionRelay = 598
    
    BaseVS = 600
    ReqChallenge = 600
    VACResponse = 601
    ReqChallengeTest = 602
    VSMarkCheat = 604
    VSAddCheat = 605
    VSPurgeCodeModDB = 606
    VSGetChallengeResults = 607
    VSChallengeResultText = 608
    VSReportLingerer = 609
    VSRequestManagedChallenge = 610
    VSLoadDBFinished = 611
    
    BaseDRMS = 625
    DRMBuildBlobRequest = 628
    DRMBuildBlobResponse = 629
    DRMResolveGuidRequest = 630
    DRMResolveGuidResponse = 631
    DRMVariabilityReport = 633
    DRMVariabilityReportResponse = 634
    DRMStabilityReport = 635
    DRMStabilityReportResponse = 636
    DRMDetailsReportRequest = 637
    DRMDetailsReportResponse = 638
    DRMProcessFile = 639
    DRMAdminUpdate = 640
    DRMAdminUpdateResponse = 641
    DRMSync = 642
    DRMSyncResponse = 643
    DRMProcessFileResponse = 644
    DRMEmptyGuidCache = 645
    DRMEmptyGuidCacheResponse = 646
    
    BaseCS = 650
    CSUserContentRequest = 652
    
    BaseClient = 700
    ClientLogOn_Deprecated = 701
    ClientAnonLogOn_Deprecated = 702
    ClientHeartBeat = 703
    ClientVACResponse = 704
    ClientGamesPlayed_obsolete = 705
    ClientLogOff = 706
    ClientNoUDPConnectivity = 707
    ClientInformOfCreateAccount = 708
    ClientAckVACBan = 709
    ClientConnectionStats = 710
    ClientInitPurchase = 711
    ClientPingResponse = 712
    ClientRemoveFriend = 714
    ClientGamesPlayedNoDataBlob = 715
    ClientChangeStatus = 716
    ClientVacStatusResponse = 717
    ClientFriendMsg = 718
    ClientGameConnect_obsolete = 719
    ClientGamesPlayed2_obsolete = 720
    ClientGameEnded_obsolete = 721
    ClientGetFinalPrice = 722
    ClientSystemIM = 726
    ClientSystemIMAck = 727
    ClientGetLicenses = 728
    ClientCancelLicense = 729
    ClientGetLegacyGameKey = 730
    ClientContentServerLogOn_Deprecated = 731
    ClientAckVACBan2 = 732
    ClientAckMessageByGID = 735
    ClientGetPurchaseReceipts = 736
    ClientAckPurchaseReceipt = 737
    ClientGamesPlayed3_obsolete = 738
    ClientSendGuestPass = 739
    ClientAckGuestPass = 740
    ClientRedeemGuestPass = 741
    ClientGamesPlayed = 742
    ClientRegisterKey = 743
    ClientInviteUserToClan = 744
    ClientAcknowledgeClanInvite = 745
    ClientPurchaseWithMachineID = 746
    ClientAppUsageEvent = 747
    ClientGetGiftTargetList = 748
    ClientGetGiftTargetListResponse = 749
    ClientLogOnResponse = 751
    ClientVACChallenge = 753
    ClientSetHeartbeatRate = 755
    ClientNotLoggedOnDeprecated = 756
    ClientLoggedOff = 757
    GSApprove = 758
    GSDeny = 759
    GSKick = 760
    ClientCreateAcctResponse = 761
    ClientPurchaseResponse = 763
    ClientPing = 764
    ClientNOP = 765
    ClientPersonaState = 766
    ClientFriendsList = 767
    ClientAccountInfo = 768
    ClientVacStatusQuery = 770
    ClientNewsUpdate = 771
    ClientGameConnectDeny = 773
    GSStatusReply = 774
    ClientGetFinalPriceResponse = 775
    ClientGameConnectTokens = 779
    ClientLicenseList = 780
    ClientCancelLicenseResponse = 781
    ClientVACBanStatus = 782
    ClientCMList = 783
    ClientEncryptPct = 784
    ClientGetLegacyGameKeyResponse = 785
    ClientFavoritesList = 786
    CSUserContentApprove = 787
    CSUserContentDeny = 788
    ClientInitPurchaseResponse = 789
    ClientAddFriend = 791
    ClientAddFriendResponse = 792
    ClientInviteFriend = 793
    ClientInviteFriendResponse = 794
    ClientSendGuestPassResponse = 795
    ClientAckGuestPassResponse = 796
    ClientRedeemGuestPassResponse = 797
    ClientUpdateGuestPassesList = 798
    ClientChatMsg = 799
    ClientChatInvite = 800
    ClientJoinChat = 801
    ClientChatMemberInfo = 802
    ClientLogOnWithCredentials_Deprecated = 803
    ClientPasswordChangeResponse = 805
    ClientChatEnter = 807
    ClientFriendRemovedFromSource = 808
    ClientCreateChat = 809
    ClientCreateChatResponse = 810
    ClientUpdateChatMetadata = 811
    ClientP2PIntroducerMessage = 813
    ClientChatActionResult = 814
    ClientRequestFriendData = 815
    ClientGetUserStats = 818
    ClientGetUserStatsResponse = 819
    ClientStoreUserStats = 820
    ClientStoreUserStatsResponse = 821
    ClientClanState = 822
    ClientServiceModule = 830
    ClientServiceCall = 831
    ClientServiceCallResponse = 832
    ClientPackageInfoRequest = 833
    ClientPackageInfoResponse = 834
    ClientNatTraversalStatEvent = 839
    ClientAppInfoRequest = 840
    ClientAppInfoResponse = 841
    ClientSteamUsageEvent = 842
    ClientCheckPassword = 845
    ClientResetPassword = 846
    ClientCheckPasswordResponse = 848
    ClientResetPasswordResponse = 849
    ClientSessionToken = 850
    ClientDRMProblemReport = 851
    ClientSetIgnoreFriend = 855
    ClientSetIgnoreFriendResponse = 856
    ClientGetAppOwnershipTicket = 857
    ClientGetAppOwnershipTicketResponse = 858
    ClientGetLobbyListResponse = 860
    ClientGetLobbyMetadata = 861
    ClientGetLobbyMetadataResponse = 862
    ClientVTTCert = 863
    ClientAppInfoUpdate = 866
    ClientAppInfoChanges = 867
    ClientServerList = 880
    ClientEmailChangeResponse = 891
    ClientSecretQAChangeResponse = 892
    ClientDRMBlobRequest = 896
    ClientDRMBlobResponse = 897
    ClientLookupKey = 898
    ClientLookupKeyResponse = 899
    
    BaseGameServer = 900
    GSDisconnectNotice = 901
    GSStatus = 903
    GSUserPlaying = 905
    GSStatus2 = 906
    GSStatusUpdate_Unused = 907
    GSServerType = 908
    GSPlayerList = 909
    GSGetUserAchievementStatus = 910
    GSGetUserAchievementStatusResponse = 911
    GSGetPlayStats = 918
    GSGetPlayStatsResponse = 919
    GSGetUserGroupStatus = 920
    AMGetUserGroupStatus = 921
    AMGetUserGroupStatusResponse = 922
    GSGetUserGroupStatusResponse = 923
    GSGetReputation = 936
    GSGetReputationResponse = 937
    GSAssociateWithClan = 938
    GSAssociateWithClanResponse = 939
    GSComputeNewPlayerCompatibility = 940
    GSComputeNewPlayerCompatibilityResponse = 941
    
    BaseAdmin = 1000
    AdminCmd = 1000
    AdminCmdResponse = 1004
    AdminLogListenRequest = 1005
    AdminLogEvent = 1006
    LogSearchRequest = 1007
    LogSearchResponse = 1008
    LogSearchCancel = 1009
    UniverseData = 1010
    RequestStatHistory = 1014
    StatHistory = 1015
    AdminPwLogon = 1017
    AdminPwLogonResponse = 1018
    AdminSpew = 1019
    AdminConsoleTitle = 1020
    AdminGCSpew = 1023
    AdminGCCommand = 1024
    AdminGCGetCommandList = 1025
    AdminGCGetCommandListResponse = 1026
    FBSConnectionData = 1027
    AdminMsgSpew = 1028
    
    BaseFBS = 1100
    FBSReqVersion = 1100
    FBSVersionInfo = 1101
    FBSForceRefresh = 1102
    FBSForceBounce = 1103
    FBSDeployPackage = 1104
    FBSDeployResponse = 1105
    FBSUpdateBootstrapper = 1106
    FBSSetState = 1107
    FBSApplyOSUpdates = 1108
    FBSRunCMDScript = 1109
    FBSRebootBox = 1110
    FBSSetBigBrotherMode = 1111
    FBSMinidumpServer = 1112
    FBSSetShellCount_obsolete = 1113
    FBSDeployHotFixPackage = 1114
    FBSDeployHotFixResponse = 1115
    FBSDownloadHotFix = 1116
    FBSDownloadHotFixResponse = 1117
    FBSUpdateTargetConfigFile = 1118
    FBSApplyAccountCred = 1119
    FBSApplyAccountCredResponse = 1120
    FBSSetShellCount = 1121
    FBSTerminateShell = 1122
    FBSQueryGMForRequest = 1123
    FBSQueryGMResponse = 1124
    FBSTerminateZombies = 1125
    FBSInfoFromBootstrapper = 1126
    FBSRebootBoxResponse = 1127
    FBSBootstrapperPackageRequest = 1128
    FBSBootstrapperPackageResponse = 1129
    FBSBootstrapperGetPackageChunk = 1130
    FBSBootstrapperGetPackageChunkResponse = 1131
    FBSBootstrapperPackageTransferProgress = 1132
    FBSRestartBootstrapper = 1133
    
    BaseFileXfer = 1200
    FileXferRequest = 1200
    FileXferResponse = 1201
    FileXferData = 1202
    FileXferEnd = 1203
    FileXferDataAck = 1204
    
    BaseChannelAuth = 1300
    ChannelAuthChallenge = 1300
    ChannelAuthResponse = 1301
    ChannelAuthResult = 1302
    ChannelEncryptRequest = 1303
    ChannelEncryptResponse = 1304
    ChannelEncryptResult = 1305
    
    BaseBS = 1400
    BSPurchaseStart = 1401
    BSPurchaseResponse = 1402
    BSSettleNOVA = 1404
    BSSettleComplete = 1406
    BSBannedRequest = 1407
    BSInitPayPalTxn = 1408
    BSInitPayPalTxnResponse = 1409
    BSGetPayPalUserInfo = 1410
    BSGetPayPalUserInfoResponse = 1411
    BSRefundTxn = 1413
    BSRefundTxnResponse = 1414
    BSGetEvents = 1415
    BSChaseRFRRequest = 1416
    BSPaymentInstrBan = 1417
    BSPaymentInstrBanResponse = 1418
    BSProcessGCReports = 1419
    BSProcessPPReports = 1420
    BSInitGCBankXferTxn = 1421
    BSInitGCBankXferTxnResponse = 1422
    BSQueryGCBankXferTxn = 1423
    BSQueryGCBankXferTxnResponse = 1424
    BSCommitGCTxn = 1425
    BSQueryTransactionStatus = 1426
    BSQueryTransactionStatusResponse = 1427
    BSQueryCBOrderStatus = 1428
    BSQueryCBOrderStatusResponse = 1429
    BSRunRedFlagReport = 1430
    BSQueryPaymentInstUsage = 1431
    BSQueryPaymentInstResponse = 1432
    BSQueryTxnExtendedInfo = 1433
    BSQueryTxnExtendedInfoResponse = 1434
    BSUpdateConversionRates = 1435
    BSProcessUSBankReports = 1436
    BSPurchaseRunFraudChecks = 1437
    BSPurchaseRunFraudChecksResponse = 1438
    BSStartShippingJobs = 1439
    BSQueryBankInformation = 1440
    BSQueryBankInformationResponse = 1441
    BSValidateXsollaSignature = 1445
    BSValidateXsollaSignatureResponse = 1446
    BSQiwiWalletInvoice = 1448
    BSQiwiWalletInvoiceResponse = 1449
    BSUpdateInventoryFromProPack = 1450
    BSUpdateInventoryFromProPackResponse = 1451
    BSSendShippingRequest = 1452
    BSSendShippingRequestResponse = 1453
    BSGetProPackOrderStatus = 1454
    BSGetProPackOrderStatusResponse = 1455
    BSCheckJobRunning = 1456
    BSCheckJobRunningResponse = 1457
    BSResetPackagePurchaseRateLimit = 1458
    BSResetPackagePurchaseRateLimitResponse = 1459
    BSUpdatePaymentData = 1460
    BSUpdatePaymentDataResponse = 1461
    BSGetBillingAddress = 1462
    BSGetBillingAddressResponse = 1463
    BSGetCreditCardInfo = 1464
    BSGetCreditCardInfoResponse = 1465
    BSRemoveExpiredPaymentData = 1468
    BSRemoveExpiredPaymentDataResponse = 1469
    BSConvertToCurrentKeys = 1470
    BSConvertToCurrentKeysResponse = 1471
    BSInitPurchase = 1472
    BSInitPurchaseResponse = 1473
    BSCompletePurchase = 1474
    BSCompletePurchaseResponse = 1475
    BSPruneCardUsageStats = 1476
    BSPruneCardUsageStatsResponse = 1477
    BSStoreBankInformation = 1478
    BSStoreBankInformationResponse = 1479
    BSVerifyPOSAKey = 1480
    BSVerifyPOSAKeyResponse = 1481
    BSReverseRedeemPOSAKey = 1482
    BSReverseRedeemPOSAKeyResponse = 1483
    BSQueryFindCreditCard = 1484
    BSQueryFindCreditCardResponse = 1485
    BSStatusInquiryPOSAKey = 1486
    BSStatusInquiryPOSAKeyResponse = 1487
    BSValidateMoPaySignature = 1488
    BSValidateMoPaySignatureResponse = 1489
    BSMoPayConfirmProductDelivery = 1490
    BSMoPayConfirmProductDeliveryResponse = 1491
    BSGenerateMoPayMD5 = 1492
    BSGenerateMoPayMD5Response = 1493
    BSBoaCompraConfirmProductDelivery = 1494
    BSBoaCompraConfirmProductDeliveryResponse = 1495
    BSGenerateBoaCompraMD5 = 1496
    BSGenerateBoaCompraMD5Response = 1497
    
    BaseATS = 1500
    ATSStartStressTest = 1501
    ATSStopStressTest = 1502
    ATSRunFailServerTest = 1503
    ATSUFSPerfTestTask = 1504
    ATSUFSPerfTestResponse = 1505
    ATSCycleTCM = 1506
    ATSInitDRMSStressTest = 1507
    ATSCallTest = 1508
    ATSCallTestReply = 1509
    ATSStartExternalStress = 1510
    ATSExternalStressJobStart = 1511
    ATSExternalStressJobQueued = 1512
    ATSExternalStressJobRunning = 1513
    ATSExternalStressJobStopped = 1514
    ATSExternalStressJobStopAll = 1515
    ATSExternalStressActionResult = 1516
    ATSStarted = 1517
    ATSCSPerfTestTask = 1518
    ATSCSPerfTestResponse = 1519
    
    BaseDP = 1600
    DPSetPublishingState = 1601
    DPGamePlayedStats = 1602
    DPUniquePlayersStat = 1603
    DPVacInfractionStats = 1605
    DPVacBanStats = 1606
    DPBlockingStats = 1607
    DPNatTraversalStats = 1608
    DPSteamUsageEvent = 1609
    DPVacCertBanStats = 1610
    DPVacCafeBanStats = 1611
    DPCloudStats = 1612
    DPAchievementStats = 1613
    DPAccountCreationStats = 1614
    DPGetPlayerCount = 1615
    DPGetPlayerCountResponse = 1616
    DPGameServersPlayersStats = 1617
    DPDownloadRateStatistics = 1618
    DPFacebookStatistics = 1619
    ClientDPCheckSpecialSurvey = 1620
    ClientDPCheckSpecialSurveyResponse = 1621
    ClientDPSendSpecialSurveyResponse = 1622
    ClientDPSendSpecialSurveyResponseReply = 1623
    DPStoreSaleStatistics = 1624
    ClientDPUpdateAppJobReport = 1625
    ClientDPSteam2AppStarted = 1627
    DPUpdateContentEvent = 1626
    ClientDPContentStatsReport = 1630
    
    BaseCM = 1700
    CMSetAllowState = 1701
    CMSpewAllowState = 1702
    CMAppInfoResponseDeprecated = 1703
    
    BaseDSS = 1800
    DSSNewFile = 1801
    DSSCurrentFileList = 1802
    DSSSynchList = 1803
    DSSSynchListResponse = 1804
    DSSSynchSubscribe = 1805
    DSSSynchUnsubscribe = 1806
    
    BaseEPM = 1900
    EPMStartProcess = 1901
    EPMStopProcess = 1902
    EPMRestartProcess = 1903
    
    BaseGC = 2200
    GCSendClient = 2200
    AMRelayToGC = 2201
    GCUpdatePlayedState = 2202
    GCCmdRevive = 2203
    GCCmdBounce = 2204
    GCCmdForceBounce = 2205
    GCCmdDown = 2206
    GCCmdDeploy = 2207
    GCCmdDeployResponse = 2208
    GCCmdSwitch = 2209
    AMRefreshSessions = 2210
    GCUpdateGSState = 2211
    GCAchievementAwarded = 2212
    GCSystemMessage = 2213
    GCValidateSession = 2214
    GCValidateSessionResponse = 2215
    GCCmdStatus = 2216
    GCRegisterWebInterfaces = 2217
    GCRegisterWebInterfaces_Deprecated = 2217
    GCGetAccountDetails = 2218
    GCGetAccountDetails_DEPRECATED = 2218
    GCInterAppMessage = 2219
    GCGetEmailTemplate = 2220
    GCGetEmailTemplateResponse = 2221
    ISRelayToGCH = 2222
    GCHRelayClientToIS = 2223
    GCHUpdateSession = 2224
    GCHRequestUpdateSession = 2225
    GCHRequestStatus = 2226
    GCHRequestStatusResponse = 2227
    
    BaseP2P = 2500
    P2PIntroducerMessage = 2502
    
    BaseSM = 2900
    SMExpensiveReport = 2902
    SMHourlyReport = 2903
    SMFishingReport = 2904
    SMPartitionRenames = 2905
    SMMonitorSpace = 2906
    SMGetSchemaConversionResults = 2907
    SMGetSchemaConversionResultsResponse = 2908
    
    BaseTest = 3000
    FailServer = 3000
    JobHeartbeatTest = 3001
    JobHeartbeatTestResponse = 3002
    
    BaseFTSRange = 3100
    FTSGetBrowseCounts = 3101
    FTSGetBrowseCountsResponse = 3102
    FTSBrowseClans = 3103
    FTSBrowseClansResponse = 3104
    FTSSearchClansByLocation = 3105
    FTSSearchClansByLocationResponse = 3106
    FTSSearchPlayersByLocation = 3107
    FTSSearchPlayersByLocationResponse = 3108
    FTSClanDeleted = 3109
    FTSSearch = 3110
    FTSSearchResponse = 3111
    FTSSearchStatus = 3112
    FTSSearchStatusResponse = 3113
    FTSGetGSPlayStats = 3114
    FTSGetGSPlayStatsResponse = 3115
    FTSGetGSPlayStatsForServer = 3116
    FTSGetGSPlayStatsForServerResponse = 3117
    FTSReportIPUpdates = 3118
    
    BaseCCSRange = 3150
    CCSGetComments = 3151
    CCSGetCommentsResponse = 3152
    CCSAddComment = 3153
    CCSAddCommentResponse = 3154
    CCSDeleteComment = 3155
    CCSDeleteCommentResponse = 3156
    CCSPreloadComments = 3157
    CCSNotifyCommentCount = 3158
    CCSGetCommentsForNews = 3159
    CCSGetCommentsForNewsResponse = 3160
    CCSDeleteAllCommentsByAuthor = 3161
    CCSDeleteAllCommentsByAuthorResponse = 3162
    
    BaseLBSRange = 3200
    LBSSetScore = 3201
    LBSSetScoreResponse = 3202
    LBSFindOrCreateLB = 3203
    LBSFindOrCreateLBResponse = 3204
    LBSGetLBEntries = 3205
    LBSGetLBEntriesResponse = 3206
    LBSGetLBList = 3207
    LBSGetLBListResponse = 3208
    LBSSetLBDetails = 3209
    LBSDeleteLB = 3210
    LBSDeleteLBEntry = 3211
    LBSResetLB = 3212
    
    BaseOGS = 3400
    OGSBeginSession = 3401
    OGSBeginSessionResponse = 3402
    OGSEndSession = 3403
    OGSEndSessionResponse = 3404
    OGSWriteAppSessionRow = 3406

    BaseBRP = 3600
    BRPStartShippingJobs = 3601
    BRPProcessUSBankReports = 3602
    BRPProcessGCReports = 3603
    BRPProcessPPReports = 3604
    BRPSettleNOVA = 3605
    BRPSettleCB = 3606
    BRPCommitGC = 3607
    BRPCommitGCResponse = 3608
    BRPFindHungTransactions = 3609
    BRPCheckFinanceCloseOutDate = 3610
    BRPProcessLicenses = 3611
    BRPProcessLicensesResponse = 3612
    BRPRemoveExpiredPaymentData = 3613
    BRPRemoveExpiredPaymentDataResponse = 3614
    BRPConvertToCurrentKeys = 3615
    BRPConvertToCurrentKeysResponse = 3616
    BRPPruneCardUsageStats = 3617
    BRPPruneCardUsageStatsResponse = 3618
    BRPCheckActivationCodes = 3619
    BRPCheckActivationCodesResponse = 3620
    
    BaseAMRange2 = 4000
    AMCreateChat = 4001
    AMCreateChatResponse = 4002
    AMUpdateChatMetadata = 4003
    AMPublishChatMetadata = 4004
    AMSetProfileURL = 4005
    AMGetAccountEmailAddress = 4006
    AMGetAccountEmailAddressResponse = 4007
    AMRequestFriendData = 4008
    AMRouteToClients = 4009
    AMLeaveClan = 4010
    AMClanPermissions = 4011
    AMClanPermissionsResponse = 4012
    AMCreateClanEvent = 4013
    AMCreateClanEventResponse = 4014
    AMUpdateClanEvent = 4015
    AMUpdateClanEventResponse = 4016
    AMGetClanEvents = 4017
    AMGetClanEventsResponse = 4018
    AMDeleteClanEvent = 4019
    AMDeleteClanEventResponse = 4020
    AMSetClanPermissionSettings = 4021
    AMSetClanPermissionSettingsResponse = 4022
    AMGetClanPermissionSettings = 4023
    AMGetClanPermissionSettingsResponse = 4024
    AMPublishChatRoomInfo = 4025
    ClientChatRoomInfo = 4026
    AMCreateClanAnnouncement = 4027
    AMCreateClanAnnouncementResponse = 4028
    AMUpdateClanAnnouncement = 4029
    AMUpdateClanAnnouncementResponse = 4030
    AMGetClanAnnouncementsCount = 4031
    AMGetClanAnnouncementsCountResponse = 4032
    AMGetClanAnnouncements = 4033
    AMGetClanAnnouncementsResponse = 4034
    AMDeleteClanAnnouncement = 4035
    AMDeleteClanAnnouncementResponse = 4036
    AMGetSingleClanAnnouncement = 4037
    AMGetSingleClanAnnouncementResponse = 4038
    AMGetClanHistory = 4039
    AMGetClanHistoryResponse = 4040
    AMGetClanPermissionBits = 4041
    AMGetClanPermissionBitsResponse = 4042
    AMSetClanPermissionBits = 4043
    AMSetClanPermissionBitsResponse = 4044
    AMSessionInfoRequest = 4045
    AMSessionInfoResponse = 4046
    AMValidateWGToken = 4047
    AMGetSingleClanEvent = 4048
    AMGetSingleClanEventResponse = 4049
    AMGetClanRank = 4050
    AMGetClanRankResponse = 4051
    AMSetClanRank = 4052
    AMSetClanRankResponse = 4053
    AMGetClanPOTW = 4054
    AMGetClanPOTWResponse = 4055
    AMSetClanPOTW = 4056
    AMSetClanPOTWResponse = 4057
    AMRequestChatMetadata = 4058
    AMDumpUser = 4059
    AMKickUserFromClan = 4060
    AMAddFounderToClan = 4061
    AMValidateWGTokenResponse = 4062
    AMSetCommunityState = 4063
    AMSetAccountDetails = 4064
    AMGetChatBanList = 4065
    AMGetChatBanListResponse = 4066
    AMUnBanFromChat = 4067
    AMSetClanDetails = 4068
    AMGetAccountLinks = 4069
    AMGetAccountLinksResponse = 4070
    AMSetAccountLinks = 4071
    AMSetAccountLinksResponse = 4072
    AMGetUserGameStats = 4073
    AMGetUserGameStatsResponse = 4074
    AMCheckClanMembership = 4075
    AMGetClanMembers = 4076
    AMGetClanMembersResponse = 4077
    AMJoinPublicClan = 4078
    AMNotifyChatOfClanChange = 4079
    AMResubmitPurchase = 4080
    AMAddFriend = 4081
    AMAddFriendResponse = 4082
    AMRemoveFriend = 4083
    AMDumpClan = 4084
    AMChangeClanOwner = 4085
    AMCancelEasyCollect = 4086
    AMCancelEasyCollectResponse = 4087
    AMGetClanMembershipList = 4088
    AMGetClanMembershipListResponse = 4089
    AMClansInCommon = 4090
    AMClansInCommonResponse = 4091
    AMIsValidAccountID = 4092
    AMConvertClan = 4093
    AMGetGiftTargetListRelay = 4094
    AMWipeFriendsList = 4095
    AMSetIgnored = 4096
    AMClansInCommonCountResponse = 4097
    AMFriendsList = 4098
    AMFriendsListResponse = 4099
    AMFriendsInCommon = 4100
    AMFriendsInCommonResponse = 4101
    AMFriendsInCommonCountResponse = 4102
    AMClansInCommonCount = 4103
    AMChallengeVerdict = 4104
    AMChallengeNotification = 4105
    AMFindGSByIP = 4106
    AMFoundGSByIP = 4107
    AMGiftRevoked = 4108
    AMCreateAccountRecord = 4109
    AMUserClanList = 4110
    AMUserClanListResponse = 4111
    AMGetAccountDetails2 = 4112
    AMGetAccountDetailsResponse2 = 4113
    AMSetCommunityProfileSettings = 4114
    AMSetCommunityProfileSettingsResponse = 4115
    AMGetCommunityPrivacyState = 4116
    AMGetCommunityPrivacyStateResponse = 4117
    AMCheckClanInviteRateLimiting = 4118
    AMGetUserAchievementStatus = 4119
    AMGetIgnored = 4120
    AMGetIgnoredResponse = 4121
    AMSetIgnoredResponse = 4122
    AMSetFriendRelationshipNone_ = 4123
    AMGetFriendRelationship = 4124
    AMGetFriendRelationshipResponse = 4125
    AMServiceModulesCache = 4126
    AMServiceModulesCall = 4127
    AMServiceModulesCallResponse = 4128
    AMGetCaptchaDataForIP = 4129
    AMGetCaptchaDataForIPResponse = 4130
    AMValidateCaptchaDataForIP = 4131
    AMValidateCaptchaDataForIPResponse = 4132
    AMTrackFailedAuthByIP = 4133
    AMGetCaptchaDataByGID = 4134
    AMGetCaptchaDataByGIDResponse = 4135
    AMGetLobbyList = 4136
    AMGetLobbyListResponse = 4137
    AMGetLobbyMetadata = 4138
    AMGetLobbyMetadataResponse = 4139
    CommunityAddFriendNews = 4140
    AMAddClanNews = 4141
    AMWriteNews = 4142
    AMFindClanUser = 4143
    AMFindClanUserResponse = 4144
    AMBanFromChat = 4145
    AMGetUserHistoryResponse = 4146
    AMGetUserNewsSubscriptions = 4147
    AMGetUserNewsSubscriptionsResponse = 4148
    AMSetUserNewsSubscriptions = 4149
    AMGetUserNews = 4150
    AMGetUserNewsResponse = 4151
    AMSendQueuedEmails = 4152
    AMSetLicenseFlags = 4153
    AMGetUserHistory = 4154
    CommunityDeleteUserNews = 4155
    AMAllowUserFilesRequest = 4156
    AMAllowUserFilesResponse = 4157
    AMGetAccountStatus = 4158
    AMGetAccountStatusResponse = 4159
    AMEditBanReason = 4160
    AMCheckClanMembershipResponse = 4161
    AMProbeClanMembershipList = 4162
    AMProbeClanMembershipListResponse = 4163
    AMGetFriendsLobbies = 4165
    AMGetFriendsLobbiesResponse = 4166
    AMGetUserFriendNewsResponse = 4172
    CommunityGetUserFriendNews = 4173
    AMGetUserClansNewsResponse = 4174
    AMGetUserClansNews = 4175
    AMStoreInitPurchase = 4176
    AMStoreInitPurchaseResponse = 4177
    AMStoreGetFinalPrice = 4178
    AMStoreGetFinalPriceResponse = 4179
    AMStoreCompletePurchase = 4180
    AMStoreCancelPurchase = 4181
    AMStorePurchaseResponse = 4182
    AMCreateAccountRecordInSteam3 = 4183
    AMGetPreviousCBAccount = 4184
    AMGetPreviousCBAccountResponse = 4185
    AMUpdateBillingAddress = 4186
    AMUpdateBillingAddressResponse = 4187
    AMGetBillingAddress = 4188
    AMGetBillingAddressResponse = 4189
    AMGetUserLicenseHistory = 4190
    AMGetUserLicenseHistoryResponse = 4191
    AMSupportChangePassword = 4194
    AMSupportChangeEmail = 4195
    AMSupportChangeSecretQA = 4196
    AMResetUserVerificationGSByIP = 4197
    AMUpdateGSPlayStats = 4198
    AMSupportEnableOrDisable = 4199
    AMGetComments = 4200
    AMGetCommentsResponse = 4201
    AMAddComment = 4202
    AMAddCommentResponse = 4203
    AMDeleteComment = 4204
    AMDeleteCommentResponse = 4205
    AMGetPurchaseStatus = 4206
    AMSupportIsAccountEnabled = 4209
    AMSupportIsAccountEnabledResponse = 4210
    AMGetUserStats = 4211
    AMSupportKickSession = 4212
    AMGSSearch = 4213
    MarketingMessageUpdate = 4216
    AMRouteFriendMsg = 4219
    AMTicketAuthRequestOrResponse = 4220
    AMVerifyDepotManagementRights = 4222
    AMVerifyDepotManagementRightsResponse = 4223
    AMAddFreeLicense = 4224
    AMGetUserFriendsMinutesPlayed = 4225
    AMGetUserFriendsMinutesPlayedResponse = 4226
    AMGetUserMinutesPlayed = 4227
    AMGetUserMinutesPlayedResponse = 4228
    AMValidateEmailLink = 4231
    AMValidateEmailLinkResponse = 4232
    AMAddUsersToMarketingTreatment = 4234
    AMStoreUserStats = 4236
    AMGetUserGameplayInfo = 4237
    AMGetUserGameplayInfoResponse = 4238
    AMGetCardList = 4239
    AMGetCardListResponse = 4240
    AMDeleteStoredCard = 4241
    AMRevokeLegacyGameKeys = 4242
    AMGetWalletDetails = 4244
    AMGetWalletDetailsResponse = 4245
    AMDeleteStoredPaymentInfo = 4246
    AMGetStoredPaymentSummary = 4247
    AMGetStoredPaymentSummaryResponse = 4248
    AMGetWalletConversionRate = 4249
    AMGetWalletConversionRateResponse = 4250
    AMConvertWallet = 4251
    AMConvertWalletResponse = 4252
    AMRelayGetFriendsWhoPlayGame = 4253
    AMRelayGetFriendsWhoPlayGameResponse = 4254
    AMSetPreApproval = 4255
    AMSetPreApprovalResponse = 4256
    AMMarketingTreatmentUpdate = 4257
    AMCreateRefund = 4258
    AMCreateRefundResponse = 4259
    AMCreateChargeback = 4260
    AMCreateChargebackResponse = 4261
    AMCreateDispute = 4262
    AMCreateDisputeResponse = 4263
    AMClearDispute = 4264
    AMClearDisputeResponse = 4265
    AMPlayerNicknameList = 4266
    AMPlayerNicknameListResponse = 4267
    AMSetDRMTestConfig = 4268
    AMGetUserCurrentGameInfo = 4269
    AMGetUserCurrentGameInfoResponse = 4270
    AMGetGSPlayerList = 4271
    AMGetGSPlayerListResponse = 4272
    AMUpdatePersonaStateCache = 4275
    AMGetGameMembers = 4276
    AMGetGameMembersResponse = 4277
    AMGetSteamIDForMicroTxn = 4278
    AMGetSteamIDForMicroTxnResponse = 4279
    AMAddPublisherUser = 4280
    AMRemovePublisherUser = 4281
    AMGetUserLicenseList = 4282
    AMGetUserLicenseListResponse = 4283
    AMReloadGameGroupPolicy = 4284
    AMAddFreeLicenseResponse = 4285
    AMVACStatusUpdate = 4286
    AMGetAccountDetails = 4287
    AMGetAccountDetailsResponse = 4288
    AMGetPlayerLinkDetails = 4289
    AMGetPlayerLinkDetailsResponse = 4290
    AMSubscribeToPersonaFeed = 4291
    AMGetUserVacBanList = 4292
    AMGetUserVacBanListResponse = 4293
    AMGetAccountFlagsForWGSpoofing = 4294
    AMGetAccountFlagsForWGSpoofingResponse = 4295
    AMGetFriendsWishlistInfo = 4296
    AMGetFriendsWishlistInfoResponse = 4297
    AMGetClanOfficers = 4298
    AMGetClanOfficersResponse = 4299
    AMNameChange = 4300
    AMGetNameHistory = 4301
    AMGetNameHistoryResponse = 4302
    AMUpdateProviderStatus = 4305
    AMClearPersonaMetadataBlob = 4306
    AMSupportRemoveAccountSecurity = 4307
    AMIsAccountInCaptchaGracePeriod = 4308
    AMIsAccountInCaptchaGracePeriodResponse = 4309
    AMAccountPS3Unlink = 4310
    AMAccountPS3UnlinkResponse = 4311
    AMStoreUserStatsResponse = 4312
    AMGetAccountPSNInfo = 4313
    AMGetAccountPSNInfoResponse = 4314
    AMAuthenticatedPlayerList = 4315
    AMGetUserGifts = 4316
    AMGetUserGiftsResponse = 4317
    AMTransferLockedGifts = 4320
    AMTransferLockedGiftsResponse = 4321
    AMPlayerHostedOnGameServer = 4322
    AMGetAccountBanInfo = 4323
    AMGetAccountBanInfoResponse = 4324
    AMRecordBanEnforcement = 4325
    AMRollbackGiftTransfer = 4326
    AMRollbackGiftTransferResponse = 4327
    AMHandlePendingTransaction = 4328
    AMRequestClanDetails = 4329
    AMDeleteStoredPaypalAgreement = 4330
    AMGameServerUpdate = 4331
    AMGameServerRemove = 4332
    AMGetPaypalAgreements = 4333
    AMGetPaypalAgreementsResponse = 4334
    AMGameServerPlayerCompatibilityCheck = 4335
    AMGameServerPlayerCompatibilityCheckResponse = 4336
    AMRenewLicense = 4337
    AMGetAccountCommunityBanInfo = 4338
    AMGetAccountCommunityBanInfoResponse = 4339
    AMGameServerAccountChangePassword = 4340
    AMGameServerAccountDeleteAccount = 4341
    AMRenewAgreement = 4342
    AMSendEmail = 4343
    AMXsollaPayment = 4344
    AMXsollaPaymentResponse = 4345
    AMAcctAllowedToPurchase = 4346
    AMAcctAllowedToPurchaseResponse = 4347
    AMSwapKioskDeposit = 4348
    AMSwapKioskDepositResponse = 4349
    AMSetUserGiftUnowned = 4350
    AMSetUserGiftUnownedResponse = 4351
    AMClaimUnownedUserGift = 4352
    AMClaimUnownedUserGiftResponse = 4353
    AMSetClanName = 4354
    AMSetClanNameResponse = 4355
    AMGrantCoupon = 4356
    AMGrantCouponResponse = 4357
    AMIsPackageRestrictedInUserCountry = 4358
    AMIsPackageRestrictedInUserCountryResponse = 4359
    AMHandlePendingTransactionResponse = 4360
    AMGrantGuestPasses2 = 4361
    AMGrantGuestPasses2Response = 4362
    AMSessionQuery = 4363
    AMSessionQueryResponse = 4364
    AMGetPlayerBanDetails = 4365
    AMGetPlayerBanDetailsResponse = 4366
    AMFinalizePurchase = 4367
    AMFinalizePurchaseResponse = 4368
    AMPersonaChangeResponse = 4372
    AMGetClanDetailsForForumCreation = 4373
    AMGetClanDetailsForForumCreationResponse = 4374
    AMGetPendingNotificationCount = 4375
    AMGetPendingNotificationCountResponse = 4376
    AMPasswordHashUpgrade = 4377
    AMMoPayPayment = 4378
    AMMoPayPaymentResponse = 4379
    AMBoaCompraPayment = 4380
    AMBoaCompraPaymentResponse = 4381
    AMExpireCaptchaByGID = 4382
    AMCompleteExternalPurchase = 4383
    AMCompleteExternalPurchaseResponse = 4384
    AMResolveNegativeWalletCredits = 4385
    AMResolveNegativeWalletCreditsResponse = 4386
    AMPayelpPayment = 4387
    AMPayelpPaymentResponse = 4388
    AMPlayerGetClanBasicDetails = 4389
    AMPlayerGetClanBasicDetailsResponse = 4390
    
    AMTwoFactorRecoverAuthenticatorRequest = 4402
    AMTwoFactorRecoverAuthenticatorResponse = 4403
    AMValidatePasswordResetCodeAndSendSmsRequest = 4406
    AMValidatePasswordResetCodeAndSendSmsResponse = 4407
    AMGetAccountResetDetailsRequest = 4408
    AMGetAccountResetDetailsResponse = 4409
    
    BasePSRange = 5000
    PSCreateShoppingCart = 5001
    PSCreateShoppingCartResponse = 5002
    PSIsValidShoppingCart = 5003
    PSIsValidShoppingCartResponse = 5004
    PSAddPackageToShoppingCart = 5005
    PSAddPackageToShoppingCartResponse = 5006
    PSRemoveLineItemFromShoppingCart = 5007
    PSRemoveLineItemFromShoppingCartResponse = 5008
    PSGetShoppingCartContents = 5009
    PSGetShoppingCartContentsResponse = 5010
    PSAddWalletCreditToShoppingCart = 5011
    PSAddWalletCreditToShoppingCartResponse = 5012
    
    BaseUFSRange = 5200
    ClientUFSUploadFileRequest = 5202
    ClientUFSUploadFileResponse = 5203
    ClientUFSUploadFileChunk = 5204
    ClientUFSUploadFileFinished = 5205
    ClientUFSGetFileListForApp = 5206
    ClientUFSGetFileListForAppResponse = 5207
    ClientUFSDownloadRequest = 5210
    ClientUFSDownloadResponse = 5211
    ClientUFSDownloadChunk = 5212
    ClientUFSLoginRequest = 5213
    ClientUFSLoginResponse = 5214
    UFSReloadPartitionInfo = 5215
    ClientUFSTransferHeartbeat = 5216
    UFSSynchronizeFile = 5217
    UFSSynchronizeFileResponse = 5218
    ClientUFSDeleteFileRequest = 5219
    ClientUFSDeleteFileResponse = 5220
    UFSDownloadRequest = 5221
    UFSDownloadResponse = 5222
    UFSDownloadChunk = 5223
    ClientUFSGetUGCDetails = 5226
    ClientUFSGetUGCDetailsResponse = 5227
    UFSUpdateFileFlags = 5228
    UFSUpdateFileFlagsResponse = 5229
    ClientUFSGetSingleFileInfo = 5230
    ClientUFSGetSingleFileInfoResponse = 5231
    ClientUFSShareFile = 5232
    ClientUFSShareFileResponse = 5233
    UFSReloadAccount = 5234
    UFSReloadAccountResponse = 5235
    UFSUpdateRecordBatched = 5236
    UFSUpdateRecordBatchedResponse = 5237
    UFSMigrateFile = 5238
    UFSMigrateFileResponse = 5239
    UFSGetUGCURLs = 5240
    UFSGetUGCURLsResponse = 5241
    UFSHttpUploadFileFinishRequest = 5242
    UFSHttpUploadFileFinishResponse = 5243
    UFSDownloadStartRequest = 5244
    UFSDownloadStartResponse = 5245
    UFSDownloadChunkRequest = 5246
    UFSDownloadChunkResponse = 5247
    UFSDownloadFinishRequest = 5248
    UFSDownloadFinishResponse = 5249
    UFSFlushURLCache = 5250
    UFSUploadCommit = 5251
    UFSUploadCommitResponse = 5252
    
    BaseClient2 = 5400
    ClientRequestForgottenPasswordEmail = 5401
    ClientRequestForgottenPasswordEmailResponse = 5402
    ClientCreateAccountResponse = 5403
    ClientResetForgottenPassword = 5404
    ClientResetForgottenPasswordResponse = 5405
    ClientCreateAccount2 = 5406
    ClientInformOfResetForgottenPassword = 5407
    ClientInformOfResetForgottenPasswordResponse = 5408
    ClientAnonUserLogOn_Deprecated = 5409
    ClientGamesPlayedWithDataBlob = 5410
    ClientUpdateUserGameInfo = 5411
    ClientFileToDownload = 5412
    ClientFileToDownloadResponse = 5413
    ClientLBSSetScore = 5414
    ClientLBSSetScoreResponse = 5415
    ClientLBSFindOrCreateLB = 5416
    ClientLBSFindOrCreateLBResponse = 5417
    ClientLBSGetLBEntries = 5418
    ClientLBSGetLBEntriesResponse = 5419
    ClientMarketingMessageUpdate = 5420
    ClientChatDeclined = 5426
    ClientFriendMsgIncoming = 5427
    ClientAuthList_Deprecated = 5428
    ClientTicketAuthComplete = 5429
    ClientIsLimitedAccount = 5430
    ClientRequestAuthList = 5431
    ClientAuthList = 5432
    ClientStat = 5433
    ClientP2PConnectionInfo = 5434
    ClientP2PConnectionFailInfo = 5435
    ClientGetNumberOfCurrentPlayers = 5436
    ClientGetNumberOfCurrentPlayersResponse = 5437
    ClientGetDepotDecryptionKey = 5438
    ClientGetDepotDecryptionKeyResponse = 5439
    GSPerformHardwareSurvey = 5440
    ClientGetAppBetaPasswords = 5441
    ClientGetAppBetaPasswordsResponse = 5442
    ClientEnableTestLicense = 5443
    ClientEnableTestLicenseResponse = 5444
    ClientDisableTestLicense = 5445
    ClientDisableTestLicenseResponse = 5446
    ClientRequestValidationMail = 5448
    ClientRequestValidationMailResponse = 5449
    ClientCheckAppBetaPassword = 5450
    ClientCheckAppBetaPasswordResponse = 5451
    ClientToGC = 5452
    ClientFromGC = 5453
    ClientRequestChangeMail = 5454
    ClientRequestChangeMailResponse = 5455
    ClientEmailAddrInfo = 5456
    ClientPasswordChange3 = 5457
    ClientEmailChange3 = 5458
    ClientPersonalQAChange3 = 5459
    ClientResetForgottenPassword3 = 5460
    ClientRequestForgottenPasswordEmail3 = 5461
    ClientCreateAccount3 = 5462
    ClientNewLoginKey = 5463
    ClientNewLoginKeyAccepted = 5464
    ClientLogOnWithHash_Deprecated = 5465
    ClientStoreUserStats2 = 5466
    ClientStatsUpdated = 5467
    ClientActivateOEMLicense = 5468
    ClientRegisterOEMMachine = 5469
    ClientRegisterOEMMachineResponse = 5470
    ClientRequestedClientStats = 5480
    ClientStat2Int32 = 5481
    ClientStat2 = 5482
    ClientVerifyPassword = 5483
    ClientVerifyPasswordResponse = 5484
    ClientDRMDownloadRequest = 5485
    ClientDRMDownloadResponse = 5486
    ClientDRMFinalResult = 5487
    ClientGetFriendsWhoPlayGame = 5488
    ClientGetFriendsWhoPlayGameResponse = 5489
    ClientOGSBeginSession = 5490
    ClientOGSBeginSessionResponse = 5491
    ClientOGSEndSession = 5492
    ClientOGSEndSessionResponse = 5493
    ClientOGSWriteRow = 5494
    ClientDRMTest = 5495
    ClientDRMTestResult = 5496
    ClientServerUnavailable = 5500
    ClientServersAvailable = 5501
    ClientRegisterAuthTicketWithCM = 5502
    ClientGCMsgFailed = 5503
    ClientMicroTxnAuthRequest = 5504
    ClientMicroTxnAuthorize = 5505
    ClientMicroTxnAuthorizeResponse = 5506
    ClientAppMinutesPlayedData = 5507
    ClientGetMicroTxnInfo = 5508
    ClientGetMicroTxnInfoResponse = 5509
    ClientMarketingMessageUpdate2 = 5510
    ClientDeregisterWithServer = 5511
    ClientSubscribeToPersonaFeed = 5512
    ClientLogon = 5514
    ClientGetClientDetails = 5515
    ClientGetClientDetailsResponse = 5516
    ClientReportOverlayDetourFailure = 5517
    ClientGetClientAppList = 5518
    ClientGetClientAppListResponse = 5519
    ClientInstallClientApp = 5520
    ClientInstallClientAppResponse = 5521
    ClientUninstallClientApp = 5522
    ClientUninstallClientAppResponse = 5523
    ClientSetClientAppUpdateState = 5524
    ClientSetClientAppUpdateStateResponse = 5525
    ClientRequestEncryptedAppTicket = 5526
    ClientRequestEncryptedAppTicketResponse = 5527
    ClientWalletInfoUpdate = 5528
    ClientLBSSetUGC = 5529
    ClientLBSSetUGCResponse = 5530
    ClientAMGetClanOfficers = 5531
    ClientAMGetClanOfficersResponse = 5532
    ClientCheckFileSignature = 5533
    ClientCheckFileSignatureResponse = 5534
    ClientFriendProfileInfo = 5535
    ClientFriendProfileInfoResponse = 5536
    ClientUpdateMachineAuth = 5537
    ClientUpdateMachineAuthResponse = 5538
    ClientReadMachineAuth = 5539
    ClientReadMachineAuthResponse = 5540
    ClientRequestMachineAuth = 5541
    ClientRequestMachineAuthResponse = 5542
    ClientScreenshotsChanged = 5543
    ClientEmailChange4 = 5544
    ClientEmailChangeResponse4 = 5545
    ClientGetCDNAuthToken = 5546
    ClientGetCDNAuthTokenResponse = 5547
    ClientDownloadRateStatistics = 5548
    ClientRequestAccountData = 5549
    ClientRequestAccountDataResponse = 5550
    ClientResetForgottenPassword4 = 5551
    ClientHideFriend = 5552
    ClientFriendsGroupsList = 5553
    ClientGetClanActivityCounts = 5554
    ClientGetClanActivityCountsResponse = 5555
    ClientOGSReportString = 5556
    ClientOGSReportBug = 5557
    ClientSentLogs = 5558
    ClientLogonGameServer = 5559
    AMClientCreateFriendsGroup = 5560
    AMClientCreateFriendsGroupResponse = 5561
    AMClientDeleteFriendsGroup = 5562
    AMClientDeleteFriendsGroupResponse = 5563
    AMClientRenameFriendsGroup = 5564
    AMClientRenameFriendsGroupResponse = 5565
    AMClientAddFriendToGroup = 5566
    AMClientAddFriendToGroupResponse = 5567
    AMClientRemoveFriendFromGroup = 5568
    AMClientRemoveFriendFromGroupResponse = 5569
    ClientAMGetPersonaNameHistory = 5570
    ClientAMGetPersonaNameHistoryResponse = 5571
    ClientRequestFreeLicense = 5572
    ClientRequestFreeLicenseResponse = 5573
    ClientDRMDownloadRequestWithCrashData = 5574
    ClientAuthListAck = 5575
    ClientItemAnnouncements = 5576
    ClientRequestItemAnnouncements = 5577
    ClientFriendMsgEchoToSender = 5578
    ClientChangeSteamGuardOptions = 5579
    ClientChangeSteamGuardOptionsResponse = 5580
    ClientOGSGameServerPingSample = 5581
    ClientCommentNotifications = 5582
    ClientRequestCommentNotifications = 5583
    ClientPersonaChangeResponse = 5584
    ClientRequestWebAPIAuthenticateUserNonce = 5585
    ClientRequestWebAPIAuthenticateUserNonceResponse = 5586
    ClientPlayerNicknameList = 5587
    AMClientSetPlayerNickname = 5588
    AMClientSetPlayerNicknameResponse = 5589
    ClientRequestOAuthTokenForApp = 5590
    ClientRequestOAuthTokenForAppResponse = 5591
    ClientCreateAccountProto = 5590
    ClientCreateAccountProtoResponse = 5591
    ClientGetNumberOfCurrentPlayersDP = 5592
    ClientGetNumberOfCurrentPlayersDPResponse = 5593
    ClientServiceMethod = 5594
    ClientServiceMethodResponse = 5595
    ClientFriendUserStatusPublished = 5596
    ClientCurrentUIMode = 5597
    ClientVanityURLChangedNotification = 5598
    ClientUserNotifications = 5599
    
    BaseDFS = 5600
    DFSGetFile = 5601
    DFSInstallLocalFile = 5602
    DFSConnection = 5603
    DFSConnectionReply = 5604
    ClientDFSAuthenticateRequest = 5605
    ClientDFSAuthenticateResponse = 5606
    ClientDFSEndSession = 5607
    DFSPurgeFile = 5608
    DFSRouteFile = 5609
    DFSGetFileFromServer = 5610
    DFSAcceptedResponse = 5611
    DFSRequestPingback = 5612
    DFSRecvTransmitFile = 5613
    DFSSendTransmitFile = 5614
    DFSRequestPingback2 = 5615
    DFSResponsePingback2 = 5616
    ClientDFSDownloadStatus = 5617
    DFSStartTransfer = 5618
    DFSTransferComplete = 5619
    
    BaseMDS = 5800
    ClientMDSLoginRequest = 5801
    ClientMDSLoginResponse = 5802
    ClientMDSUploadManifestRequest = 5803
    ClientMDSUploadManifestResponse = 5804
    ClientMDSTransmitManifestDataChunk = 5805
    ClientMDSHeartbeat = 5806
    ClientMDSUploadDepotChunks = 5807
    ClientMDSUploadDepotChunksResponse = 5808
    ClientMDSInitDepotBuildRequest = 5809
    ClientMDSInitDepotBuildResponse = 5810
    AMToMDSGetDepotDecryptionKey = 5812
    MDSToAMGetDepotDecryptionKeyResponse = 5813
    MDSGetVersionsForDepot = 5814
    MDSGetVersionsForDepotResponse = 5815
    MDSSetPublicVersionForDepot = 5816
    MDSSetPublicVersionForDepotResponse = 5817
    ClientMDSInitWorkshopBuildRequest = 5816
    ClientMDSInitWorkshopBuildResponse = 5817
    ClientMDSGetDepotManifest = 5818
    ClientMDSGetDepotManifestResponse = 5819
    ClientMDSGetDepotManifestChunk = 5820
    ClientMDSUploadRateTest = 5823
    ClientMDSUploadRateTestResponse = 5824
    MDSDownloadDepotChunksAck = 5825
    MDSContentServerStatsBroadcast = 5826
    MDSContentServerConfigRequest = 5827
    MDSContentServerConfig = 5828
    MDSGetDepotManifest = 5829
    MDSGetDepotManifestResponse = 5830
    MDSGetDepotManifestChunk = 5831
    MDSGetDepotChunk = 5832
    MDSGetDepotChunkResponse = 5833
    MDSGetDepotChunkChunk = 5834
    MDSUpdateContentServerConfig = 5835
    MDSGetServerListForUser = 5836
    MDSGetServerListForUserResponse = 5837
    ClientMDSRegisterAppBuild = 5838
    ClientMDSRegisterAppBuildResponse = 5839
    ClientMDSSetAppBuildLive = 5840
    ClientMDSSetAppBuildLiveResponse = 5841
    ClientMDSGetPrevDepotBuild = 5842
    ClientMDSGetPrevDepotBuildResponse = 5843
    MDSToCSFlushChunk = 5844
    ClientMDSSignInstallScript = 5845
    ClientMDSSignInstallScriptResponse = 5846
    
    CSBase = 6200
    CSPing = 6201
    CSPingResponse = 6202
    
    GMSBase = 6400
    GMSGameServerReplicate = 6401
    ClientGMSServerQuery = 6403
    GMSClientServerQueryResponse = 6404
    AMGMSGameServerUpdate = 6405
    AMGMSGameServerRemove = 6406
    GameServerOutOfDate = 6407
    
    ClientAuthorizeLocalDeviceRequest = 6501
    ClientAuthorizeLocalDevice = 6502
    ClientDeauthorizeDeviceRequest = 6503
    ClientDeauthorizeDevice = 6504
    ClientUseLocalDeviceAuthorizations = 6505
    ClientGetAuthorizedDevices = 6506
    ClientGetAuthorizedDevicesResponse = 6507
    
    MMSBase = 6600
    ClientMMSCreateLobby = 6601
    ClientMMSCreateLobbyResponse = 6602
    ClientMMSJoinLobby = 6603
    ClientMMSJoinLobbyResponse = 6604
    ClientMMSLeaveLobby = 6605
    ClientMMSLeaveLobbyResponse = 6606
    ClientMMSGetLobbyList = 6607
    ClientMMSGetLobbyListResponse = 6608
    ClientMMSSetLobbyData = 6609
    ClientMMSSetLobbyDataResponse = 6610
    ClientMMSGetLobbyData = 6611
    ClientMMSLobbyData = 6612
    ClientMMSSendLobbyChatMsg = 6613
    ClientMMSLobbyChatMsg = 6614
    ClientMMSSetLobbyOwner = 6615
    ClientMMSSetLobbyOwnerResponse = 6616
    ClientMMSSetLobbyGameServer = 6617
    ClientMMSLobbyGameServerSet = 6618
    ClientMMSUserJoinedLobby = 6619
    ClientMMSUserLeftLobby = 6620
    ClientMMSInviteToLobby = 6621
    ClientMMSFlushFrenemyListCache = 6622
    ClientMMSFlushFrenemyListCacheResponse = 6623
    ClientMMSSetLobbyLinked = 6624
    
    NonStdMsgBase = 6800
    NonStdMsgMemcached = 6801
    NonStdMsgHTTPServer = 6802
    NonStdMsgHTTPClient = 6803
    NonStdMsgWGResponse = 6804
    NonStdMsgPHPSimulator = 6805
    NonStdMsgChase = 6806
    NonStdMsgDFSTransfer = 6807
    NonStdMsgTests = 6808
    NonStdMsgUMQpipeAAPL = 6809
    NonStdMsgSyslog = 6810
    NonStdMsgLogsink = 6811
    
    UDSBase = 7000
    ClientUDSP2PSessionStarted = 7001
    ClientUDSP2PSessionEnded = 7002
    UDSRenderUserAuth = 7003
    UDSRenderUserAuthResponse = 7004
    ClientUDSInviteToGame = 7005
    UDSFindSession = 7006
    UDSFindSessionResponse = 7007

    MPASBase = 7100
    MPASVacBanReset = 7101
    
    KGSBase = 7200
    KGSAllocateKeyRange = 7201
    KGSAllocateKeyRangeResponse = 7202
    KGSGenerateKeys = 7203
    KGSGenerateKeysResponse = 7204
    KGSRemapKeys = 7205
    KGSRemapKeysResponse = 7206
    KGSGenerateGameStopWCKeys = 7207
    KGSGenerateGameStopWCKeysResponse = 7208
    
    UCMBase = 7300
    ClientUCMAddScreenshot = 7301
    ClientUCMAddScreenshotResponse = 7302
    UCMValidateObjectExists = 7303
    UCMValidateObjectExistsResponse = 7304
    UCMResetCommunityContent = 7307
    UCMResetCommunityContentResponse = 7308
    ClientUCMDeleteScreenshot = 7309
    ClientUCMDeleteScreenshotResponse = 7310
    ClientUCMPublishFile = 7311
    ClientUCMPublishFileResponse = 7312
    ClientUCMGetPublishedFileDetails = 7313
    ClientUCMGetPublishedFileDetailsResponse = 7314
    ClientUCMDeletePublishedFile = 7315
    ClientUCMDeletePublishedFileResponse = 7316
    ClientUCMEnumerateUserPublishedFiles = 7317
    ClientUCMEnumerateUserPublishedFilesResponse = 7318
    ClientUCMSubscribePublishedFile = 7319
    ClientUCMSubscribePublishedFileResponse = 7320
    ClientUCMEnumerateUserSubscribedFiles = 7321
    ClientUCMEnumerateUserSubscribedFilesResponse = 7322
    ClientUCMUnsubscribePublishedFile = 7323
    ClientUCMUnsubscribePublishedFileResponse = 7324
    ClientUCMUpdatePublishedFile = 7325
    ClientUCMUpdatePublishedFileResponse = 7326
    UCMUpdatePublishedFile = 7327
    UCMUpdatePublishedFileResponse = 7328
    UCMDeletePublishedFile = 7329
    UCMDeletePublishedFileResponse = 7330
    UCMUpdatePublishedFileStat = 7331
    UCMUpdatePublishedFileBan = 7332
    UCMUpdatePublishedFileBanResponse = 7333
    UCMUpdateTaggedScreenshot = 7334
    UCMAddTaggedScreenshot = 7335
    UCMRemoveTaggedScreenshot = 7336
    UCMReloadPublishedFile = 7337
    UCMReloadUserFileListCaches = 7338
    UCMPublishedFileReported = 7339
    UCMUpdatePublishedFileIncompatibleStatus = 7340
    UCMPublishedFilePreviewAdd = 7341
    UCMPublishedFilePreviewAddResponse = 7342
    UCMPublishedFilePreviewRemove = 7343
    UCMPublishedFilePreviewRemoveResponse = 7344
    UCMPublishedFilePreviewChangeSortOrder = 7345
    UCMPublishedFilePreviewChangeSortOrderResponse = 7346
    ClientUCMPublishedFileSubscribed = 7347
    ClientUCMPublishedFileUnsubscribed = 7348
    UCMPublishedFileSubscribed = 7349
    UCMPublishedFileUnsubscribed = 7350
    UCMPublishFile = 7351
    UCMPublishFileResponse = 7352
    UCMPublishedFileChildAdd = 7353
    UCMPublishedFileChildAddResponse = 7354
    UCMPublishedFileChildRemove = 7355
    UCMPublishedFileChildRemoveResponse = 7356
    UCMPublishedFileChildChangeSortOrder = 7357
    UCMPublishedFileChildChangeSortOrderResponse = 7358
    UCMPublishedFileParentChanged = 7359
    ClientUCMGetPublishedFilesForUser = 7360
    ClientUCMGetPublishedFilesForUserResponse = 7361
    UCMGetPublishedFilesForUser = 7362
    UCMGetPublishedFilesForUserResponse = 7363
    ClientUCMSetUserPublishedFileAction = 7364
    ClientUCMSetUserPublishedFileActionResponse = 7365
    ClientUCMEnumeratePublishedFilesByUserAction = 7366
    ClientUCMEnumeratePublishedFilesByUserActionResponse = 7367
    ClientUCMPublishedFileDeleted = 7368
    UCMGetUserSubscribedFiles = 7369
    UCMGetUserSubscribedFilesResponse = 7370
    UCMFixStatsPublishedFile = 7371
    UCMDeleteOldScreenshot = 7372
    UCMDeleteOldScreenshotResponse = 7373
    UCMDeleteOldVideo = 7374
    UCMDeleteOldVideoResponse = 7375
    UCMUpdateOldScreenshotPrivacy = 7376
    UCMUpdateOldScreenshotPrivacyResponse = 7377
    ClientUCMEnumerateUserSubscribedFilesWithUpdates = 7378
    ClientUCMEnumerateUserSubscribedFilesWithUpdatesResponse = 7379
    UCMPublishedFileContentUpdated = 7380
    UCMPublishedFileUpdated = 7381
    ClientWorkshopItemChangesRequest = 7382
    ClientWorkshopItemChangesResponse = 7383
    ClientWorkshopItemInfoRequest = 7384
    ClientWorkshopItemInfoResponse = 7385
    
    FSBase = 7500
    ClientRichPresenceUpload = 7501
    ClientRichPresenceRequest = 7502
    ClientRichPresenceInfo = 7503
    FSRichPresenceRequest = 7504
    FSRichPresenceResponse = 7505
    FSComputeFrenematrix = 7506
    FSComputeFrenematrixResponse = 7507
    FSPlayStatusNotification = 7508
    FSPublishPersonaStatus = 7509
    FSAddOrRemoveFollower = 7510
    FSAddOrRemoveFollowerResponse = 7511
    FSUpdateFollowingList = 7512
    FSCommentNotification = 7513
    FSCommentNotificationViewed = 7514
    ClientFSGetFollowerCount = 7515
    ClientFSGetFollowerCountResponse = 7516
    ClientFSGetIsFollowing = 7517
    ClientFSGetIsFollowingResponse = 7518
    ClientFSEnumerateFollowingList = 7519
    ClientFSEnumerateFollowingListResponse = 7520
    FSGetPendingNotificationCount = 7521
    FSGetPendingNotificationCountResponse = 7522
    ClientFSOfflineMessageNotification = 7523
    ClientFSRequestOfflineMessageCount = 7524
    ClientFSGetFriendMessageHistory = 7525
    ClientFSGetFriendMessageHistoryResponse = 7526
    ClientFSGetFriendMessageHistoryForOfflineMessages = 7527
    ClientFSGetFriendsSteamLevels = 7528
    ClientFSGetFriendsSteamLevelsResponse = 7529
    
    DRMRange2 = 7600
    CEGVersionSetEnableDisableRequest = 7600
    CEGVersionSetEnableDisableResponse = 7601
    CEGPropStatusDRMSRequest = 7602
    CEGPropStatusDRMSResponse = 7603
    CEGWhackFailureReportRequest = 7604
    CEGWhackFailureReportResponse = 7605
    DRMSFetchVersionSet = 7606
    DRMSFetchVersionSetResponse = 7607
    
    EconBase = 7700
    EconTrading_InitiateTradeRequest = 7701
    EconTrading_InitiateTradeProposed = 7702
    EconTrading_InitiateTradeResponse = 7703
    EconTrading_InitiateTradeResult = 7704
    EconTrading_StartSession = 7705
    EconTrading_CancelTradeRequest = 7706
    EconFlushInventoryCache = 7707
    EconFlushInventoryCacheResponse = 7708
    EconCDKeyProcessTransaction = 7711
    EconCDKeyProcessTransactionResponse = 7712
    EconGetErrorLogs = 7713
    EconGetErrorLogsResponse = 7714
    
    RMRange = 7800
    RMTestVerisignOTP = 7800
    RMTestVerisignOTPResponse = 7801
    RMDeleteMemcachedKeys = 7803
    RMRemoteInvoke = 7804
    BadLoginIPList = 7805
    
    UGSBase = 7900
    UGSUpdateGlobalStats = 7900
    ClientUGSGetGlobalStats = 7901
    ClientUGSGetGlobalStatsResponse = 7902

    StoreBase = 8000
    StoreUpdateRecommendationCount = 8000

    UMQBase = 8100
    UMQLogonRequest = 8100
    UMQLogonResponse = 8101
    UMQLogoffRequest = 8102
    UMQLogoffResponse = 8103
    UMQSendChatMessage = 8104
    UMQIncomingChatMessage = 8105
    UMQPoll = 8106
    UMQPollResults = 8107
    UMQ2AM_ClientMsgBatch = 8108
    UMQEnqueueMobileSalePromotions = 8109
    UMQEnqueueMobileAnnouncements = 8110

    WorkshopBase = 8200
    WorkshopAcceptTOSRequest = 8200
    WorkshopAcceptTOSResponse = 8201

    WebAPIBase = 8300
    WebAPIValidateOAuth2Token = 8300
    WebAPIValidateOAuth2TokenResponse = 8301
    WebAPIInvalidateTokensForAccount = 8302
    WebAPIRegisterGCInterfaces = 8303
    WebAPIInvalidateOAuthClientCache = 8304
    WebAPIInvalidateOAuthTokenCache = 8305

    BackpackBase = 8400
    BackpackAddToCurrency = 8401
    BackpackAddToCurrencyResponse = 8402

    CREBase = 8500
    CRERankByTrend = 8501
    CRERankByTrendResponse = 8502
    CREItemVoteSummary = 8503
    CREItemVoteSummaryResponse = 8504
    CRERankByVote = 8505
    CRERankByVoteResponse = 8506
    CREUpdateUserPublishedItemVote = 8507
    CREUpdateUserPublishedItemVoteResponse = 8508
    CREGetUserPublishedItemVoteDetails = 8509
    CREGetUserPublishedItemVoteDetailsResponse = 8510
    CREEnumeratePublishedFiles = 8511
    CREEnumeratePublishedFilesResponse = 8512
    CREPublishedFileVoteAdded = 8513

    SecretsBase = 8600
    SecretsRequestCredentialPair = 8600
    SecretsCredentialPairResponse = 8601
    SecretsRequestServerIdentity = 8602
    SecretsServerIdentityResponse = 8603
    SecretsUpdateServerIdentities = 8604

    BoxMonitorBase = 8700
    BoxMonitorReportRequest = 8700
    BoxMonitorReportResponse = 8701

    LogsinkBase = 8800
    LogsinkWriteReport = 8800
    
    PICSBase = 8900
    ClientPICSChangesSinceRequest = 8901
    ClientPICSChangesSinceResponse = 8902
    ClientPICSProductInfoRequest = 8903
    ClientPICSProductInfoResponse = 8904
    ClientPICSAccessTokenRequest = 8905
    ClientPICSAccessTokenResponse = 8906

    WorkerProcess = 9000
    WorkerProcessPingRequest = 9000
    WorkerProcessPingResponse = 9001
    WorkerProcessShutdown = 9002

    DRMWorkerProcess = 9100
    DRMWorkerProcessDRMAndSign = 9100
    DRMWorkerProcessDRMAndSignResponse = 9101
    DRMWorkerProcessSteamworksInfoRequest = 9102
    DRMWorkerProcessSteamworksInfoResponse = 9103
    DRMWorkerProcessInstallDRMDLLRequest = 9104
    DRMWorkerProcessInstallDRMDLLResponse = 9105
    DRMWorkerProcessSecretIdStringRequest = 9106
    DRMWorkerProcessSecretIdStringResponse = 9107
    DRMWorkerProcessGetDRMGuidsFromFileRequest = 9108
    DRMWorkerProcessGetDRMGuidsFromFileResponse = 9109
    DRMWorkerProcessInstallProcessedFilesRequest = 9110
    DRMWorkerProcessInstallProcessedFilesResponse = 9111
    DRMWorkerProcessExamineBlobRequest = 9112
    DRMWorkerProcessExamineBlobResponse = 9113
    DRMWorkerProcessDescribeSecretRequest = 9114
    DRMWorkerProcessDescribeSecretResponse = 9115
    DRMWorkerProcessBackfillOriginalRequest = 9116
    DRMWorkerProcessBackfillOriginalResponse = 9117
    DRMWorkerProcessValidateDRMDLLRequest = 9118
    DRMWorkerProcessValidateDRMDLLResponse = 9119
    DRMWorkerProcessValidateFileRequest = 9120
    DRMWorkerProcessValidateFileResponse = 9121
    DRMWorkerProcessSplitAndInstallRequest = 9122
    DRMWorkerProcessSplitAndInstallResponse = 9123
    DRMWorkerProcessGetBlobRequest = 9124
    DRMWorkerProcessGetBlobResponse = 9125
    DRMWorkerProcessEvaluateCrashRequest = 9126
    DRMWorkerProcessEvaluateCrashResponse = 9127
    DRMWorkerProcessAnalyzeFileRequest = 9128
    DRMWorkerProcessAnalyzeFileResponse = 9129
    DRMWorkerProcessUnpackBlobRequest = 9130
    DRMWorkerProcessUnpackBlobResponse = 9131
    DRMWorkerProcessInstallAllRequest = 9132
    DRMWorkerProcessInstallAllResponse = 9133

    TestWorkerProcess = 9200
    TestWorkerProcessLoadUnloadModuleRequest = 9200
    TestWorkerProcessLoadUnloadModuleResponse = 9201
    TestWorkerProcessServiceModuleCallRequest = 9202
    TestWorkerProcessServiceModuleCallResponse = 9203
    
    ClientGetEmoticonList = 9330
    ClientEmoticonList = 9331
    
    ClientSharedLibraryBase = 9400
    ClientSharedLicensesLockStatus = 9403
    ClientSharedLicensesStopPlaying = 9404
    ClientSharedLibraryLockStatus = 9405
    ClientSharedLibraryStopPlaying = 9406
    
    ClientUnlockStreaming = 9507
    ClientUnlockStreamingResponse = 9508
    
    ClientPlayingSessionState = 9600
    ClientKickPlayingSession = 9601
    
    ClientBroadcastInit = 9700
    ClientBroadcastFrames = 9701
    ClientBroadcastDisconnect = 9702
    ClientBroadcastScreenshot = 9703
    ClientBroadcastUploadConfig = 9704
    
    ClientVoiceCallPreAuthorize = 9800
    ClientVoiceCallPreAuthorizeResponse = 9801


class EUniverse:
    Invalid = 0
    
    Public = 1
    Beta = 2
    Internal = 3
    Dev = 4

    Max = 5

class EChatEntryType:

    Invalid = 0
    
    ChatMsg = 1
    Typing = 2
    InviteGame = 3
    Emote = 4
    LobbyGameStart = 5
    LeftConversation = 6
    Entered = 7
    WasKicked = 8
    WasBanned = 9
    Disconnected = 10
    HistoricalChat = 11
    Reserved1 = 12
    Reserved2 = 13
    LinkBlocked = 14


class EPersonaState:

    Offline = 0

    Online = 1
    Busy = 2
    Away = 3
    Snooze = 4
    LookingToTrade = 5
    LookingToPlay = 6

    Max = 7


class EAccountType:

    Invalid = 0

    Individual = 1
    Multiseat = 2
    GameServer = 3
    AnonGameServer = 4
    Pending = 5
    ContentServer = 6
    Clan = 7
    Chat = 8
    ConsoleUser = 9
    AnonUser = 10

    Max = 11


class EFriendRelationship:

    None_ = 0
    
    Blocked = 1
    RequestRecipient = 2
    Friend = 3
    RequestInitiator = 4
    Ignored = 5
    IgnoredFriend = 6
    SuggestedFriend = 7

    Max = 8


class EAccountFlags:

    NormalUser = 0
    
    PersonaNameSet = 1
    Unbannable = 2
    PasswordSet = 4
    Support = 8
    Admin = 16
    Supervisor = 32
    AppEditor = 64
    HWIDSet = 128
    PersonalQASet = 256
    VacBeta = 512
    Debug = 1024
    Disabled = 2048
    LimitedUser = 4096
    LimitedUserForce = 8192
    EmailValidated = 16384
    MarketingTreatment = 32768
    OGGInviteOptOut = 65536
    ForcePasswordChange = 131072
    ForceEmailVerification = 262144
    LogonExtraSecurity = 524288
    LogonExtraSecurityDisabled = 1048576
    Steam2MigrationComplete = 2097152
    NeedLogs = 4194304
    Lockdown = 8388608
    MasterAppEditor = 16777216
    BannedFromWebAPI = 33554432
    ClansOnlyFromFriends = 67108864
    GlobalModerator = 134217728


class EClanPermission:

    Nobody = 0
    
    Owner = 1
    Officer = 2
    OwnerAndOfficer = 3
    Member = 4
    Moderator = 8

    OwnerOfficerModerator = Owner | Officer | Moderator
    AllMembers = Owner | Officer | Moderator | Member 

    OGGGameOwner = 16

    NonMember = 128

    MemberAllowed        = NonMember | Member
    ModeratorAllowed    = NonMember | Member | Moderator
    OfficerAllowed        = NonMember | Member | Moderator | Officer
    OwnerAllowed        = NonMember | Member | Moderator | Officer | Owner
    Anybody                = NonMember | Member | Moderator | Officer | Owner


class EChatPermission:

    Close = 1
    Invite = 2
    Talk = 8
    Kick = 16
    Mute = 32
    SetMetadata = 64
    ChangePermissions = 128
    Ban = 256
    ChangeAccess = 512

    EveryoneNotInClanDefault = Talk
    EveryoneDefault = Talk | Invite

    # todo: this doesn't seem correct...
    MemberDefault = Ban | Kick | Talk | Invite

    OfficerDefault = Ban | Kick | Talk | Invite
    OwnerDefault = ChangeAccess | Ban | SetMetadata | Mute | Kick | Talk | Invite | Close

    Mask = 1019


class EFriendFlags:

    None_ = 0
    Blocked = 1
    FriendshipRequested = 2
    Immediate = 4
    ClanMember = 8
    OnGameServer = 16
    RequestingFriendship = 128
    RequestingInfo = 256
    Ignored = 512
    IgnoredFriend = 1024
    Suggested = 2048

    FlagAll = 65535


class EPersonaStateFlag:

    HasRichPresence = 1
    InJoinableGame = 2
    
    OnlineUsingWeb = 256
    OnlineUsingMobile = 512
    OnlineUsingBigPicture = 1024


class EClientPersonaStateFlag:

    Status = 1
    PlayerName = 2
    QueryPort = 4
    SourceID = 8
    Presence = 16
    Metadata = 32
    LastSeen = 64
    ClanInfo = 128
    GameExtraInfo = 256
    GameDataBlob = 512
    ClanTag = 1024
    Facebook = 2048


class EAppUsageEvent:

    GameLaunch = 1
    GameLaunchTrial = 2
    Media = 3
    PreloadStart = 4
    PreloadFinish = 5
    MarketingMessageView = 6
    InGameAdViewed = 7
    GameLaunchFreeWeekend = 8


class ELicenseFlags:

    None_ = 0
    Renew = 0x01
    RenewalFailed = 0x02
    Pending = 0x04
    Expired = 0x08
    CancelledByUser = 0x10
    CancelledByAdmin = 0x20
    LowViolenceContent = 0x40
    ImportedFromSteam2 = 0x80


class ELicenseType:

    NoLicense = 0
    SinglePurchase = 1
    SinglePurchaseLimitedUse = 2
    RecurringCharge = 3
    RecurringChargeLimitedUse = 4
    RecurringChargeLimitedUseWithOverages = 5
    RecurringOption = 6


class EPaymentMethod:

    None_ = 0
    ActivationCode = 1
    CreditCard = 2
    Giropay = 3
    PayPal = 4
    Ideal = 5
    PaySafeCard = 6
    Sofort = 7
    GuestPass = 8
    WebMoney = 9
    MoneyBookers = 10
    AliPay = 11
    Yandex = 12
    Kiosk = 13
    Qiwi = 14
    GameStop = 15
    HardwarePromo = 16
    MoPay = 17
    BoletoBancario = 18
    BoaCompraGold = 19
    BancoDoBrasilOnline = 20
    ItauOnline = 21
    BradescoOnline = 22
    Pagseguro = 23
    VisaBrazil = 24
    AmexBrazil = 25
    Aura = 26
    Hipercard = 27
    MastercardBrazil = 28
    DinersCardBrazil = 29
    AuthorizedDevice = 30
    MOLPoints = 31
    ClickAndBuy = 32
    Beeline = 33
    Konbini = 34
    EClubPoints = 35
    CreditCardJapan = 36
    BankTransferJapan = 37
    PayEasyJapan = 38
    Zong = 39
    CultureVoucher = 40
    BookVoucher = 41
    HappymoneyVoucher = 42
    ConvenientStoreVoucher = 43
    GameVoucher = 44
    Multibanco = 45
    Payshop = 46
    Maestro = 47
    OXXO = 48
    ToditoCash = 49
    Carnet = 50
    SPEI = 51
    ThreePay = 52
    IsBank = 53
    Garanti = 54
    Akbank = 55
    YapiKredi = 56
    Halkbank = 57
    BankAsya = 58
    Finansbank = 59
    DenizBank = 60
    PTT = 61
    CashU = 62
    OneCard = 63
    AutoGrant = 64
    WebMoneyJapan = 65
    Smart2PayTest = 66
    Wallet = 128
    Valve = 129
    SteamPressMaster = 130
    StorePromotion = 131
    OEMTicket = 256
    Split = 512
    Complimentary = 1024


class EIntroducerRouting:

    FileShare = 0
    P2PVoiceChat = 1
    P2PNetworking = 2


class EServerFlags:

    None_ = 0
    Active = 1
    Secure = 2
    Dedicated = 4
    Linux = 8
    Passworded = 16
    Private = 32


class EDenyReason:

    InvalidVersion = 1
    Generic = 2
    NotLoggedOn = 3
    NoLicense = 4
    Cheater = 5
    LoggedInElseWhere = 6
    UnknownText = 7
    IncompatibleAnticheat = 8
    MemoryCorruption = 9
    IncompatibleSoftware = 10
    SteamConnectionLost = 11
    SteamConnectionError = 12
    SteamResponseTimedOut = 13
    SteamValidationStalled = 14
    SteamOwnerLeftGuestUser = 15


class EClanRank:

    None_ = 0
    Owner = 1
    Officer = 2
    Member = 3
    Moderator = 4


class EClanRelationship:

    None_ = 0
    Blocked = 1
    Invited = 2
    Member = 3
    Kicked = 4
    KickAcknowledged = 5


class EAuthSessionResponse:

    OK = 0
    UserNotConnectedToSteam = 1
    NoLicenseOrExpired = 2
    VACBanned = 3
    LoggedInElseWhere = 4
    VACCheckTimedOut = 5
    AuthTicketCanceled = 6
    AuthTicketInvalidAlreadyUsed = 7
    AuthTicketInvalid = 8
    PublisherIssuedBan = 9


class EChatRoomEnterResponse:

    Success = 1
    DoesntExist = 2
    NotAllowed = 3
    Full = 4
    Error = 5
    Banned = 6
    Limited = 7
    ClanDisabled = 8
    CommunityBan = 9
    MemberBlockedYou = 10
    YouBlockedMember = 11

    # these appear to have been removed
    NoRankingDataLobby = 12
    NoRankingDataUser = 13
    RankOutOfRange = 14


class EChatRoomType:

    Friend = 1
    MUC = 2
    Lobby = 3


class EChatInfoType:

    StateChange = 1
    InfoUpdate = 2
    MemberLimitChange = 3


class EChatAction:

    InviteChat = 1
    Kick = 2
    Ban = 3
    UnBan = 4
    StartVoiceSpeak = 5
    EndVoiceSpeak = 6
    LockChat = 7
    UnlockChat = 8
    CloseChat = 9
    SetJoinable = 10
    SetUnjoinable = 11
    SetOwner = 12
    SetInvisibleToFriends = 13
    SetVisibleToFriends = 14
    SetModerated = 15
    SetUnmoderated = 16


class EChatActionResult:

    Success = 1
    Error = 2
    NotPermitted = 3
    NotAllowedOnClanMember = 4
    NotAllowedOnBannedUser = 5
    NotAllowedOnChatOwner = 6
    NotAllowedOnSelf = 7
    ChatDoesntExist = 8
    ChatFull = 9
    VoiceSlotsFull = 10


class EAppInfoSection:

    Unknown = 0
    All = 1

    First = 2
    Common = 2
    Extended = 3
    Config = 4
    Stats = 5
    Install = 6
    Depots = 7
    VAC = 8
    DRM = 9
    UFS = 10
    OGG = 11
    Items = 12
    ItemsUNUSED = 12
    Policies = 13
    SysReqs = 14
    Community = 15
    Store = 16

    Max = 17


class EContentDownloadSourceType:

    Invalid = 0

    CS = 1
    CDN = 2
    LCS = 3
    ProxyCache = 4

    Max = 5


class EPlatformType:

    Unknown = 0

    Win32 = 1
    Win64 = 2
    Linux = 3
    OSX = 4
    PS3 = 5

    Max = 6


class EOSType:

    Unknown = -1

    UMQ = -400

    PS3 = -300

    MacOSUnknown = -102
    MacOS104 = -101
    MacOS105 = -100
    MacOS1058 = -99
    MacOS106 = -95
    MacOS1063 = -94
    MacOS1064_slgu = -93
    MacOS1067 = -92
    MacOS107 = -90
    MacOS108 = -89
    MacOS109 = -88
    MacOS1010 = -87

    LinuxUnknown = -203
    Linux22 = -202
    Linux24 = -201
    Linux26 = -200
    Linux32 = -199
    Linux35 = -198
    Linux36 = -197
    Linux310 = -196

    WinUnknown = 0
    Win311 = 1
    Win95 = 2
    Win98 = 3
    WinME = 4
    WinNT = 5
    Win200 = 6
    WinXP = 7
    Win2003 = 8
    WinVista = 9
    Win7 = 10
    Windows7 = 10
    Win2008 = 11
    Win2012 = 12
    Win8 = 13
    Windows8 = 13
    Win81 = 14
    Windows81 = 14
    Win2012R2 = 15
    Win10 = 16

    WinMAX = 15

    Max = 26


class EServerType:

    Invalid = -1
    First = 0

    Shell = 0
    GM = 1
    BUM = 2
    AM = 3
    BS = 4
    VS = 5
    ATS = 6
    CM = 7
    FBS = 8
    FG = 9
    BoxMonitor = 9
    SS = 10
    DRMS = 11
    HubOBSOLETE = 12
    Console = 13
    ASBOBSOLETE = 14
    PICS = 14
    Client = 15
    BootstrapOBSOLETE = 16
    DP = 17
    WG = 18
    SM = 19
    UFS = 21
    Util = 23
    DSS = 24
    Community = 24
    P2PRelayOBSOLETE = 25
    AppInformation = 26
    Spare = 27
    FTS = 28
    EPM = 29
    PS = 30
    IS = 31
    CCS = 32
    DFS = 33
    LBS = 34
    MDS = 35
    CS = 36
    GC = 37
    NS = 38
    OGS = 39
    WebAPI = 40
    UDS = 41
    MMS = 42
    GMS = 43
    KGS = 44
    UCM = 45
    RM = 46
    FS = 47
    Econ = 48
    Backpack = 49
    UGS = 50
    Store = 51
    MoneyStats = 52
    CRE = 53
    UMQ = 54
    Workshop = 55
    BRP = 56
    GCH = 57
    MPAS = 58
    Trade = 59
    Secrets = 60
    Logsink = 61
    Market = 62
    Quest = 63
    WDS = 64
    ACS = 65
    PNP = 66

    Max = 67

 
class EBillingType:

    NoCost = 0
    BillOnceOnly = 1
    BillMonthly = 2
    ProofOfPrepurchaseOnly = 3
    GuestPass = 4
    HardwarePromo = 5
    Gift = 6
    AutoGrant = 7
    OEMTicket = 8
    RecurringOption = 9

    NumBillingTypes = 10


class EActivationCodeClass:

    WonCDKey = 0
    ValveCDKey = 1
    Doom3CDKey = 2
    DBLookup = 3
    Steam2010Key = 4
    Max = 5
    Test = 2147483647
    Invalid = 4294967295



class EChatMemberStateChange:

    Entered = 0x01
    Left = 0x02
    Disconnected = 0x04
    Kicked = 0x08
    Banned = 0x10

    VoiceSpeaking = 0x1000
    VoiceDoneSpeaking = 0x2000


class ERegionCode:

    USEast = 0x00
    USWest = 0x01
    SouthAmerica = 0x02
    Europe = 0x03
    Asia = 0x04
    Australia = 0x05
    MiddleEast = 0x06
    Africa = 0x07
    World = 0xFF


class ECurrencyCode:

    Invalid = 0

    USD = 1
    GBP = 2
    EUR = 3
    CHF = 4
    RUB = 5
    PLN = 6
    BRL = 7
    JPY = 8
    NOK = 9
    IDR = 10
    MYR = 11
    PHP = 12
    SGD = 13
    THB = 14
    VND = 15
    KRW = 16
    TRY = 17
    UAH = 18
    MXN = 19
    CAD = 20
    AUD = 21
    NZD = 22
    CNY = 23
    INR = 24
    CLP = 25
    PEN = 26
    COP = 27
    ZAR = 28
    HKD = 29
    TWD = 30
    SAR = 31
    AED = 32

    Max = 33


class EDepotFileFlag:

    UserConfig = 1
    VersionedUserConfig = 2
    Encrypted = 4
    ReadOnly = 8
    Hidden = 16
    Executable = 32
    Directory = 64
    CustomExecutable = 128
    InstallScript = 256


class EWorkshopEnumerationType:

    RankedByVote = 0
    Recent = 1
    Trending = 2
    FavoriteOfFriends = 3
    VotedByFriends = 4
    ContentByFriends = 5
    RecentFromFollowedUsers = 6


class EPublishedFileVisibility:

    Public = 0
    FriendsOnly = 1
    Private = 2


class EWorkshopFileType:

    First = 0

    Community    = 0
    Microtransaction    = 1
    Collection    = 2
    Art    = 3
    Video    = 4
    Screenshot    = 5
    Game    = 6
    Software    = 7
    Concept    = 8
    WebGuide    = 9
    IntegratedGuide    = 10
    Merch    = 11
    ControllerBinding    = 12
    SteamworksAccessInvite = 13
    SteamVideo = 14
    GameManagedItem = 15

    Max = 16


class EWorkshopFileAction:

    Played = 0
    Completed = 1


class EEconTradeResponse:

    Accepted = 0
    Declined = 1
    TradeBannedInitiator = 2
    TradeBannedTarget = 3
    TargetAlreadyTrading = 4
    Disabled = 5
    NotLoggedIn = 6
    Cancel = 7
    TooSoon = 8
    TooSoonPenalty = 9
    ConnectionFailed = 10
    AlreadyTrading = 11
    AlreadyHasTradeRequest = 12
    NoResponse = 13
    CyberCafeInitiator = 14
    CyberCafeTarget = 15
    SchoolLabInitiator = 16
    SchoolLabTarget = 16
    InitiatorBlockedTarget = 18
    InitiatorNeedsVerifiedEmail = 20
    InitiatorNeedsSteamGuard = 21
    TargetAccountCannotTrade = 22
    InitiatorSteamGuardDuration = 23
    InitiatorPasswordResetProbation = 24
    InitiatorNewDeviceCooldown = 25
    OKToDeliver = 50


class EMarketingMessageFlags:

    None_ = 0
    
    HighPriority = 1
    PlatformWindows = 2
    PlatformMac = 4
    PlatformLinux = 8
    PlatformRestrictions = PlatformWindows | PlatformMac | PlatformLinux


class ENewsUpdateType:

    AppNews = 0
    SteamAds = 1
    SteamNews = 2
    CDDBUpdate = 3
    ClientUpdate = 4


class ESystemIMType:

    RawText = 0
    InvalidCard = 1
    RecurringPurchaseFailed = 2
    CardWillExpire = 3
    SubscriptionExpired = 4
    GuestPassReceived = 5
    GuestPassGranted = 6
    GiftRevoked = 7
    SupportMessage = 8
    SupportMessageClearAlert = 9

    Max = 10


class EChatFlags:

    Locked = 1
    InvisibleToFriends = 2
    Moderated = 4
    Unjoinable = 8


class ERemoteStoragePlatform:

    None_ = 0
    
    Windows = 1
    OSX = 2
    PS3 = 4
    Linux = 8
    Reserved1 = 8
    Reserved2 = 16

    All = -1


class EDRMBlobDownloadType:

    Error = 0
    
    File = 1
    Parts = 2
    Compressed = 4
    AllMask = 7
    IsJob = 8
    HighPriority = 16
    AddTimestamp = 32
    LowPriority = 64


class EDRMBlobDownloadErrorDetail:

    None_ = 0
    
    DownloadFailed = 1
    TargetLocked = 2
    OpenZip = 3
    ReadZipDirectory = 4
    UnexpectedZipEntry = 5
    UnzipFullFile = 6
    UnknownBlobType = 7
    UnzipStrips = 8
    UnzipMergeGuid = 9
    UnzipSignature = 10
    ApplyStrips = 11
    ApplyMergeGuid = 12
    ApplySignature = 13
    AppIdMismatch = 14
    AppIdUnexpected = 15
    AppliedSignatureCorrupt = 16
    ApplyValveSignatureHeader = 17
    UnzipValveSignatureHeader = 18
    PathManipulationError = 19
    
    TargetLocked_Base = 65536
    TargetLocked_Max = 131071
    
    NextBase = 131072


class EClientStat:

    P2PConnectionsUDP = 0
    P2PConnectionsRelay = 1
    P2PGameConnections = 2
    P2PVoiceConnections = 3
    BytesDownloaded = 4
    
    Max = 5


class EClientStatAggregateMethod:

    LatestOnly = 0
    Sum = 1
    Event = 2
    Scalar = 3


class ELeaderboardDataRequest:

    Global = 0
    GlobalAroundUser = 1
    Friends = 2
    Users = 3


class ELeaderboardSortMethod:

    None_ = 0
    
    Ascending = 1
    Descending = 2


class ELeaderboardDisplayType:

    None_ = 0
    Numeric = 1
    TimeSeconds = 2
    TimeMilliSeconds = 3


class ELeaderboardUploadScoreMethod:

    None_ = 0
    
    KeepBest = 1
    ForceUpdate = 2


class EUCMFilePrivacyState:

    Invalid = -1
    Private = 2
    FriendsOnly = 4
    Public = 8
    
    All = Public | FriendsOnly | Private
   
  
class EResult:

    Invalid = 0
    
    OK = 1
    Fail = 2
    NoConnection = 3
    InvalidPassword = 5
    LoggedInElsewhere = 6
    InvalidProtocolVer = 7
    InvalidParam = 8
    FileNotFound = 9
    Busy = 10
    InvalidState = 11
    InvalidName = 12
    InvalidEmail = 13
    DuplicateName = 14
    AccessDenied = 15
    Timeout = 16
    Banned = 17
    AccountNotFound = 18
    InvalidSteamID = 19
    ServiceUnavailable = 20
    NotLoggedOn = 21
    Pending = 22
    EncryptionFailure = 23
    InsufficientPrivilege = 24
    LimitExceeded = 25
    Revoked = 26
    Expired = 27
    AlreadyRedeemed = 28
    DuplicateRequest = 29
    AlreadyOwned = 30
    IPNotFound = 31
    PersistFailed = 32
    LockingFailed = 33
    LogonSessionReplaced = 34
    ConnectFailed = 35
    HandshakeFailed = 36
    IOFailure = 37
    RemoteDisconnect = 38
    ShoppingCartNotFound = 39
    Blocked = 40
    Ignored = 41
    NoMatch = 42
    AccountDisabled = 43
    ServiceReadOnly = 44
    AccountNotFeatured = 45
    AdministratorOK = 46
    ContentVersion = 47
    TryAnotherCM = 48
    PasswordRequiredToKickSession = 49
    AlreadyLoggedInElsewhere = 50
    Suspended = 51
    Cancelled = 52
    DataCorruption = 53
    DiskFull = 54
    RemoteCallFailed = 55
    PasswordNotSet = 56
    PasswordUnset = 56
    ExternalAccountUnlinked = 57
    PSNTicketInvalid = 58
    ExternalAccountAlreadyLinked = 59
    RemoteFileConflict = 60
    IllegalPassword = 61
    SameAsPreviousValue = 62
    AccountLogonDenied = 63
    CannotUseOldPassword = 64
    InvalidLoginAuthCode = 65
    AccountLogonDeniedNoMailSent = 66
    AccountLogonDeniedNoMail = 66
    HardwareNotCapableOfIPT = 67
    IPTInitError = 68
    ParentalControlRestricted = 69
    FacebookQueryError = 70
    ExpiredLoginAuthCode = 71
    IPLoginRestrictionFailed = 72
    AccountLocked = 73
    AccountLockedDown = 73
    AccountLogonDeniedVerifiedEmailRequired = 74
    NoMatchingURL = 75
    BadResponse = 76
    RequirePasswordReEntry = 77
    ValueOutOfRange = 78
    UnexpectedError = 79
    Disabled = 80
    InvalidCEGSubmission = 81
    RestrictedDevice = 82
    RegionLocked = 83
    RateLimitExceeded = 84
    AccountLogonDeniedNeedTwoFactorCode = 85
    AccountLoginDeniedNeedTwoFactor = 85
    ItemOrEntryHasBeenDeleted = 86
    ItemDeleted = 86
    AccountLoginDeniedThrottle = 87
    TwoFactorCodeMismatch = 88
    TwoFactorActivationCodeMismatch = 89
    AccountAssociatedToMultiplePlayers = 90
    AccountAssociatedToMultiplePartners = 90
    NotModified = 91
    NoMobileDeviceAvailable = 92
    NoMobileDevice = 92
    TimeIsOutOfSync = 93
    TimeNotSynced = 93
    SMSCodeFailed = 94
    TooManyAccountsAccessThisResource = 95
    AccountLimitExceeded = 95
    AccountActivityLimitExceeded = 96
    PhoneActivityLimitExceeded = 97
    RefundToWallet = 98
    EmailSendFailure = 99
    NotSettled = 100
    NeedCaptcha = 101


   
    
class UniverseKeys:
    Public = str(bytearray([
                0x30, 0x81, 0x9D, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                0x05, 0x00, 0x03, 0x81, 0x8B, 0x00, 0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0xDF, 0xEC, 0x1A, 
                0xD6, 0x2C, 0x10, 0x66, 0x2C, 0x17, 0x35, 0x3A, 0x14, 0xB0, 0x7C, 0x59, 0x11, 0x7F, 0x9D, 0xD3, 
                0xD8, 0x2B, 0x7A, 0xE3, 0xE0, 0x15, 0xCD, 0x19, 0x1E, 0x46, 0xE8, 0x7B, 0x87, 0x74, 0xA2, 0x18, 
                0x46, 0x31, 0xA9, 0x03, 0x14, 0x79, 0x82, 0x8E, 0xE9, 0x45, 0xA2, 0x49, 0x12, 0xA9, 0x23, 0x68, 
                0x73, 0x89, 0xCF, 0x69, 0xA1, 0xB1, 0x61, 0x46, 0xBD, 0xC1, 0xBE, 0xBF, 0xD6, 0x01, 0x1B, 0xD8, 
                0x81, 0xD4, 0xDC, 0x90, 0xFB, 0xFE, 0x4F, 0x52, 0x73, 0x66, 0xCB, 0x95, 0x70, 0xD7, 0xC5, 0x8E, 
                0xBA, 0x1C, 0x7A, 0x33, 0x75, 0xA1, 0x62, 0x34, 0x46, 0xBB, 0x60, 0xB7, 0x80, 0x68, 0xFA, 0x13, 
                0xA7, 0x7A, 0x8A, 0x37, 0x4B, 0x9E, 0xC6, 0xF4, 0x5D, 0x5F, 0x3A, 0x99, 0xF9, 0x9E, 0xC4, 0x3A, 
                0xE9, 0x63, 0xA2, 0xBB, 0x88, 0x19, 0x28, 0xE0, 0xE7, 0x14, 0xC0, 0x42, 0x89, 0x02, 0x01, 0x11 ]))