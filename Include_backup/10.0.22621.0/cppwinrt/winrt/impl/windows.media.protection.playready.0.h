// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Protection_PlayReady_0_H
#define WINRT_Windows_Media_Protection_PlayReady_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct HResult;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IIterator;
    struct IPropertySet;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Media::Core
{
    struct AudioStreamDescriptor;
    struct IMediaStreamDescriptor;
    struct MediaStreamSample;
    struct MediaStreamSource;
    struct VideoStreamDescriptor;
}
WINRT_EXPORT namespace winrt::Windows::Media::Protection
{
    struct MediaProtectionManager;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady
{
    enum class NDCertificateFeature : int32_t
    {
        Transmitter = 1,
        Receiver = 2,
        SharedCertificate = 3,
        SecureClock = 4,
        AntiRollBackClock = 5,
        CRLS = 9,
        PlayReady3Features = 13,
    };
    enum class NDCertificatePlatformID : int32_t
    {
        Windows = 0,
        OSX = 1,
        WindowsOnARM = 2,
        WindowsMobile7 = 5,
        iOSOnARM = 6,
        XBoxOnPPC = 7,
        WindowsPhone8OnARM = 8,
        WindowsPhone8OnX86 = 9,
        XboxOne = 10,
        AndroidOnARM = 11,
        WindowsPhone81OnARM = 12,
        WindowsPhone81OnX86 = 13,
    };
    enum class NDCertificateType : int32_t
    {
        Unknown = 0,
        PC = 1,
        Device = 2,
        Domain = 3,
        Issuer = 4,
        CrlSigner = 5,
        Service = 6,
        Silverlight = 7,
        Application = 8,
        Metering = 9,
        KeyFileSigner = 10,
        Server = 11,
        LicenseSigner = 12,
    };
    enum class NDClosedCaptionFormat : int32_t
    {
        ATSC = 0,
        SCTE20 = 1,
        Unknown = 2,
    };
    enum class NDContentIDType : int32_t
    {
        KeyID = 1,
        PlayReadyObject = 2,
        Custom = 3,
    };
    enum class NDMediaStreamType : int32_t
    {
        Audio = 1,
        Video = 2,
    };
    enum class NDProximityDetectionType : int32_t
    {
        UDP = 1,
        TCP = 2,
        TransportAgnostic = 4,
    };
    enum class NDStartAsyncOptions : int32_t
    {
        MutualAuthentication = 1,
        WaitForLicenseDescriptor = 2,
    };
    enum class PlayReadyDecryptorSetup : int32_t
    {
        Uninitialized = 0,
        OnDemand = 1,
    };
    enum class PlayReadyEncryptionAlgorithm : int32_t
    {
        Unprotected = 0,
        Aes128Ctr = 1,
        Cocktail = 4,
        Aes128Cbc = 5,
        Unspecified = 65535,
        Uninitialized = 2147483647,
    };
    enum class PlayReadyHardwareDRMFeatures : int32_t
    {
        HardwareDRM = 1,
        HEVC = 2,
        Aes128Cbc = 3,
    };
    enum class PlayReadyITADataFormat : int32_t
    {
        SerializedProperties = 0,
        SerializedProperties_WithContentProtectionWrapper = 1,
    };
    struct INDClient;
    struct INDClientFactory;
    struct INDClosedCaptionDataReceivedEventArgs;
    struct INDCustomData;
    struct INDCustomDataFactory;
    struct INDDownloadEngine;
    struct INDDownloadEngineNotifier;
    struct INDLicenseFetchCompletedEventArgs;
    struct INDLicenseFetchDescriptor;
    struct INDLicenseFetchDescriptorFactory;
    struct INDLicenseFetchResult;
    struct INDMessenger;
    struct INDProximityDetectionCompletedEventArgs;
    struct INDRegistrationCompletedEventArgs;
    struct INDSendResult;
    struct INDStartResult;
    struct INDStorageFileHelper;
    struct INDStreamParser;
    struct INDStreamParserNotifier;
    struct INDTCPMessengerFactory;
    struct INDTransmitterProperties;
    struct IPlayReadyContentHeader;
    struct IPlayReadyContentHeader2;
    struct IPlayReadyContentHeaderFactory;
    struct IPlayReadyContentHeaderFactory2;
    struct IPlayReadyContentResolver;
    struct IPlayReadyDomain;
    struct IPlayReadyDomainIterableFactory;
    struct IPlayReadyDomainJoinServiceRequest;
    struct IPlayReadyDomainLeaveServiceRequest;
    struct IPlayReadyITADataGenerator;
    struct IPlayReadyIndividualizationServiceRequest;
    struct IPlayReadyLicense;
    struct IPlayReadyLicense2;
    struct IPlayReadyLicenseAcquisitionServiceRequest;
    struct IPlayReadyLicenseAcquisitionServiceRequest2;
    struct IPlayReadyLicenseAcquisitionServiceRequest3;
    struct IPlayReadyLicenseIterableFactory;
    struct IPlayReadyLicenseManagement;
    struct IPlayReadyLicenseSession;
    struct IPlayReadyLicenseSession2;
    struct IPlayReadyLicenseSessionFactory;
    struct IPlayReadyMeteringReportServiceRequest;
    struct IPlayReadyRevocationServiceRequest;
    struct IPlayReadySecureStopIterableFactory;
    struct IPlayReadySecureStopServiceRequest;
    struct IPlayReadySecureStopServiceRequestFactory;
    struct IPlayReadyServiceRequest;
    struct IPlayReadySoapMessage;
    struct IPlayReadyStatics;
    struct IPlayReadyStatics2;
    struct IPlayReadyStatics3;
    struct IPlayReadyStatics4;
    struct IPlayReadyStatics5;
    struct NDClient;
    struct NDCustomData;
    struct NDDownloadEngineNotifier;
    struct NDLicenseFetchDescriptor;
    struct NDStorageFileHelper;
    struct NDStreamParserNotifier;
    struct NDTCPMessenger;
    struct PlayReadyContentHeader;
    struct PlayReadyContentResolver;
    struct PlayReadyDomain;
    struct PlayReadyDomainIterable;
    struct PlayReadyDomainIterator;
    struct PlayReadyDomainJoinServiceRequest;
    struct PlayReadyDomainLeaveServiceRequest;
    struct PlayReadyITADataGenerator;
    struct PlayReadyIndividualizationServiceRequest;
    struct PlayReadyLicense;
    struct PlayReadyLicenseAcquisitionServiceRequest;
    struct PlayReadyLicenseIterable;
    struct PlayReadyLicenseIterator;
    struct PlayReadyLicenseManagement;
    struct PlayReadyLicenseSession;
    struct PlayReadyMeteringReportServiceRequest;
    struct PlayReadyRevocationServiceRequest;
    struct PlayReadySecureStopIterable;
    struct PlayReadySecureStopIterator;
    struct PlayReadySecureStopServiceRequest;
    struct PlayReadySoapMessage;
    struct PlayReadyStatics;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDClient>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDClientFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDCustomData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDMessenger>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDSendResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDStartResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDStreamParser>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDClient>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDCustomData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDStorageFileHelper>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentResolver>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomain>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainJoinServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainLeaveServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataGenerator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyIndividualizationServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicense>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseAcquisitionServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseManagement>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyMeteringReportServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyRevocationServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyStatics>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDCertificateFeature>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDCertificatePlatformID>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDCertificateType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDContentIDType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::NDStartAsyncOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataFormat>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDClient> = L"Windows.Media.Protection.PlayReady.NDClient";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDCustomData> = L"Windows.Media.Protection.PlayReady.NDCustomData";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier> = L"Windows.Media.Protection.PlayReady.NDDownloadEngineNotifier";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor> = L"Windows.Media.Protection.PlayReady.NDLicenseFetchDescriptor";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDStorageFileHelper> = L"Windows.Media.Protection.PlayReady.NDStorageFileHelper";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier> = L"Windows.Media.Protection.PlayReady.NDStreamParserNotifier";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger> = L"Windows.Media.Protection.PlayReady.NDTCPMessenger";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader> = L"Windows.Media.Protection.PlayReady.PlayReadyContentHeader";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentResolver> = L"Windows.Media.Protection.PlayReady.PlayReadyContentResolver";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomain> = L"Windows.Media.Protection.PlayReady.PlayReadyDomain";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable> = L"Windows.Media.Protection.PlayReady.PlayReadyDomainIterable";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterator> = L"Windows.Media.Protection.PlayReady.PlayReadyDomainIterator";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainJoinServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadyDomainJoinServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainLeaveServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadyDomainLeaveServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataGenerator> = L"Windows.Media.Protection.PlayReady.PlayReadyITADataGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyIndividualizationServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadyIndividualizationServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicense> = L"Windows.Media.Protection.PlayReady.PlayReadyLicense";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseAcquisitionServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadyLicenseAcquisitionServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable> = L"Windows.Media.Protection.PlayReady.PlayReadyLicenseIterable";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterator> = L"Windows.Media.Protection.PlayReady.PlayReadyLicenseIterator";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseManagement> = L"Windows.Media.Protection.PlayReady.PlayReadyLicenseManagement";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession> = L"Windows.Media.Protection.PlayReady.PlayReadyLicenseSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyMeteringReportServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadyMeteringReportServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyRevocationServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadyRevocationServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable> = L"Windows.Media.Protection.PlayReady.PlayReadySecureStopIterable";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterator> = L"Windows.Media.Protection.PlayReady.PlayReadySecureStopIterator";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest> = L"Windows.Media.Protection.PlayReady.PlayReadySecureStopServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage> = L"Windows.Media.Protection.PlayReady.PlayReadySoapMessage";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyStatics> = L"Windows.Media.Protection.PlayReady.PlayReadyStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDCertificateFeature> = L"Windows.Media.Protection.PlayReady.NDCertificateFeature";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDCertificatePlatformID> = L"Windows.Media.Protection.PlayReady.NDCertificatePlatformID";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDCertificateType> = L"Windows.Media.Protection.PlayReady.NDCertificateType";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat> = L"Windows.Media.Protection.PlayReady.NDClosedCaptionFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDContentIDType> = L"Windows.Media.Protection.PlayReady.NDContentIDType";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType> = L"Windows.Media.Protection.PlayReady.NDMediaStreamType";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType> = L"Windows.Media.Protection.PlayReady.NDProximityDetectionType";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::NDStartAsyncOptions> = L"Windows.Media.Protection.PlayReady.NDStartAsyncOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup> = L"Windows.Media.Protection.PlayReady.PlayReadyDecryptorSetup";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm> = L"Windows.Media.Protection.PlayReady.PlayReadyEncryptionAlgorithm";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures> = L"Windows.Media.Protection.PlayReady.PlayReadyHardwareDRMFeatures";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataFormat> = L"Windows.Media.Protection.PlayReady.PlayReadyITADataFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDClient> = L"Windows.Media.Protection.PlayReady.INDClient";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDClientFactory> = L"Windows.Media.Protection.PlayReady.INDClientFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> = L"Windows.Media.Protection.PlayReady.INDClosedCaptionDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDCustomData> = L"Windows.Media.Protection.PlayReady.INDCustomData";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory> = L"Windows.Media.Protection.PlayReady.INDCustomDataFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine> = L"Windows.Media.Protection.PlayReady.INDDownloadEngine";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier> = L"Windows.Media.Protection.PlayReady.INDDownloadEngineNotifier";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> = L"Windows.Media.Protection.PlayReady.INDLicenseFetchCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor> = L"Windows.Media.Protection.PlayReady.INDLicenseFetchDescriptor";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory> = L"Windows.Media.Protection.PlayReady.INDLicenseFetchDescriptorFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult> = L"Windows.Media.Protection.PlayReady.INDLicenseFetchResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDMessenger> = L"Windows.Media.Protection.PlayReady.INDMessenger";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> = L"Windows.Media.Protection.PlayReady.INDProximityDetectionCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> = L"Windows.Media.Protection.PlayReady.INDRegistrationCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDSendResult> = L"Windows.Media.Protection.PlayReady.INDSendResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDStartResult> = L"Windows.Media.Protection.PlayReady.INDStartResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper> = L"Windows.Media.Protection.PlayReady.INDStorageFileHelper";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDStreamParser> = L"Windows.Media.Protection.PlayReady.INDStreamParser";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier> = L"Windows.Media.Protection.PlayReady.INDStreamParserNotifier";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory> = L"Windows.Media.Protection.PlayReady.INDTCPMessengerFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties> = L"Windows.Media.Protection.PlayReady.INDTransmitterProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader> = L"Windows.Media.Protection.PlayReady.IPlayReadyContentHeader";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2> = L"Windows.Media.Protection.PlayReady.IPlayReadyContentHeader2";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory> = L"Windows.Media.Protection.PlayReady.IPlayReadyContentHeaderFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2> = L"Windows.Media.Protection.PlayReady.IPlayReadyContentHeaderFactory2";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver> = L"Windows.Media.Protection.PlayReady.IPlayReadyContentResolver";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain> = L"Windows.Media.Protection.PlayReady.IPlayReadyDomain";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory> = L"Windows.Media.Protection.PlayReady.IPlayReadyDomainIterableFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyDomainJoinServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyDomainLeaveServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator> = L"Windows.Media.Protection.PlayReady.IPlayReadyITADataGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyIndividualizationServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicense";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicense2";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseAcquisitionServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseAcquisitionServiceRequest2";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseAcquisitionServiceRequest3";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseIterableFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseManagement";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseSession2";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory> = L"Windows.Media.Protection.PlayReady.IPlayReadyLicenseSessionFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyMeteringReportServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyRevocationServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory> = L"Windows.Media.Protection.PlayReady.IPlayReadySecureStopIterableFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadySecureStopServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory> = L"Windows.Media.Protection.PlayReady.IPlayReadySecureStopServiceRequestFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest> = L"Windows.Media.Protection.PlayReady.IPlayReadyServiceRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage> = L"Windows.Media.Protection.PlayReady.IPlayReadySoapMessage";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics> = L"Windows.Media.Protection.PlayReady.IPlayReadyStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2> = L"Windows.Media.Protection.PlayReady.IPlayReadyStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3> = L"Windows.Media.Protection.PlayReady.IPlayReadyStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4> = L"Windows.Media.Protection.PlayReady.IPlayReadyStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5> = L"Windows.Media.Protection.PlayReady.IPlayReadyStatics5";
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDClient>{ 0x3BD6781B,0x61B8,0x46E2,{ 0x99,0xA5,0x8A,0xBC,0xB6,0xB9,0xF7,0xD6 } }; // 3BD6781B-61B8-46E2-99A5-8ABCB6B9F7D6
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDClientFactory>{ 0x3E53DD62,0xFEE8,0x451F,{ 0xB0,0xD4,0xF7,0x06,0xCC,0xA3,0xE0,0x37 } }; // 3E53DD62-FEE8-451F-B0D4-F706CCA3E037
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs>{ 0x4738D29F,0xC345,0x4649,{ 0x84,0x68,0xB8,0xC5,0xFC,0x35,0x71,0x90 } }; // 4738D29F-C345-4649-8468-B8C5FC357190
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDCustomData>{ 0xF5CB0FDC,0x2D09,0x4F19,{ 0xB5,0xE1,0x76,0xA0,0xB3,0xEE,0x92,0x67 } }; // F5CB0FDC-2D09-4F19-B5E1-76A0B3EE9267
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory>{ 0xD65405AB,0x3424,0x4833,{ 0x8C,0x9A,0xAF,0x5F,0xDE,0xB2,0x28,0x72 } }; // D65405AB-3424-4833-8C9A-AF5FDEB22872
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine>{ 0x2D223D65,0xC4B6,0x4438,{ 0x8D,0x46,0xB9,0x6E,0x6D,0x0F,0xB2,0x1F } }; // 2D223D65-C4B6-4438-8D46-B96E6D0FB21F
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier>{ 0xD720B4D4,0xF4B8,0x4530,{ 0xA8,0x09,0x91,0x93,0xA5,0x71,0xE7,0xFC } }; // D720B4D4-F4B8-4530-A809-9193A571E7FC
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs>{ 0x1EE30A1A,0x11B2,0x4558,{ 0x88,0x65,0xE3,0xA5,0x16,0x92,0x25,0x17 } }; // 1EE30A1A-11B2-4558-8865-E3A516922517
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor>{ 0x5498D33A,0xE686,0x4935,{ 0xA5,0x67,0x7C,0xA7,0x7A,0xD2,0x0F,0xA4 } }; // 5498D33A-E686-4935-A567-7CA77AD20FA4
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>{ 0xD0031202,0xCFAC,0x4F00,{ 0xAE,0x6A,0x97,0xAF,0x80,0xB8,0x48,0xF2 } }; // D0031202-CFAC-4F00-AE6A-97AF80B848F2
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>{ 0x21D39698,0xAA62,0x45FF,{ 0xA5,0xFF,0x80,0x37,0xE5,0x43,0x38,0x25 } }; // 21D39698-AA62-45FF-A5FF-8037E5433825
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDMessenger>{ 0xD42DF95D,0xA75B,0x47BF,{ 0x82,0x49,0xBC,0x83,0x82,0x0D,0xA3,0x8A } }; // D42DF95D-A75B-47BF-8249-BC83820DA38A
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs>{ 0x2A706328,0xDA25,0x4F8C,{ 0x9E,0xB7,0x5D,0x0F,0xC3,0x65,0x8B,0xCA } }; // 2A706328-DA25-4F8C-9EB7-5D0FC3658BCA
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs>{ 0x9E39B64D,0xAB5B,0x4905,{ 0xAC,0xDC,0x78,0x7A,0x77,0xC6,0x37,0x4D } }; // 9E39B64D-AB5B-4905-ACDC-787A77C6374D
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDSendResult>{ 0xE3685517,0xA584,0x479D,{ 0x90,0xB7,0xD6,0x89,0xC7,0xBF,0x7C,0x80 } }; // E3685517-A584-479D-90B7-D689C7BF7C80
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDStartResult>{ 0x79F6E96E,0xF50F,0x4015,{ 0x8B,0xA4,0xC2,0xBC,0x34,0x4E,0xBD,0x4E } }; // 79F6E96E-F50F-4015-8BA4-C2BC344EBD4E
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper>{ 0xD8F0BEF8,0x91D2,0x4D47,{ 0xA3,0xF9,0xEA,0xFF,0x4E,0xDB,0x72,0x9F } }; // D8F0BEF8-91D2-4D47-A3F9-EAFF4EDB729F
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDStreamParser>{ 0xE0BAA198,0x9796,0x41C9,{ 0x86,0x95,0x59,0x43,0x7E,0x67,0xE6,0x6A } }; // E0BAA198-9796-41C9-8695-59437E67E66A
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier>{ 0xC167ACD0,0x2CE6,0x426C,{ 0xAC,0xE5,0x5E,0x92,0x75,0xFE,0xA7,0x15 } }; // C167ACD0-2CE6-426C-ACE5-5E9275FEA715
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>{ 0x7DD85CFE,0x1B99,0x4F68,{ 0x8F,0x82,0x81,0x77,0xF7,0xCE,0xDF,0x2B } }; // 7DD85CFE-1B99-4F68-8F82-8177F7CEDF2B
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties>{ 0xE536AF23,0xAC4F,0x4ADC,{ 0x8C,0x66,0x4F,0xF7,0xC2,0x70,0x2D,0xD6 } }; // E536AF23-AC4F-4ADC-8C66-4FF7C2702DD6
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>{ 0x9A438A6A,0x7F4C,0x452E,{ 0x88,0xBD,0x01,0x48,0xC6,0x38,0x7A,0x2C } }; // 9A438A6A-7F4C-452E-88BD-0148C6387A2C
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>{ 0x359C79F4,0x2180,0x498C,{ 0x96,0x5B,0xE7,0x54,0xD8,0x75,0xEA,0xB2 } }; // 359C79F4-2180-498C-965B-E754D875EAB2
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>{ 0xCB97C8FF,0xB758,0x4776,{ 0xBF,0x01,0x21,0x7A,0x8B,0x51,0x0B,0x2C } }; // CB97C8FF-B758-4776-BF01-217A8B510B2C
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>{ 0xD1239CF5,0xAE6D,0x4778,{ 0x97,0xFD,0x6E,0x3A,0x2E,0xEA,0xDB,0xEB } }; // D1239CF5-AE6D-4778-97FD-6E3A2EEADBEB
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>{ 0xFBFD2523,0x906D,0x4982,{ 0xA6,0xB8,0x68,0x49,0x56,0x5A,0x7C,0xE8 } }; // FBFD2523-906D-4982-A6B8-6849565A7CE8
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>{ 0xADCC93AC,0x97E6,0x43EF,{ 0x95,0xE4,0xD7,0x86,0x8F,0x3B,0x16,0xA9 } }; // ADCC93AC-97E6-43EF-95E4-D7868F3B16A9
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>{ 0x4DF384EE,0x3121,0x4DF3,{ 0xA5,0xE8,0xD0,0xC2,0x4C,0x05,0x00,0xFC } }; // 4DF384EE-3121-4DF3-A5E8-D0C24C0500FC
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest>{ 0x171B4A5A,0x405F,0x4739,{ 0xB0,0x40,0x67,0xB9,0xF0,0xC3,0x87,0x58 } }; // 171B4A5A-405F-4739-B040-67B9F0C38758
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest>{ 0x062D58BE,0x97AD,0x4917,{ 0xAA,0x03,0x46,0xD4,0xC2,0x52,0xD4,0x64 } }; // 062D58BE-97AD-4917-AA03-46D4C252D464
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator>{ 0x24446B8E,0x10B9,0x4530,{ 0xB2,0x5B,0x90,0x1A,0x80,0x29,0xA9,0xB2 } }; // 24446B8E-10B9-4530-B25B-901A8029A9B2
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest>{ 0x21F5A86B,0x008C,0x4611,{ 0xAB,0x2F,0xAA,0xA6,0xC6,0x9F,0x0E,0x24 } }; // 21F5A86B-008C-4611-AB2F-AAA6C69F0E24
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>{ 0xEE474C4E,0xFA3C,0x414D,{ 0xA9,0xF2,0x3F,0xFC,0x1E,0xF8,0x32,0xD4 } }; // EE474C4E-FA3C-414D-A9F2-3FFC1EF832D4
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2>{ 0x30F4E7A7,0xD8E3,0x48A0,{ 0xBC,0xDA,0xFF,0x9F,0x40,0x53,0x04,0x36 } }; // 30F4E7A7-D8E3-48A0-BCDA-FF9F40530436
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>{ 0x5D85FF45,0x3E9F,0x4F48,{ 0x93,0xE1,0x95,0x30,0xC8,0xD5,0x8C,0x3E } }; // 5D85FF45-3E9F-4F48-93E1-9530C8D58C3E
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>{ 0xB7FA5EB5,0xFE0C,0xB225,{ 0xBC,0x60,0x5A,0x9E,0xDD,0x32,0xCE,0xB5 } }; // B7FA5EB5-FE0C-B225-BC60-5A9EDD32CEB5
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>{ 0x394E5F4D,0x7F75,0x430D,{ 0xB2,0xE7,0x7F,0x75,0xF3,0x4B,0x2D,0x75 } }; // 394E5F4D-7F75-430D-B2E7-7F75F34B2D75
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>{ 0xD4179F08,0x0837,0x4978,{ 0x8E,0x68,0xBE,0x42,0x93,0xC8,0xD7,0xA6 } }; // D4179F08-0837-4978-8E68-BE4293C8D7A6
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>{ 0xAAEB2141,0x0957,0x4405,{ 0xB8,0x92,0x8B,0xF3,0xEC,0x5D,0xAD,0xD9 } }; // AAEB2141-0957-4405-B892-8BF3EC5DADD9
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>{ 0xA1723A39,0x87FA,0x4FDD,{ 0xAB,0xBB,0xA9,0x72,0x0E,0x84,0x52,0x59 } }; // A1723A39-87FA-4FDD-ABBB-A9720E845259
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>{ 0x4909BE3A,0x3AED,0x4656,{ 0x8A,0xD7,0xEE,0x0F,0xD7,0x79,0x95,0x10 } }; // 4909BE3A-3AED-4656-8AD7-EE0FD7799510
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>{ 0x62492699,0x6527,0x429E,{ 0x98,0xBE,0x48,0xD7,0x98,0xAC,0x27,0x39 } }; // 62492699-6527-429E-98BE-48D798AC2739
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest>{ 0xC12B231C,0x0ECD,0x4F11,{ 0xA1,0x85,0x1E,0x24,0xA4,0xA6,0x7F,0xB7 } }; // C12B231C-0ECD-4F11-A185-1E24A4A67FB7
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest>{ 0x543D66AC,0xFAF0,0x4560,{ 0x84,0xA5,0x0E,0x4A,0xCE,0xC9,0x39,0xE4 } }; // 543D66AC-FAF0-4560-84A5-0E4ACEC939E4
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>{ 0x5F1F0165,0x4214,0x4D9E,{ 0x81,0xEB,0xE8,0x9F,0x9D,0x29,0x4A,0xEE } }; // 5F1F0165-4214-4D9E-81EB-E89F9D294AEE
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>{ 0xB5501EE5,0x01BF,0x4401,{ 0x96,0x77,0x05,0x63,0x0A,0x6A,0x4C,0xC8 } }; // B5501EE5-01BF-4401-9677-05630A6A4CC8
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>{ 0x0E448AC9,0xE67E,0x494E,{ 0x9F,0x49,0x62,0x85,0x43,0x8C,0x76,0xCF } }; // 0E448AC9-E67E-494E-9F49-6285438C76CF
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>{ 0x8BAD2836,0xA703,0x45A6,{ 0xA1,0x80,0x76,0xF3,0x56,0x5A,0xA7,0x25 } }; // 8BAD2836-A703-45A6-A180-76F3565AA725
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage>{ 0xB659FCB5,0xCE41,0x41BA,{ 0x8A,0x0D,0x61,0xDF,0x5F,0xFF,0xA1,0x39 } }; // B659FCB5-CE41-41BA-8A0D-61DF5FFFA139
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics>{ 0x5E69C00D,0x247C,0x469A,{ 0x8F,0x31,0x5C,0x1A,0x15,0x71,0xD9,0xC6 } }; // 5E69C00D-247C-469A-8F31-5C1A1571D9C6
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2>{ 0x1F8D6A92,0x5F9A,0x423E,{ 0x94,0x66,0xB3,0x39,0x69,0xAF,0x7A,0x3D } }; // 1F8D6A92-5F9A-423E-9466-B33969AF7A3D
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3>{ 0x3FA33F71,0x2DD3,0x4BED,{ 0xAE,0x49,0xF7,0x14,0x8E,0x63,0xE7,0x10 } }; // 3FA33F71-2DD3-4BED-AE49-F7148E63E710
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4>{ 0x50A91300,0xD824,0x4231,{ 0x9D,0x5E,0x78,0xEF,0x88,0x44,0xC7,0xD7 } }; // 50A91300-D824-4231-9D5E-78EF8844C7D7
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5>{ 0x230A7075,0xDFA0,0x4F8E,{ 0xA7,0x79,0xCE,0xFE,0xA9,0xC6,0x82,0x4B } }; // 230A7075-DFA0-4F8E-A779-CEFEA9C6824B
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDClient>{ using type = winrt::Windows::Media::Protection::PlayReady::INDClient; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDCustomData>{ using type = winrt::Windows::Media::Protection::PlayReady::INDCustomData; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier>{ using type = winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor>{ using type = winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDStorageFileHelper>{ using type = winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier>{ using type = winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger>{ using type = winrt::Windows::Media::Protection::PlayReady::INDMessenger; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomain>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable>{ using type = winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterator>{ using type = winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainJoinServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainLeaveServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataGenerator>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyIndividualizationServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicense>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseAcquisitionServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>{ using type = winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterator>{ using type = winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyMeteringReportServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadyRevocationServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable>{ using type = winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterator>{ using type = winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest; };
    template <> struct default_interface<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage>{ using type = winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage; };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDClient>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_RegistrationCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RegistrationCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ProximityDetectionCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProximityDetectionCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_LicenseFetchCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_LicenseFetchCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ReRegistrationNeeded(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReRegistrationNeeded(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ClosedCaptionDataReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ClosedCaptionDataReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall StartAsync(void*, uint32_t, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall LicenseFetchAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReRegistrationAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall Close() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDClientFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ClosedCaptionDataFormat(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PresentationTimestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_ClosedCaptionData(uint32_t* __ccDataBytesSize, uint8_t**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDCustomData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CustomDataTypeID(uint32_t* __customDataTypeIDBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall get_CustomData(uint32_t* __customDataBytesSize, uint8_t**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(uint32_t, uint8_t*, uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Open(void*, uint32_t, uint8_t*) noexcept = 0;
            virtual int32_t __stdcall Pause() noexcept = 0;
            virtual int32_t __stdcall Resume() noexcept = 0;
            virtual int32_t __stdcall Close() noexcept = 0;
            virtual int32_t __stdcall Seek(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_CanSeek(bool*) noexcept = 0;
            virtual int32_t __stdcall get_BufferFullMinThresholdInSamples(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_BufferFullMaxThresholdInSamples(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Notifier(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OnStreamOpened() noexcept = 0;
            virtual int32_t __stdcall OnPlayReadyObjectReceived(uint32_t, uint8_t*) noexcept = 0;
            virtual int32_t __stdcall OnContentIDReceived(void*) noexcept = 0;
            virtual int32_t __stdcall OnDataReceived(uint32_t, uint8_t*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall OnEndOfStream() noexcept = 0;
            virtual int32_t __stdcall OnNetworkError() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResponseCustomData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContentIDType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ContentID(uint32_t* __contentIDBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall get_LicenseFetchChallengeCustomData(void**) noexcept = 0;
            virtual int32_t __stdcall put_LicenseFetchChallengeCustomData(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(int32_t, uint32_t, uint8_t*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResponseCustomData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDMessenger>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SendRegistrationRequestAsync(uint32_t, uint8_t*, uint32_t, uint8_t*, void**) noexcept = 0;
            virtual int32_t __stdcall SendProximityDetectionStartAsync(int32_t, uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*, void**) noexcept = 0;
            virtual int32_t __stdcall SendProximityDetectionResponseAsync(int32_t, uint32_t, uint8_t*, uint32_t, uint8_t*, uint32_t, uint8_t*, void**) noexcept = 0;
            virtual int32_t __stdcall SendLicenseFetchRequestAsync(uint32_t, uint8_t*, uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProximityDetectionRetryCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResponseCustomData(void**) noexcept = 0;
            virtual int32_t __stdcall get_TransmitterProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_TransmitterCertificateAccepted(bool*) noexcept = 0;
            virtual int32_t __stdcall put_TransmitterCertificateAccepted(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDSendResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Response(uint32_t* __responseDataBytesSize, uint8_t**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDStartResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MediaStreamSource(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFileURLs(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDStreamParser>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ParseData(uint32_t, uint8_t*) noexcept = 0;
            virtual int32_t __stdcall GetStreamInformation(void*, int32_t*, uint32_t*) noexcept = 0;
            virtual int32_t __stdcall BeginOfStream() noexcept = 0;
            virtual int32_t __stdcall EndOfStream() noexcept = 0;
            virtual int32_t __stdcall get_Notifier(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OnContentIDReceived(void*) noexcept = 0;
            virtual int32_t __stdcall OnMediaStreamDescriptorCreated(void*, void*) noexcept = 0;
            virtual int32_t __stdcall OnSampleParsed(uint32_t, int32_t, void*, int64_t, int32_t, uint32_t, uint8_t*) noexcept = 0;
            virtual int32_t __stdcall OnBeginSetupDecryptor(void*, winrt::guid, uint32_t, uint8_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CertificateType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PlatformIdentifier(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedFeatures(uint32_t* __featureSetsSize, int32_t**) noexcept = 0;
            virtual int32_t __stdcall get_SecurityLevel(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SecurityVersion(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExpirationDate(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_ClientID(uint32_t* __clientIDBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall get_ModelDigest(uint32_t* __modelDigestBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall get_ModelManufacturerName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ModelName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ModelNumber(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_KeyId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_KeyIdString(void**) noexcept = 0;
            virtual int32_t __stdcall get_LicenseAcquisitionUrl(void**) noexcept = 0;
            virtual int32_t __stdcall get_LicenseAcquisitionUserInterfaceUrl(void**) noexcept = 0;
            virtual int32_t __stdcall get_DomainServiceId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_EncryptionType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CustomAttributes(void**) noexcept = 0;
            virtual int32_t __stdcall get_DecryptorSetup(int32_t*) noexcept = 0;
            virtual int32_t __stdcall GetSerializedHeader(uint32_t* __headerBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall get_HeaderWithEmbeddedUpdates(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_KeyIds(uint32_t* __contentKeyIdsSize, winrt::guid**) noexcept = 0;
            virtual int32_t __stdcall get_KeyIdStrings(uint32_t* __contentKeyIdStringsSize, void***) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstanceFromWindowsMediaDrmHeader(uint32_t, uint8_t*, void*, void*, void*, winrt::guid, void**) noexcept = 0;
            virtual int32_t __stdcall CreateInstanceFromComponents(winrt::guid, void*, int32_t, void*, void*, void*, winrt::guid, void**) noexcept = 0;
            virtual int32_t __stdcall CreateInstanceFromPlayReadyHeader(uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstanceFromComponents2(uint32_t, uint32_t, winrt::guid*, uint32_t, void**, int32_t, void*, void*, void*, winrt::guid, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ServiceRequest(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AccountId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_Revision(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_FriendlyName(void**) noexcept = 0;
            virtual int32_t __stdcall get_DomainJoinUrl(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(winrt::guid, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DomainAccountId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_DomainAccountId(winrt::guid) noexcept = 0;
            virtual int32_t __stdcall get_DomainFriendlyName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DomainFriendlyName(void*) noexcept = 0;
            virtual int32_t __stdcall get_DomainServiceId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_DomainServiceId(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DomainAccountId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_DomainAccountId(winrt::guid) noexcept = 0;
            virtual int32_t __stdcall get_DomainServiceId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_DomainServiceId(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GenerateData(winrt::guid, uint32_t, void*, int32_t, uint32_t* __dataBytesSize, uint8_t**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FullyEvaluated(bool*) noexcept = 0;
            virtual int32_t __stdcall get_UsableForPlay(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ExpirationDate(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExpireAfterFirstPlay(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DomainAccountID(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_ChainDepth(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall GetKIDAtChainDepth(uint32_t, winrt::guid*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SecureStopId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_SecurityLevel(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InMemoryOnly(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ExpiresInRealTime(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContentHeader(void**) noexcept = 0;
            virtual int32_t __stdcall put_ContentHeader(void*) noexcept = 0;
            virtual int32_t __stdcall get_DomainServiceId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_DomainServiceId(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SessionId(winrt::guid*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateLicenseIterable(void*, bool, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, bool, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall DeleteLicenses(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateLAServiceRequest(void**) noexcept = 0;
            virtual int32_t __stdcall ConfigureMediaProtectionManager(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateLicenseIterable(void*, bool, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MeteringCertificate(uint32_t* __meteringCertBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall put_MeteringCertificate(uint32_t, uint8_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SessionID(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_StartTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_UpdateTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Stopped(bool*) noexcept = 0;
            virtual int32_t __stdcall get_PublisherCertificate(uint32_t* __publisherCertBytesSize, uint8_t**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(uint32_t, uint8_t*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateInstanceFromSessionID(winrt::guid, uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
            virtual int32_t __stdcall put_Uri(void*) noexcept = 0;
            virtual int32_t __stdcall get_ResponseCustomData(void**) noexcept = 0;
            virtual int32_t __stdcall get_ChallengeCustomData(void**) noexcept = 0;
            virtual int32_t __stdcall put_ChallengeCustomData(void*) noexcept = 0;
            virtual int32_t __stdcall BeginServiceRequest(void**) noexcept = 0;
            virtual int32_t __stdcall NextServiceRequest(void**) noexcept = 0;
            virtual int32_t __stdcall GenerateManualEnablingChallenge(void**) noexcept = 0;
            virtual int32_t __stdcall ProcessManualEnablingResponse(uint32_t, uint8_t*, winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetMessageBody(uint32_t* __messageBodyBytesSize, uint8_t**) noexcept = 0;
            virtual int32_t __stdcall get_MessageHeaders(void**) noexcept = 0;
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DomainJoinServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_DomainLeaveServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_IndividualizationServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_LicenseAcquirerServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_MeteringReportServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_RevocationServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_MediaProtectionSystemId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_PlayReadySecurityVersion(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PlayReadyCertificateSecurityLevel(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SecureStopServiceRequestType(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall CheckSupportedHardware(int32_t, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_InputTrustAuthorityToCreate(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProtectionSystemId(winrt::guid*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HardwareDRMDisabledAtTime(void**) noexcept = 0;
            virtual int32_t __stdcall get_HardwareDRMDisabledUntilTime(void**) noexcept = 0;
            virtual int32_t __stdcall ResetHardwareDRMDisabled() noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDClient
    {
        WINRT_IMPL_AUTO(winrt::event_token) RegistrationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const& handler) const;
        using RegistrationCompleted_revoker = impl::event_revoker<winrt::Windows::Media::Protection::PlayReady::INDClient, &impl::abi_t<winrt::Windows::Media::Protection::PlayReady::INDClient>::remove_RegistrationCompleted>;
        [[nodiscard]] RegistrationCompleted_revoker RegistrationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) RegistrationCompleted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ProximityDetectionCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const& handler) const;
        using ProximityDetectionCompleted_revoker = impl::event_revoker<winrt::Windows::Media::Protection::PlayReady::INDClient, &impl::abi_t<winrt::Windows::Media::Protection::PlayReady::INDClient>::remove_ProximityDetectionCompleted>;
        [[nodiscard]] ProximityDetectionCompleted_revoker ProximityDetectionCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ProximityDetectionCompleted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) LicenseFetchCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const& handler) const;
        using LicenseFetchCompleted_revoker = impl::event_revoker<winrt::Windows::Media::Protection::PlayReady::INDClient, &impl::abi_t<winrt::Windows::Media::Protection::PlayReady::INDClient>::remove_LicenseFetchCompleted>;
        [[nodiscard]] LicenseFetchCompleted_revoker LicenseFetchCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) LicenseFetchCompleted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ReRegistrationNeeded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ReRegistrationNeeded_revoker = impl::event_revoker<winrt::Windows::Media::Protection::PlayReady::INDClient, &impl::abi_t<winrt::Windows::Media::Protection::PlayReady::INDClient>::remove_ReRegistrationNeeded>;
        [[nodiscard]] ReRegistrationNeeded_revoker ReRegistrationNeeded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ReRegistrationNeeded(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ClosedCaptionDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const& handler) const;
        using ClosedCaptionDataReceived_revoker = impl::event_revoker<winrt::Windows::Media::Protection::PlayReady::INDClient, &impl::abi_t<winrt::Windows::Media::Protection::PlayReady::INDClient>::remove_ClosedCaptionDataReceived>;
        [[nodiscard]] ClosedCaptionDataReceived_revoker ClosedCaptionDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ClosedCaptionDataReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDStartResult>) StartAsync(winrt::Windows::Foundation::Uri const& contentUrl, uint32_t startAsyncOptions, winrt::Windows::Media::Protection::PlayReady::INDCustomData const& registrationCustomData, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>) LicenseFetchAsync(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ReRegistrationAsync(winrt::Windows::Media::Protection::PlayReady::INDCustomData const& registrationCustomData) const;
        WINRT_IMPL_AUTO(void) Close() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDClient>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDClient<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDClientFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDClient) CreateInstance(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine const& downloadEngine, winrt::Windows::Media::Protection::PlayReady::INDStreamParser const& streamParser, winrt::Windows::Media::Protection::PlayReady::INDMessenger const& pMessenger) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDClientFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDClientFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat) ClosedCaptionDataFormat() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int64_t) PresentationTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) ClosedCaptionData() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDCustomData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) CustomDataTypeID() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) CustomData() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDCustomData>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDCustomData<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDCustomDataFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDCustomData) CreateInstance(array_view<uint8_t const> customDataTypeIDBytes, array_view<uint8_t const> customDataBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDCustomDataFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDDownloadEngine
    {
        WINRT_IMPL_AUTO(void) Open(winrt::Windows::Foundation::Uri const& uri, array_view<uint8_t const> sessionIDBytes) const;
        WINRT_IMPL_AUTO(void) Pause() const;
        WINRT_IMPL_AUTO(void) Resume() const;
        WINRT_IMPL_AUTO(void) Close() const;
        WINRT_IMPL_AUTO(void) Seek(winrt::Windows::Foundation::TimeSpan const& startPosition) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanSeek() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) BufferFullMinThresholdInSamples() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) BufferFullMaxThresholdInSamples() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier) Notifier() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier
    {
        WINRT_IMPL_AUTO(void) OnStreamOpened() const;
        WINRT_IMPL_AUTO(void) OnPlayReadyObjectReceived(array_view<uint8_t const> dataBytes) const;
        WINRT_IMPL_AUTO(void) OnContentIDReceived(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const;
        WINRT_IMPL_AUTO(void) OnDataReceived(array_view<uint8_t const> dataBytes, uint32_t bytesReceived) const;
        WINRT_IMPL_AUTO(void) OnEndOfStream() const;
        WINRT_IMPL_AUTO(void) OnNetworkError() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDLicenseFetchCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) ResponseCustomData() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDLicenseFetchCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDContentIDType) ContentIDType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) ContentID() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) LicenseFetchChallengeCustomData() const;
        WINRT_IMPL_AUTO(void) LicenseFetchChallengeCustomData(winrt::Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptorFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor) CreateInstance(winrt::Windows::Media::Protection::PlayReady::NDContentIDType const& contentIDType, array_view<uint8_t const> contentIDBytes, winrt::Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptorFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDLicenseFetchResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) ResponseCustomData() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDLicenseFetchResult<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDMessenger
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) SendRegistrationRequestAsync(array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) SendProximityDetectionStartAsync(winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType const& pdType, array_view<uint8_t const> transmitterChannelBytes, array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) SendProximityDetectionResponseAsync(winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType const& pdType, array_view<uint8_t const> transmitterChannelBytes, array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> responseDataBytes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) SendLicenseFetchRequestAsync(array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDMessenger>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDMessenger<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDProximityDetectionCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ProximityDetectionRetryCount() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDProximityDetectionCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) ResponseCustomData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties) TransmitterProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) TransmitterCertificateAccepted() const;
        WINRT_IMPL_AUTO(void) TransmitterCertificateAccepted(bool accept) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDSendResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) Response() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDSendResult>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDSendResult<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDStartResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSource) MediaStreamSource() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDStartResult>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDStartResult<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDStorageFileHelper
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) GetFileURLs(winrt::Windows::Storage::IStorageFile const& file) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDStorageFileHelper<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDStreamParser
    {
        WINRT_IMPL_AUTO(void) ParseData(array_view<uint8_t const> dataBytes) const;
        WINRT_IMPL_AUTO(uint32_t) GetStreamInformation(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType& streamType) const;
        WINRT_IMPL_AUTO(void) BeginOfStream() const;
        WINRT_IMPL_AUTO(void) EndOfStream() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier) Notifier() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDStreamParser>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier
    {
        WINRT_IMPL_AUTO(void) OnContentIDReceived(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const;
        WINRT_IMPL_AUTO(void) OnMediaStreamDescriptorCreated(param::vector<winrt::Windows::Media::Core::AudioStreamDescriptor> const& audioStreamDescriptors, param::vector<winrt::Windows::Media::Core::VideoStreamDescriptor> const& videoStreamDescriptors) const;
        WINRT_IMPL_AUTO(void) OnSampleParsed(uint32_t streamID, winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType const& streamType, winrt::Windows::Media::Core::MediaStreamSample const& streamSample, int64_t pts, winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat const& ccFormat, array_view<uint8_t const> ccDataBytes) const;
        WINRT_IMPL_AUTO(void) OnBeginSetupDecryptor(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::guid const& keyID, array_view<uint8_t const> proBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDTCPMessengerFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger) CreateInstance(param::hstring const& remoteHostName, uint32_t remoteHostPort) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDTCPMessengerFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDCertificateType) CertificateType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDCertificatePlatformID) PlatformIdentifier() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<winrt::Windows::Media::Protection::PlayReady::NDCertificateFeature>) SupportedFeatures() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SecurityLevel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SecurityVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) ExpirationDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) ClientID() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) ModelDigest() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ModelManufacturerName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ModelName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ModelNumber() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) KeyId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) KeyIdString() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) LicenseAcquisitionUrl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) LicenseAcquisitionUserInterfaceUrl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainServiceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm) EncryptionType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CustomAttributes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup) DecryptorSetup() const;
        WINRT_IMPL_AUTO(com_array<uint8_t>) GetSerializedHeader() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) HeaderWithEmbeddedUpdates() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<winrt::guid>) KeyIds() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<hstring>) KeyIdStrings() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader2<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) CreateInstanceFromWindowsMediaDrmHeader(array_view<uint8_t const> headerBytes, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) CreateInstanceFromComponents(winrt::guid const& contentKeyId, param::hstring const& contentKeyIdString, winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) CreateInstanceFromPlayReadyHeader(array_view<uint8_t const> headerBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) CreateInstanceFromComponents2(uint32_t dwFlags, array_view<winrt::guid const> contentKeyIds, array_view<hstring const> contentKeyIdStrings, winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory2<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyContentResolver
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest) ServiceRequest(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyContentResolver<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) AccountId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ServiceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Revision() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FriendlyName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) DomainJoinUrl() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainIterableFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable) CreateInstance(winrt::guid const& domainAccountId) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainIterableFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainAccountId() const;
        WINRT_IMPL_AUTO(void) DomainAccountId(winrt::guid const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DomainFriendlyName() const;
        WINRT_IMPL_AUTO(void) DomainFriendlyName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainServiceId() const;
        WINRT_IMPL_AUTO(void) DomainServiceId(winrt::guid const& value) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainAccountId() const;
        WINRT_IMPL_AUTO(void) DomainAccountId(winrt::guid const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainServiceId() const;
        WINRT_IMPL_AUTO(void) DomainServiceId(winrt::guid const& value) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyITADataGenerator
    {
        WINRT_IMPL_AUTO(com_array<uint8_t>) GenerateData(winrt::guid const& guidCPSystemId, uint32_t countOfStreams, winrt::Windows::Foundation::Collections::IPropertySet const& configuration, winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataFormat const& format) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyITADataGenerator<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyIndividualizationServiceRequest
    {
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyIndividualizationServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) FullyEvaluated() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) UsableForPlay() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) ExpirationDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExpireAfterFirstPlay() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainAccountID() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ChainDepth() const;
        WINRT_IMPL_AUTO(winrt::guid) GetKIDAtChainDepth(uint32_t chainDepth) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) SecureStopId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SecurityLevel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) InMemoryOnly() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ExpiresInRealTime() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) ContentHeader() const;
        WINRT_IMPL_AUTO(void) ContentHeader(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainServiceId() const;
        WINRT_IMPL_AUTO(void) DomainServiceId(winrt::guid const& value) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) SessionId() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest2<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable) CreateLicenseIterable(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest3<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseIterableFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable) CreateInstance(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseIterableFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseManagement
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeleteLicenses(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseManagement<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest) CreateLAServiceRequest() const;
        WINRT_IMPL_AUTO(void) ConfigureMediaProtectionManager(winrt::Windows::Media::Protection::MediaProtectionManager const& mpm) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable) CreateLicenseIterable(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession2<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSessionFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession) CreateInstance(winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSessionFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyMeteringReportServiceRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) MeteringCertificate() const;
        WINRT_IMPL_AUTO(void) MeteringCertificate(array_view<uint8_t const> meteringCertBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyMeteringReportServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyRevocationServiceRequest
    {
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyRevocationServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopIterableFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable) CreateInstance(array_view<uint8_t const> publisherCertBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopIterableFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) SessionID() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) StartTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) UpdateTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Stopped() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint8_t>) PublisherCertificate() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequestFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest) CreateInstance(array_view<uint8_t const> publisherCertBytes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest) CreateInstanceFromSessionID(winrt::guid const& sessionID, array_view<uint8_t const> publisherCertBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequestFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
        WINRT_IMPL_AUTO(void) Uri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResponseCustomData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ChallengeCustomData() const;
        WINRT_IMPL_AUTO(void) ChallengeCustomData(param::hstring const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) BeginServiceRequest() const;
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest) NextServiceRequest() const;
        WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage) GenerateManualEnablingChallenge() const;
        WINRT_IMPL_AUTO(winrt::hresult) ProcessManualEnablingResponse(array_view<uint8_t const> responseBytes) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage
    {
        WINRT_IMPL_AUTO(com_array<uint8_t>) GetMessageBody() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) MessageHeaders() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainJoinServiceRequestType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) DomainLeaveServiceRequestType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) IndividualizationServiceRequestType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) LicenseAcquirerServiceRequestType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) MeteringReportServiceRequestType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) RevocationServiceRequestType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) MediaProtectionSystemId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) PlayReadySecurityVersion() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) PlayReadyCertificateSecurityLevel() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) SecureStopServiceRequestType() const;
        WINRT_IMPL_AUTO(bool) CheckSupportedHardware(winrt::Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const& hwdrmFeature) const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) InputTrustAuthorityToCreate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ProtectionSystemId() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) HardwareDRMDisabledAtTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) HardwareDRMDisabledUntilTime() const;
        WINRT_IMPL_AUTO(void) ResetHardwareDRMDisabled() const;
    };
    template <> struct consume<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5>
    {
        template <typename D> using type = consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>;
    };
}
#endif
