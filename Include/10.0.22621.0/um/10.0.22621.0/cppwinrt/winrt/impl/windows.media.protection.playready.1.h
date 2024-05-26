// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Protection_PlayReady_1_H
#define WINRT_Windows_Media_Protection_PlayReady_1_H
#include "winrt/impl/Windows.Media.Protection.0.h"
#include "winrt/impl/Windows.Media.Protection.PlayReady.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady
{
    struct __declspec(empty_bases) INDClient :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDClient>
    {
        INDClient(std::nullptr_t = nullptr) noexcept {}
        INDClient(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDClientFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDClientFactory>
    {
        INDClientFactory(std::nullptr_t = nullptr) noexcept {}
        INDClientFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDClosedCaptionDataReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDClosedCaptionDataReceivedEventArgs>
    {
        INDClosedCaptionDataReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INDClosedCaptionDataReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDCustomData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDCustomData>
    {
        INDCustomData(std::nullptr_t = nullptr) noexcept {}
        INDCustomData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDCustomDataFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDCustomDataFactory>
    {
        INDCustomDataFactory(std::nullptr_t = nullptr) noexcept {}
        INDCustomDataFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDDownloadEngine :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDDownloadEngine>
    {
        INDDownloadEngine(std::nullptr_t = nullptr) noexcept {}
        INDDownloadEngine(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDDownloadEngineNotifier :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDDownloadEngineNotifier>
    {
        INDDownloadEngineNotifier(std::nullptr_t = nullptr) noexcept {}
        INDDownloadEngineNotifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDLicenseFetchCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDLicenseFetchCompletedEventArgs>
    {
        INDLicenseFetchCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INDLicenseFetchCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDLicenseFetchDescriptor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDLicenseFetchDescriptor>
    {
        INDLicenseFetchDescriptor(std::nullptr_t = nullptr) noexcept {}
        INDLicenseFetchDescriptor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDLicenseFetchDescriptorFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDLicenseFetchDescriptorFactory>
    {
        INDLicenseFetchDescriptorFactory(std::nullptr_t = nullptr) noexcept {}
        INDLicenseFetchDescriptorFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDLicenseFetchResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDLicenseFetchResult>
    {
        INDLicenseFetchResult(std::nullptr_t = nullptr) noexcept {}
        INDLicenseFetchResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDMessenger :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDMessenger>
    {
        INDMessenger(std::nullptr_t = nullptr) noexcept {}
        INDMessenger(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDProximityDetectionCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDProximityDetectionCompletedEventArgs>
    {
        INDProximityDetectionCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INDProximityDetectionCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDRegistrationCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDRegistrationCompletedEventArgs>
    {
        INDRegistrationCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INDRegistrationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDSendResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDSendResult>
    {
        INDSendResult(std::nullptr_t = nullptr) noexcept {}
        INDSendResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDStartResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDStartResult>
    {
        INDStartResult(std::nullptr_t = nullptr) noexcept {}
        INDStartResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDStorageFileHelper :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDStorageFileHelper>
    {
        INDStorageFileHelper(std::nullptr_t = nullptr) noexcept {}
        INDStorageFileHelper(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDStreamParser :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDStreamParser>
    {
        INDStreamParser(std::nullptr_t = nullptr) noexcept {}
        INDStreamParser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDStreamParserNotifier :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDStreamParserNotifier>
    {
        INDStreamParserNotifier(std::nullptr_t = nullptr) noexcept {}
        INDStreamParserNotifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDTCPMessengerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDTCPMessengerFactory>
    {
        INDTCPMessengerFactory(std::nullptr_t = nullptr) noexcept {}
        INDTCPMessengerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INDTransmitterProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INDTransmitterProperties>
    {
        INDTransmitterProperties(std::nullptr_t = nullptr) noexcept {}
        INDTransmitterProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyContentHeader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyContentHeader>
    {
        IPlayReadyContentHeader(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyContentHeader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyContentHeader2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyContentHeader2>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>
    {
        IPlayReadyContentHeader2(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyContentHeader2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyContentHeaderFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyContentHeaderFactory>
    {
        IPlayReadyContentHeaderFactory(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyContentHeaderFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyContentHeaderFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyContentHeaderFactory2>
    {
        IPlayReadyContentHeaderFactory2(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyContentHeaderFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyContentResolver :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyContentResolver>
    {
        IPlayReadyContentResolver(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyContentResolver(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyDomain :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyDomain>
    {
        IPlayReadyDomain(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyDomain(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyDomainIterableFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyDomainIterableFactory>
    {
        IPlayReadyDomainIterableFactory(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyDomainIterableFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyDomainJoinServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyDomainJoinServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadyDomainJoinServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyDomainJoinServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyDomainLeaveServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyDomainLeaveServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadyDomainLeaveServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyDomainLeaveServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyITADataGenerator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyITADataGenerator>
    {
        IPlayReadyITADataGenerator(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyITADataGenerator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyIndividualizationServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyIndividualizationServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadyIndividualizationServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyIndividualizationServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicense :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicense>
    {
        IPlayReadyLicense(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicense(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicense2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicense2>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>
    {
        IPlayReadyLicense2(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicense2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseAcquisitionServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseAcquisitionServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadyLicenseAcquisitionServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseAcquisitionServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseAcquisitionServiceRequest2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseAcquisitionServiceRequest2>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>
    {
        IPlayReadyLicenseAcquisitionServiceRequest2(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseAcquisitionServiceRequest2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseAcquisitionServiceRequest3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseAcquisitionServiceRequest3>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>
    {
        IPlayReadyLicenseAcquisitionServiceRequest3(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseAcquisitionServiceRequest3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseIterableFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseIterableFactory>
    {
        IPlayReadyLicenseIterableFactory(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseIterableFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseManagement :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseManagement>
    {
        IPlayReadyLicenseManagement(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseManagement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseSession>
    {
        IPlayReadyLicenseSession(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseSession2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseSession2>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>
    {
        IPlayReadyLicenseSession2(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseSession2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyLicenseSessionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyLicenseSessionFactory>
    {
        IPlayReadyLicenseSessionFactory(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyLicenseSessionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyMeteringReportServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyMeteringReportServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadyMeteringReportServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyMeteringReportServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyRevocationServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyRevocationServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadyRevocationServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyRevocationServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadySecureStopIterableFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadySecureStopIterableFactory>
    {
        IPlayReadySecureStopIterableFactory(std::nullptr_t = nullptr) noexcept {}
        IPlayReadySecureStopIterableFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadySecureStopServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadySecureStopServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        IPlayReadySecureStopServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadySecureStopServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadySecureStopServiceRequestFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadySecureStopServiceRequestFactory>
    {
        IPlayReadySecureStopServiceRequestFactory(std::nullptr_t = nullptr) noexcept {}
        IPlayReadySecureStopServiceRequestFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyServiceRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyServiceRequest>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest>
    {
        IPlayReadyServiceRequest(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyServiceRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadySoapMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadySoapMessage>
    {
        IPlayReadySoapMessage(std::nullptr_t = nullptr) noexcept {}
        IPlayReadySoapMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyStatics>
    {
        IPlayReadyStatics(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyStatics2>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics>
    {
        IPlayReadyStatics2(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyStatics3>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2>
    {
        IPlayReadyStatics3(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyStatics4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyStatics4>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3>
    {
        IPlayReadyStatics4(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyStatics4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPlayReadyStatics5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPlayReadyStatics5>,
        impl::require<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4>
    {
        IPlayReadyStatics5(std::nullptr_t = nullptr) noexcept {}
        IPlayReadyStatics5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
