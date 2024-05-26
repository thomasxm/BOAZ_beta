// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Protection_PlayReady_H
#define WINRT_Windows_Media_Protection_PlayReady_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.Protection.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Media.Protection.PlayReady.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->add_RegistrationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RegistrationCompleted_revoker>(this, RegistrationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDClient<D>::RegistrationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->remove_RegistrationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->add_ProximityDetectionCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ProximityDetectionCompleted_revoker>(this, ProximityDetectionCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ProximityDetectionCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->remove_ProximityDetectionCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->add_LicenseFetchCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LicenseFetchCompleted_revoker>(this, LicenseFetchCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->remove_LicenseFetchCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->add_ReRegistrationNeeded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ReRegistrationNeeded_revoker>(this, ReRegistrationNeeded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationNeeded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->remove_ReRegistrationNeeded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->add_ClosedCaptionDataReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived_revoker consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ClosedCaptionDataReceived_revoker>(this, ClosedCaptionDataReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ClosedCaptionDataReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->remove_ClosedCaptionDataReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDStartResult>) consume_Windows_Media_Protection_PlayReady_INDClient<D>::StartAsync(winrt::Windows::Foundation::Uri const& contentUrl, uint32_t startAsyncOptions, winrt::Windows::Media::Protection::PlayReady::INDCustomData const& registrationCustomData, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->StartAsync(*(void**)(&contentUrl), startAsyncOptions, *(void**)(&registrationCustomData), *(void**)(&licenseFetchDescriptor), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDStartResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>) consume_Windows_Media_Protection_PlayReady_INDClient<D>::LicenseFetchAsync(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->LicenseFetchAsync(*(void**)(&licenseFetchDescriptor), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Protection_PlayReady_INDClient<D>::ReRegistrationAsync(winrt::Windows::Media::Protection::PlayReady::INDCustomData const& registrationCustomData) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->ReRegistrationAsync(*(void**)(&registrationCustomData), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDClient<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClient)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDClient) consume_Windows_Media_Protection_PlayReady_INDClientFactory<D>::CreateInstance(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine const& downloadEngine, winrt::Windows::Media::Protection::PlayReady::INDStreamParser const& streamParser, winrt::Windows::Media::Protection::PlayReady::INDMessenger const& pMessenger) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClientFactory)->CreateInstance(*(void**)(&downloadEngine), *(void**)(&streamParser), *(void**)(&pMessenger), &instance));
        return winrt::Windows::Media::Protection::PlayReady::NDClient{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat) consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>::ClosedCaptionDataFormat() const
    {
        winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat ccForamt{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs)->get_ClosedCaptionDataFormat(reinterpret_cast<int32_t*>(&ccForamt)));
        return ccForamt;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>::PresentationTimestamp() const
    {
        int64_t presentationTimestamp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs)->get_PresentationTimestamp(&presentationTimestamp));
        return presentationTimestamp;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDClosedCaptionDataReceivedEventArgs<D>::ClosedCaptionData() const
    {
        uint32_t ccDataBytes_impl_size{};
        uint8_t* ccDataBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs)->get_ClosedCaptionData(&ccDataBytes_impl_size, &ccDataBytes));
        return com_array<uint8_t>{ ccDataBytes, ccDataBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDCustomData<D>::CustomDataTypeID() const
    {
        uint32_t customDataTypeIDBytes_impl_size{};
        uint8_t* customDataTypeIDBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDCustomData)->get_CustomDataTypeID(&customDataTypeIDBytes_impl_size, &customDataTypeIDBytes));
        return com_array<uint8_t>{ customDataTypeIDBytes, customDataTypeIDBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDCustomData<D>::CustomData() const
    {
        uint32_t customDataBytes_impl_size{};
        uint8_t* customDataBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDCustomData)->get_CustomData(&customDataBytes_impl_size, &customDataBytes));
        return com_array<uint8_t>{ customDataBytes, customDataBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDCustomData) consume_Windows_Media_Protection_PlayReady_INDCustomDataFactory<D>::CreateInstance(array_view<uint8_t const> customDataTypeIDBytes, array_view<uint8_t const> customDataBytes) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory)->CreateInstance(customDataTypeIDBytes.size(), get_abi(customDataTypeIDBytes), customDataBytes.size(), get_abi(customDataBytes), &instance));
        return winrt::Windows::Media::Protection::PlayReady::NDCustomData{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Open(winrt::Windows::Foundation::Uri const& uri, array_view<uint8_t const> sessionIDBytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->Open(*(void**)(&uri), sessionIDBytes.size(), get_abi(sessionIDBytes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Seek(winrt::Windows::Foundation::TimeSpan const& startPosition) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->Seek(impl::bind_in(startPosition)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::CanSeek() const
    {
        bool canSeek{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_CanSeek(&canSeek));
        return canSeek;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::BufferFullMinThresholdInSamples() const
    {
        uint32_t bufferFullMinThreshold{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_BufferFullMinThresholdInSamples(&bufferFullMinThreshold));
        return bufferFullMinThreshold;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::BufferFullMaxThresholdInSamples() const
    {
        uint32_t bufferFullMaxThreshold{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_BufferFullMaxThresholdInSamples(&bufferFullMaxThreshold));
        return bufferFullMaxThreshold;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier) consume_Windows_Media_Protection_PlayReady_INDDownloadEngine<D>::Notifier() const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine)->get_Notifier(&instance));
        return winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnStreamOpened() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnStreamOpened());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnPlayReadyObjectReceived(array_view<uint8_t const> dataBytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnPlayReadyObjectReceived(dataBytes.size(), get_abi(dataBytes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnContentIDReceived(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnContentIDReceived(*(void**)(&licenseFetchDescriptor)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnDataReceived(array_view<uint8_t const> dataBytes, uint32_t bytesReceived) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnDataReceived(dataBytes.size(), get_abi(dataBytes), bytesReceived));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnEndOfStream() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnEndOfStream());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDDownloadEngineNotifier<D>::OnNetworkError() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier)->OnNetworkError());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchCompletedEventArgs<D>::ResponseCustomData() const
    {
        void* customData{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs)->get_ResponseCustomData(&customData));
        return winrt::Windows::Media::Protection::PlayReady::INDCustomData{ customData, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDContentIDType) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::ContentIDType() const
    {
        winrt::Windows::Media::Protection::PlayReady::NDContentIDType contentIDType{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->get_ContentIDType(reinterpret_cast<int32_t*>(&contentIDType)));
        return contentIDType;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::ContentID() const
    {
        uint32_t contentIDBytes_impl_size{};
        uint8_t* contentIDBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->get_ContentID(&contentIDBytes_impl_size, &contentIDBytes));
        return com_array<uint8_t>{ contentIDBytes, contentIDBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::LicenseFetchChallengeCustomData() const
    {
        void* licenseFetchChallengeCustomData{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->get_LicenseFetchChallengeCustomData(&licenseFetchChallengeCustomData));
        return winrt::Windows::Media::Protection::PlayReady::INDCustomData{ licenseFetchChallengeCustomData, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptor<D>::LicenseFetchChallengeCustomData(winrt::Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor)->put_LicenseFetchChallengeCustomData(*(void**)(&licenseFetchChallengeCustomData)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchDescriptorFactory<D>::CreateInstance(winrt::Windows::Media::Protection::PlayReady::NDContentIDType const& contentIDType, array_view<uint8_t const> contentIDBytes, winrt::Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory)->CreateInstance(static_cast<int32_t>(contentIDType), contentIDBytes.size(), get_abi(contentIDBytes), *(void**)(&licenseFetchChallengeCustomData), &instance));
        return winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) consume_Windows_Media_Protection_PlayReady_INDLicenseFetchResult<D>::ResponseCustomData() const
    {
        void* customData{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult)->get_ResponseCustomData(&customData));
        return winrt::Windows::Media::Protection::PlayReady::INDCustomData{ customData, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendRegistrationRequestAsync(array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDMessenger)->SendRegistrationRequestAsync(sessionIDBytes.size(), get_abi(sessionIDBytes), challengeDataBytes.size(), get_abi(challengeDataBytes), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendProximityDetectionStartAsync(winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType const& pdType, array_view<uint8_t const> transmitterChannelBytes, array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDMessenger)->SendProximityDetectionStartAsync(static_cast<int32_t>(pdType), transmitterChannelBytes.size(), get_abi(transmitterChannelBytes), sessionIDBytes.size(), get_abi(sessionIDBytes), challengeDataBytes.size(), get_abi(challengeDataBytes), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendProximityDetectionResponseAsync(winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType const& pdType, array_view<uint8_t const> transmitterChannelBytes, array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> responseDataBytes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDMessenger)->SendProximityDetectionResponseAsync(static_cast<int32_t>(pdType), transmitterChannelBytes.size(), get_abi(transmitterChannelBytes), sessionIDBytes.size(), get_abi(sessionIDBytes), responseDataBytes.size(), get_abi(responseDataBytes), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>) consume_Windows_Media_Protection_PlayReady_INDMessenger<D>::SendLicenseFetchRequestAsync(array_view<uint8_t const> sessionIDBytes, array_view<uint8_t const> challengeDataBytes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDMessenger)->SendLicenseFetchRequestAsync(sessionIDBytes.size(), get_abi(sessionIDBytes), challengeDataBytes.size(), get_abi(challengeDataBytes), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_INDProximityDetectionCompletedEventArgs<D>::ProximityDetectionRetryCount() const
    {
        uint32_t retryCount{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs)->get_ProximityDetectionRetryCount(&retryCount));
        return retryCount;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDCustomData) consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::ResponseCustomData() const
    {
        void* customData{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->get_ResponseCustomData(&customData));
        return winrt::Windows::Media::Protection::PlayReady::INDCustomData{ customData, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties) consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::TransmitterProperties() const
    {
        void* transmitterProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->get_TransmitterProperties(&transmitterProperties));
        return winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties{ transmitterProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::TransmitterCertificateAccepted() const
    {
        bool acceptpt{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->get_TransmitterCertificateAccepted(&acceptpt));
        return acceptpt;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDRegistrationCompletedEventArgs<D>::TransmitterCertificateAccepted(bool accept) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs)->put_TransmitterCertificateAccepted(accept));
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDSendResult<D>::Response() const
    {
        uint32_t responseDataBytes_impl_size{};
        uint8_t* responseDataBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDSendResult)->get_Response(&responseDataBytes_impl_size, &responseDataBytes));
        return com_array<uint8_t>{ responseDataBytes, responseDataBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSource) consume_Windows_Media_Protection_PlayReady_INDStartResult<D>::MediaStreamSource() const
    {
        void* mediaStreamSource{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStartResult)->get_MediaStreamSource(&mediaStreamSource));
        return winrt::Windows::Media::Core::MediaStreamSource{ mediaStreamSource, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Media_Protection_PlayReady_INDStorageFileHelper<D>::GetFileURLs(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* fileURLs{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper)->GetFileURLs(*(void**)(&file), &fileURLs));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ fileURLs, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::ParseData(array_view<uint8_t const> dataBytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParser)->ParseData(dataBytes.size(), get_abi(dataBytes)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::GetStreamInformation(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType& streamType) const
    {
        uint32_t streamID{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParser)->GetStreamInformation(*(void**)(&descriptor), reinterpret_cast<int32_t*>(&streamType), &streamID));
        return streamID;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::BeginOfStream() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParser)->BeginOfStream());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::EndOfStream() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParser)->EndOfStream());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier) consume_Windows_Media_Protection_PlayReady_INDStreamParser<D>::Notifier() const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParser)->get_Notifier(&instance));
        return winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnContentIDReceived(winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const& licenseFetchDescriptor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnContentIDReceived(*(void**)(&licenseFetchDescriptor)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnMediaStreamDescriptorCreated(param::vector<winrt::Windows::Media::Core::AudioStreamDescriptor> const& audioStreamDescriptors, param::vector<winrt::Windows::Media::Core::VideoStreamDescriptor> const& videoStreamDescriptors) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnMediaStreamDescriptorCreated(*(void**)(&audioStreamDescriptors), *(void**)(&videoStreamDescriptors)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnSampleParsed(uint32_t streamID, winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType const& streamType, winrt::Windows::Media::Core::MediaStreamSample const& streamSample, int64_t pts, winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat const& ccFormat, array_view<uint8_t const> ccDataBytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnSampleParsed(streamID, static_cast<int32_t>(streamType), *(void**)(&streamSample), pts, static_cast<int32_t>(ccFormat), ccDataBytes.size(), get_abi(ccDataBytes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_INDStreamParserNotifier<D>::OnBeginSetupDecryptor(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::guid const& keyID, array_view<uint8_t const> proBytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier)->OnBeginSetupDecryptor(*(void**)(&descriptor), impl::bind_in(keyID), proBytes.size(), get_abi(proBytes)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger) consume_Windows_Media_Protection_PlayReady_INDTCPMessengerFactory<D>::CreateInstance(param::hstring const& remoteHostName, uint32_t remoteHostPort) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory)->CreateInstance(*(void**)(&remoteHostName), remoteHostPort, &instance));
        return winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDCertificateType) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::CertificateType() const
    {
        winrt::Windows::Media::Protection::PlayReady::NDCertificateType type{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_CertificateType(reinterpret_cast<int32_t*>(&type)));
        return type;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::NDCertificatePlatformID) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::PlatformIdentifier() const
    {
        winrt::Windows::Media::Protection::PlayReady::NDCertificatePlatformID identifier{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_PlatformIdentifier(reinterpret_cast<int32_t*>(&identifier)));
        return identifier;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::Media::Protection::PlayReady::NDCertificateFeature>) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::SupportedFeatures() const
    {
        uint32_t featureSets_impl_size{};
        int32_t* featureSets{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_SupportedFeatures(&featureSets_impl_size, &featureSets));
        return com_array<winrt::Windows::Media::Protection::PlayReady::NDCertificateFeature>{ featureSets, featureSets_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::SecurityLevel() const
    {
        uint32_t level{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_SecurityLevel(&level));
        return level;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::SecurityVersion() const
    {
        uint32_t securityVersion{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_SecurityVersion(&securityVersion));
        return securityVersion;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ExpirationDate() const
    {
        winrt::Windows::Foundation::DateTime expirationDate{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ExpirationDate(put_abi(expirationDate)));
        return expirationDate;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ClientID() const
    {
        uint32_t clientIDBytes_impl_size{};
        uint8_t* clientIDBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ClientID(&clientIDBytes_impl_size, &clientIDBytes));
        return com_array<uint8_t>{ clientIDBytes, clientIDBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelDigest() const
    {
        uint32_t modelDigestBytes_impl_size{};
        uint8_t* modelDigestBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelDigest(&modelDigestBytes_impl_size, &modelDigestBytes));
        return com_array<uint8_t>{ modelDigestBytes, modelDigestBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelManufacturerName() const
    {
        void* modelManufacturerName{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelManufacturerName(&modelManufacturerName));
        return hstring{ modelManufacturerName, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelName() const
    {
        void* modelName{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelName(&modelName));
        return hstring{ modelName, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_INDTransmitterProperties<D>::ModelNumber() const
    {
        void* modelNumber{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties)->get_ModelNumber(&modelNumber));
        return hstring{ modelNumber, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::KeyId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_KeyId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::KeyIdString() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_KeyIdString(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::LicenseAcquisitionUrl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_LicenseAcquisitionUrl(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::LicenseAcquisitionUserInterfaceUrl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_LicenseAcquisitionUserInterfaceUrl(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::DomainServiceId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_DomainServiceId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::EncryptionType() const
    {
        winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_EncryptionType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::CustomAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_CustomAttributes(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::DecryptorSetup() const
    {
        winrt::Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_DecryptorSetup(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::GetSerializedHeader() const
    {
        uint32_t headerBytes_impl_size{};
        uint8_t* headerBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->GetSerializedHeader(&headerBytes_impl_size, &headerBytes));
        return com_array<uint8_t>{ headerBytes, headerBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader<D>::HeaderWithEmbeddedUpdates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader)->get_HeaderWithEmbeddedUpdates(&value));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::guid>) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader2<D>::KeyIds() const
    {
        uint32_t contentKeyIds_impl_size{};
        winrt::guid* contentKeyIds{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2)->get_KeyIds(&contentKeyIds_impl_size, &contentKeyIds));
        return com_array<winrt::guid>{ contentKeyIds, contentKeyIds_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<hstring>) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeader2<D>::KeyIdStrings() const
    {
        uint32_t contentKeyIdStrings_impl_size{};
        void** contentKeyIdStrings{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2)->get_KeyIdStrings(&contentKeyIdStrings_impl_size, &contentKeyIdStrings));
        return com_array<hstring>{ contentKeyIdStrings, contentKeyIdStrings_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>::CreateInstanceFromWindowsMediaDrmHeader(array_view<uint8_t const> headerBytes, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory)->CreateInstanceFromWindowsMediaDrmHeader(headerBytes.size(), get_abi(headerBytes), *(void**)(&licenseAcquisitionUrl), *(void**)(&licenseAcquisitionUserInterfaceUrl), *(void**)(&customAttributes), impl::bind_in(domainServiceId), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>::CreateInstanceFromComponents(winrt::guid const& contentKeyId, param::hstring const& contentKeyIdString, winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory)->CreateInstanceFromComponents(impl::bind_in(contentKeyId), *(void**)(&contentKeyIdString), static_cast<int32_t>(contentEncryptionAlgorithm), *(void**)(&licenseAcquisitionUrl), *(void**)(&licenseAcquisitionUserInterfaceUrl), *(void**)(&customAttributes), impl::bind_in(domainServiceId), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory<D>::CreateInstanceFromPlayReadyHeader(array_view<uint8_t const> headerBytes) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory)->CreateInstanceFromPlayReadyHeader(headerBytes.size(), get_abi(headerBytes), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentHeaderFactory2<D>::CreateInstanceFromComponents2(uint32_t dwFlags, array_view<winrt::guid const> contentKeyIds, array_view<hstring const> contentKeyIdStrings, winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2)->CreateInstanceFromComponents2(dwFlags, contentKeyIds.size(), get_abi(contentKeyIds), contentKeyIdStrings.size(), get_abi(contentKeyIdStrings), static_cast<int32_t>(contentEncryptionAlgorithm), *(void**)(&licenseAcquisitionUrl), *(void**)(&licenseAcquisitionUserInterfaceUrl), *(void**)(&customAttributes), impl::bind_in(domainServiceId), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest) consume_Windows_Media_Protection_PlayReady_IPlayReadyContentResolver<D>::ServiceRequest(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader) const
    {
        void* serviceRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver)->ServiceRequest(*(void**)(&contentHeader), &serviceRequest));
        return winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest{ serviceRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::AccountId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_AccountId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::ServiceId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_ServiceId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::Revision() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_Revision(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::FriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_FriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomain<D>::DomainJoinUrl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain)->get_DomainJoinUrl(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainIterableFactory<D>::CreateInstance(winrt::guid const& domainAccountId) const
    {
        void* domainIterable{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory)->CreateInstance(impl::bind_in(domainAccountId), &domainIterable));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable{ domainIterable, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainAccountId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->get_DomainAccountId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainAccountId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->put_DomainAccountId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainFriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->get_DomainFriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainFriendlyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->put_DomainFriendlyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainServiceId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->get_DomainServiceId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainJoinServiceRequest<D>::DomainServiceId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest)->put_DomainServiceId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainAccountId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->get_DomainAccountId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainAccountId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->put_DomainAccountId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainServiceId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->get_DomainServiceId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyDomainLeaveServiceRequest<D>::DomainServiceId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest)->put_DomainServiceId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_IPlayReadyITADataGenerator<D>::GenerateData(winrt::guid const& guidCPSystemId, uint32_t countOfStreams, winrt::Windows::Foundation::Collections::IPropertySet const& configuration, winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataFormat const& format) const
    {
        uint32_t dataBytes_impl_size{};
        uint8_t* dataBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator)->GenerateData(impl::bind_in(guidCPSystemId), countOfStreams, *(void**)(&configuration), static_cast<int32_t>(format), &dataBytes_impl_size, &dataBytes));
        return com_array<uint8_t>{ dataBytes, dataBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::FullyEvaluated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_FullyEvaluated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::UsableForPlay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_UsableForPlay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::ExpirationDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_ExpirationDate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::ExpireAfterFirstPlay() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_ExpireAfterFirstPlay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::DomainAccountID() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_DomainAccountID(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::ChainDepth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->get_ChainDepth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense<D>::GetKIDAtChainDepth(uint32_t chainDepth) const
    {
        winrt::guid kid{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense)->GetKIDAtChainDepth(chainDepth, put_abi(kid)));
        return kid;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::SecureStopId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_SecureStopId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::SecurityLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_SecurityLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::InMemoryOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_InMemoryOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicense2<D>::ExpiresInRealTime() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2)->get_ExpiresInRealTime(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::ContentHeader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->get_ContentHeader(&value));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::ContentHeader(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->put_ContentHeader(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::DomainServiceId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->get_DomainServiceId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest<D>::DomainServiceId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest)->put_DomainServiceId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest2<D>::SessionId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2)->get_SessionId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseAcquisitionServiceRequest3<D>::CreateLicenseIterable(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3)->CreateLicenseIterable(*(void**)(&contentHeader), fullyEvaluated, &result));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseIterableFactory<D>::CreateInstance(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory)->CreateInstance(*(void**)(&contentHeader), fullyEvaluated, &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseManagement<D>::DeleteLicenses(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement)->DeleteLicenses(*(void**)(&contentHeader), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession<D>::CreateLAServiceRequest() const
    {
        void* serviceRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession)->CreateLAServiceRequest(&serviceRequest));
        return winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest{ serviceRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession<D>::ConfigureMediaProtectionManager(winrt::Windows::Media::Protection::MediaProtectionManager const& mpm) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession)->ConfigureMediaProtectionManager(*(void**)(&mpm)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSession2<D>::CreateLicenseIterable(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) const
    {
        void* licenseIterable{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2)->CreateLicenseIterable(*(void**)(&contentHeader), fullyEvaluated, &licenseIterable));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable{ licenseIterable, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession) consume_Windows_Media_Protection_PlayReady_IPlayReadyLicenseSessionFactory<D>::CreateInstance(winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory)->CreateInstance(*(void**)(&configuration), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_IPlayReadyMeteringReportServiceRequest<D>::MeteringCertificate() const
    {
        uint32_t meteringCertBytes_impl_size{};
        uint8_t* meteringCertBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest)->get_MeteringCertificate(&meteringCertBytes_impl_size, &meteringCertBytes));
        return com_array<uint8_t>{ meteringCertBytes, meteringCertBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyMeteringReportServiceRequest<D>::MeteringCertificate(array_view<uint8_t const> meteringCertBytes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest)->put_MeteringCertificate(meteringCertBytes.size(), get_abi(meteringCertBytes)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopIterableFactory<D>::CreateInstance(array_view<uint8_t const> publisherCertBytes) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory)->CreateInstance(publisherCertBytes.size(), get_abi(publisherCertBytes), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::SessionID() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_SessionID(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::StartTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_StartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::UpdateTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_UpdateTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::Stopped() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_Stopped(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequest<D>::PublisherCertificate() const
    {
        uint32_t publisherCertBytes_impl_size{};
        uint8_t* publisherCertBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest)->get_PublisherCertificate(&publisherCertBytes_impl_size, &publisherCertBytes));
        return com_array<uint8_t>{ publisherCertBytes, publisherCertBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequestFactory<D>::CreateInstance(array_view<uint8_t const> publisherCertBytes) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory)->CreateInstance(publisherCertBytes.size(), get_abi(publisherCertBytes), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest) consume_Windows_Media_Protection_PlayReady_IPlayReadySecureStopServiceRequestFactory<D>::CreateInstanceFromSessionID(winrt::guid const& sessionID, array_view<uint8_t const> publisherCertBytes) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory)->CreateInstanceFromSessionID(impl::bind_in(sessionID), publisherCertBytes.size(), get_abi(publisherCertBytes), &instance));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::Uri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->put_Uri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ResponseCustomData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->get_ResponseCustomData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ChallengeCustomData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->get_ChallengeCustomData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ChallengeCustomData(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->put_ChallengeCustomData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::BeginServiceRequest() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->BeginServiceRequest(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::NextServiceRequest() const
    {
        void* serviceRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->NextServiceRequest(&serviceRequest));
        return winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest{ serviceRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::GenerateManualEnablingChallenge() const
    {
        void* challengeMessage{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->GenerateManualEnablingChallenge(&challengeMessage));
        return winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage{ challengeMessage, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Protection_PlayReady_IPlayReadyServiceRequest<D>::ProcessManualEnablingResponse(array_view<uint8_t const> responseBytes) const
    {
        winrt::hresult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest)->ProcessManualEnablingResponse(responseBytes.size(), get_abi(responseBytes), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>::GetMessageBody() const
    {
        uint32_t messageBodyBytes_impl_size{};
        uint8_t* messageBodyBytes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage)->GetMessageBody(&messageBodyBytes_impl_size, &messageBodyBytes));
        return com_array<uint8_t>{ messageBodyBytes, messageBodyBytes_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>::MessageHeaders() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage)->get_MessageHeaders(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Protection_PlayReady_IPlayReadySoapMessage<D>::Uri() const
    {
        void* messageUri{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage)->get_Uri(&messageUri));
        return winrt::Windows::Foundation::Uri{ messageUri, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::DomainJoinServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_DomainJoinServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::DomainLeaveServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_DomainLeaveServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::IndividualizationServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_IndividualizationServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::LicenseAcquirerServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_LicenseAcquirerServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::MeteringReportServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_MeteringReportServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::RevocationServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_RevocationServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::MediaProtectionSystemId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_MediaProtectionSystemId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics<D>::PlayReadySecurityVersion() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics)->get_PlayReadySecurityVersion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics2<D>::PlayReadyCertificateSecurityLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2)->get_PlayReadyCertificateSecurityLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics3<D>::SecureStopServiceRequestType() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3)->get_SecureStopServiceRequestType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics3<D>::CheckSupportedHardware(winrt::Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const& hwdrmFeature) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3)->CheckSupportedHardware(static_cast<int32_t>(hwdrmFeature), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics4<D>::InputTrustAuthorityToCreate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4)->get_InputTrustAuthorityToCreate(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics4<D>::ProtectionSystemId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4)->get_ProtectionSystemId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>::HardwareDRMDisabledAtTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5)->get_HardwareDRMDisabledAtTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>::HardwareDRMDisabledUntilTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5)->get_HardwareDRMDisabledUntilTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_PlayReady_IPlayReadyStatics5<D>::ResetHardwareDRMDisabled() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5)->ResetHardwareDRMDisabled());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDClient> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDClient>
    {
        int32_t __stdcall add_RegistrationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RegistrationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RegistrationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegistrationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ProximityDetectionCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ProximityDetectionCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ProximityDetectionCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProximityDetectionCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_LicenseFetchCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LicenseFetchCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LicenseFetchCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LicenseFetchCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ReRegistrationNeeded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReRegistrationNeeded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReRegistrationNeeded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReRegistrationNeeded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ClosedCaptionDataReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ClosedCaptionDataReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::PlayReady::NDClient, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ClosedCaptionDataReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedCaptionDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall StartAsync(void* contentUrl, uint32_t startAsyncOptions, void* registrationCustomData, void* licenseFetchDescriptor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDStartResult>>(this->shim().StartAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&contentUrl), startAsyncOptions, *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDCustomData const*>(&registrationCustomData), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LicenseFetchAsync(void* licenseFetchDescriptor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>>(this->shim().LicenseFetchAsync(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReRegistrationAsync(void* registrationCustomData, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReRegistrationAsync(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDCustomData const*>(&registrationCustomData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDClientFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDClientFactory>
    {
        int32_t __stdcall CreateInstance(void* downloadEngine, void* streamParser, void* pMessenger, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::NDClient>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine const*>(&downloadEngine), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDStreamParser const*>(&streamParser), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDMessenger const*>(&pMessenger)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs>
    {
        int32_t __stdcall get_ClosedCaptionDataFormat(int32_t* ccForamt) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *ccForamt = detach_from<winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat>(this->shim().ClosedCaptionDataFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PresentationTimestamp(int64_t* presentationTimestamp) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *presentationTimestamp = detach_from<int64_t>(this->shim().PresentationTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedCaptionData(uint32_t* __ccDataBytesSize, uint8_t** ccDataBytes) noexcept final try
        {
            clear_abi(ccDataBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__ccDataBytesSize, *ccDataBytes) = detach_abi(this->shim().ClosedCaptionData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDCustomData> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDCustomData>
    {
        int32_t __stdcall get_CustomDataTypeID(uint32_t* __customDataTypeIDBytesSize, uint8_t** customDataTypeIDBytes) noexcept final try
        {
            clear_abi(customDataTypeIDBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__customDataTypeIDBytesSize, *customDataTypeIDBytes) = detach_abi(this->shim().CustomDataTypeID());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomData(uint32_t* __customDataBytesSize, uint8_t** customDataBytes) noexcept final try
        {
            clear_abi(customDataBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__customDataBytesSize, *customDataBytes) = detach_abi(this->shim().CustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory>
    {
        int32_t __stdcall CreateInstance(uint32_t __customDataTypeIDBytesSize, uint8_t* customDataTypeIDBytes, uint32_t __customDataBytesSize, uint8_t* customDataBytes, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::NDCustomData>(this->shim().CreateInstance(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(customDataTypeIDBytes), reinterpret_cast<uint8_t const *>(customDataTypeIDBytes) + __customDataTypeIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(customDataBytes), reinterpret_cast<uint8_t const *>(customDataBytes) + __customDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine>
    {
        int32_t __stdcall Open(void* uri, uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Open(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Pause() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resume() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Seek(int64_t startPosition) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Seek(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&startPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanSeek(bool* canSeek) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *canSeek = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BufferFullMinThresholdInSamples(uint32_t* bufferFullMinThreshold) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *bufferFullMinThreshold = detach_from<uint32_t>(this->shim().BufferFullMinThresholdInSamples());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BufferFullMaxThresholdInSamples(uint32_t* bufferFullMaxThreshold) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *bufferFullMaxThreshold = detach_from<uint32_t>(this->shim().BufferFullMaxThresholdInSamples());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Notifier(void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier>(this->shim().Notifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier>
    {
        int32_t __stdcall OnStreamOpened() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnStreamOpened();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnPlayReadyObjectReceived(uint32_t __dataBytesSize, uint8_t* dataBytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnPlayReadyObjectReceived(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(dataBytes), reinterpret_cast<uint8_t const *>(dataBytes) + __dataBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnContentIDReceived(void* licenseFetchDescriptor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnContentIDReceived(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnDataReceived(uint32_t __dataBytesSize, uint8_t* dataBytes, uint32_t bytesReceived) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnDataReceived(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(dataBytes), reinterpret_cast<uint8_t const *>(dataBytes) + __dataBytesSize), bytesReceived);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnEndOfStream() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnEndOfStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnNetworkError() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnNetworkError();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs>
    {
        int32_t __stdcall get_ResponseCustomData(void** customData) noexcept final try
        {
            clear_abi(customData);
            typename D::abi_guard guard(this->shim());
            *customData = detach_from<winrt::Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor>
    {
        int32_t __stdcall get_ContentIDType(int32_t* contentIDType) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *contentIDType = detach_from<winrt::Windows::Media::Protection::PlayReady::NDContentIDType>(this->shim().ContentIDType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentID(uint32_t* __contentIDBytesSize, uint8_t** contentIDBytes) noexcept final try
        {
            clear_abi(contentIDBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__contentIDBytesSize, *contentIDBytes) = detach_abi(this->shim().ContentID());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LicenseFetchChallengeCustomData(void** licenseFetchChallengeCustomData) noexcept final try
        {
            clear_abi(licenseFetchChallengeCustomData);
            typename D::abi_guard guard(this->shim());
            *licenseFetchChallengeCustomData = detach_from<winrt::Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().LicenseFetchChallengeCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LicenseFetchChallengeCustomData(void* licenseFetchChallengeCustomData) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LicenseFetchChallengeCustomData(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDCustomData const*>(&licenseFetchChallengeCustomData));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory>
    {
        int32_t __stdcall CreateInstance(int32_t contentIDType, uint32_t __contentIDBytesSize, uint8_t* contentIDBytes, void* licenseFetchChallengeCustomData, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::NDContentIDType const*>(&contentIDType), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(contentIDBytes), reinterpret_cast<uint8_t const *>(contentIDBytes) + __contentIDBytesSize), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDCustomData const*>(&licenseFetchChallengeCustomData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult>
    {
        int32_t __stdcall get_ResponseCustomData(void** customData) noexcept final try
        {
            clear_abi(customData);
            typename D::abi_guard guard(this->shim());
            *customData = detach_from<winrt::Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDMessenger> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDMessenger>
    {
        int32_t __stdcall SendRegistrationRequestAsync(uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __challengeDataBytesSize, uint8_t* challengeDataBytes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendRegistrationRequestAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(challengeDataBytes), reinterpret_cast<uint8_t const *>(challengeDataBytes) + __challengeDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendProximityDetectionStartAsync(int32_t pdType, uint32_t __transmitterChannelBytesSize, uint8_t* transmitterChannelBytes, uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __challengeDataBytesSize, uint8_t* challengeDataBytes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendProximityDetectionStartAsync(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType const*>(&pdType), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(transmitterChannelBytes), reinterpret_cast<uint8_t const *>(transmitterChannelBytes) + __transmitterChannelBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(challengeDataBytes), reinterpret_cast<uint8_t const *>(challengeDataBytes) + __challengeDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendProximityDetectionResponseAsync(int32_t pdType, uint32_t __transmitterChannelBytesSize, uint8_t* transmitterChannelBytes, uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __responseDataBytesSize, uint8_t* responseDataBytes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendProximityDetectionResponseAsync(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::NDProximityDetectionType const*>(&pdType), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(transmitterChannelBytes), reinterpret_cast<uint8_t const *>(transmitterChannelBytes) + __transmitterChannelBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseDataBytes), reinterpret_cast<uint8_t const *>(responseDataBytes) + __responseDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendLicenseFetchRequestAsync(uint32_t __sessionIDBytesSize, uint8_t* sessionIDBytes, uint32_t __challengeDataBytesSize, uint8_t* challengeDataBytes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::PlayReady::INDSendResult>>(this->shim().SendLicenseFetchRequestAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(sessionIDBytes), reinterpret_cast<uint8_t const *>(sessionIDBytes) + __sessionIDBytesSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(challengeDataBytes), reinterpret_cast<uint8_t const *>(challengeDataBytes) + __challengeDataBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs>
    {
        int32_t __stdcall get_ProximityDetectionRetryCount(uint32_t* retryCount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *retryCount = detach_from<uint32_t>(this->shim().ProximityDetectionRetryCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs>
    {
        int32_t __stdcall get_ResponseCustomData(void** customData) noexcept final try
        {
            clear_abi(customData);
            typename D::abi_guard guard(this->shim());
            *customData = detach_from<winrt::Windows::Media::Protection::PlayReady::INDCustomData>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransmitterProperties(void** transmitterProperties) noexcept final try
        {
            clear_abi(transmitterProperties);
            typename D::abi_guard guard(this->shim());
            *transmitterProperties = detach_from<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties>(this->shim().TransmitterProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransmitterCertificateAccepted(bool* acceptpt) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *acceptpt = detach_from<bool>(this->shim().TransmitterCertificateAccepted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransmitterCertificateAccepted(bool accept) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransmitterCertificateAccepted(accept);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDSendResult> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDSendResult>
    {
        int32_t __stdcall get_Response(uint32_t* __responseDataBytesSize, uint8_t** responseDataBytes) noexcept final try
        {
            clear_abi(responseDataBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__responseDataBytesSize, *responseDataBytes) = detach_abi(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDStartResult> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDStartResult>
    {
        int32_t __stdcall get_MediaStreamSource(void** mediaStreamSource) noexcept final try
        {
            clear_abi(mediaStreamSource);
            typename D::abi_guard guard(this->shim());
            *mediaStreamSource = detach_from<winrt::Windows::Media::Core::MediaStreamSource>(this->shim().MediaStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper>
    {
        int32_t __stdcall GetFileURLs(void* file, void** fileURLs) noexcept final try
        {
            clear_abi(fileURLs);
            typename D::abi_guard guard(this->shim());
            *fileURLs = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetFileURLs(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDStreamParser> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDStreamParser>
    {
        int32_t __stdcall ParseData(uint32_t __dataBytesSize, uint8_t* dataBytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ParseData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(dataBytes), reinterpret_cast<uint8_t const *>(dataBytes) + __dataBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStreamInformation(void* descriptor, int32_t* streamType, uint32_t* streamID) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *streamID = detach_from<uint32_t>(this->shim().GetStreamInformation(*reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType*>(streamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BeginOfStream() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeginOfStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EndOfStream() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndOfStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Notifier(void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier>(this->shim().Notifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier>
    {
        int32_t __stdcall OnContentIDReceived(void* licenseFetchDescriptor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnContentIDReceived(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor const*>(&licenseFetchDescriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnMediaStreamDescriptorCreated(void* audioStreamDescriptors, void* videoStreamDescriptors) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnMediaStreamDescriptorCreated(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::AudioStreamDescriptor> const*>(&audioStreamDescriptors), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::VideoStreamDescriptor> const*>(&videoStreamDescriptors));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnSampleParsed(uint32_t streamID, int32_t streamType, void* streamSample, int64_t pts, int32_t ccFormat, uint32_t __ccDataBytesSize, uint8_t* ccDataBytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnSampleParsed(streamID, *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::NDMediaStreamType const*>(&streamType), *reinterpret_cast<winrt::Windows::Media::Core::MediaStreamSample const*>(&streamSample), pts, *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::NDClosedCaptionFormat const*>(&ccFormat), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(ccDataBytes), reinterpret_cast<uint8_t const *>(ccDataBytes) + __ccDataBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OnBeginSetupDecryptor(void* descriptor, winrt::guid keyID, uint32_t __proBytesSize, uint8_t* proBytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnBeginSetupDecryptor(*reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor), *reinterpret_cast<winrt::guid const*>(&keyID), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(proBytes), reinterpret_cast<uint8_t const *>(proBytes) + __proBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory>
    {
        int32_t __stdcall CreateInstance(void* remoteHostName, uint32_t remoteHostPort, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&remoteHostName), remoteHostPort));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties>
    {
        int32_t __stdcall get_CertificateType(int32_t* type) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *type = detach_from<winrt::Windows::Media::Protection::PlayReady::NDCertificateType>(this->shim().CertificateType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlatformIdentifier(int32_t* identifier) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *identifier = detach_from<winrt::Windows::Media::Protection::PlayReady::NDCertificatePlatformID>(this->shim().PlatformIdentifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedFeatures(uint32_t* __featureSetsSize, int32_t** featureSets) noexcept final try
        {
            clear_abi(featureSets);
            typename D::abi_guard guard(this->shim());
            std::tie(*__featureSetsSize, *featureSets) = detach_abi(this->shim().SupportedFeatures());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SecurityLevel(uint32_t* level) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *level = detach_from<uint32_t>(this->shim().SecurityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SecurityVersion(uint32_t* securityVersion) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *securityVersion = detach_from<uint32_t>(this->shim().SecurityVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(int64_t* expirationDate) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(expirationDate);
            typename D::abi_guard guard(this->shim());
            *expirationDate = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClientID(uint32_t* __clientIDBytesSize, uint8_t** clientIDBytes) noexcept final try
        {
            clear_abi(clientIDBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__clientIDBytesSize, *clientIDBytes) = detach_abi(this->shim().ClientID());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelDigest(uint32_t* __modelDigestBytesSize, uint8_t** modelDigestBytes) noexcept final try
        {
            clear_abi(modelDigestBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__modelDigestBytesSize, *modelDigestBytes) = detach_abi(this->shim().ModelDigest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelManufacturerName(void** modelManufacturerName) noexcept final try
        {
            clear_abi(modelManufacturerName);
            typename D::abi_guard guard(this->shim());
            *modelManufacturerName = detach_from<hstring>(this->shim().ModelManufacturerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelName(void** modelName) noexcept final try
        {
            clear_abi(modelName);
            typename D::abi_guard guard(this->shim());
            *modelName = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelNumber(void** modelNumber) noexcept final try
        {
            clear_abi(modelNumber);
            typename D::abi_guard guard(this->shim());
            *modelNumber = detach_from<hstring>(this->shim().ModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader>
    {
        int32_t __stdcall get_KeyId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().KeyId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyIdString(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KeyIdString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LicenseAcquisitionUrl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().LicenseAcquisitionUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LicenseAcquisitionUserInterfaceUrl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().LicenseAcquisitionUserInterfaceUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainServiceId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EncryptionType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm>(this->shim().EncryptionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CustomAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecryptorSetup(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyDecryptorSetup>(this->shim().DecryptorSetup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSerializedHeader(uint32_t* __headerBytesSize, uint8_t** headerBytes) noexcept final try
        {
            clear_abi(headerBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__headerBytesSize, *headerBytes) = detach_abi(this->shim().GetSerializedHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderWithEmbeddedUpdates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().HeaderWithEmbeddedUpdates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2>
    {
        int32_t __stdcall get_KeyIds(uint32_t* __contentKeyIdsSize, winrt::guid** contentKeyIds) noexcept final try
        {
            clear_abi(contentKeyIds);
            typename D::abi_guard guard(this->shim());
            std::tie(*__contentKeyIdsSize, *contentKeyIds) = detach_abi(this->shim().KeyIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyIdStrings(uint32_t* __contentKeyIdStringsSize, void*** contentKeyIdStrings) noexcept final try
        {
            clear_abi(contentKeyIdStrings);
            typename D::abi_guard guard(this->shim());
            std::tie(*__contentKeyIdStringsSize, *contentKeyIdStrings) = detach_abi(this->shim().KeyIdStrings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory>
    {
        int32_t __stdcall CreateInstanceFromWindowsMediaDrmHeader(uint32_t __headerBytesSize, uint8_t* headerBytes, void* licenseAcquisitionUrl, void* licenseAcquisitionUserInterfaceUrl, void* customAttributes, winrt::guid domainServiceId, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromWindowsMediaDrmHeader(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(headerBytes), reinterpret_cast<uint8_t const *>(headerBytes) + __headerBytesSize), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&licenseAcquisitionUrl), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&licenseAcquisitionUserInterfaceUrl), *reinterpret_cast<hstring const*>(&customAttributes), *reinterpret_cast<winrt::guid const*>(&domainServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceFromComponents(winrt::guid contentKeyId, void* contentKeyIdString, int32_t contentEncryptionAlgorithm, void* licenseAcquisitionUrl, void* licenseAcquisitionUserInterfaceUrl, void* customAttributes, winrt::guid domainServiceId, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromComponents(*reinterpret_cast<winrt::guid const*>(&contentKeyId), *reinterpret_cast<hstring const*>(&contentKeyIdString), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const*>(&contentEncryptionAlgorithm), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&licenseAcquisitionUrl), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&licenseAcquisitionUserInterfaceUrl), *reinterpret_cast<hstring const*>(&customAttributes), *reinterpret_cast<winrt::guid const*>(&domainServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceFromPlayReadyHeader(uint32_t __headerBytesSize, uint8_t* headerBytes, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromPlayReadyHeader(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(headerBytes), reinterpret_cast<uint8_t const *>(headerBytes) + __headerBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2>
    {
        int32_t __stdcall CreateInstanceFromComponents2(uint32_t dwFlags, uint32_t __contentKeyIdsSize, winrt::guid* contentKeyIds, uint32_t __contentKeyIdStringsSize, void** contentKeyIdStrings, int32_t contentEncryptionAlgorithm, void* licenseAcquisitionUrl, void* licenseAcquisitionUserInterfaceUrl, void* customAttributes, winrt::guid domainServiceId, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().CreateInstanceFromComponents2(dwFlags, array_view<winrt::guid const>(reinterpret_cast<winrt::guid const *>(contentKeyIds), reinterpret_cast<winrt::guid const *>(contentKeyIds) + __contentKeyIdsSize), array_view<hstring const>(reinterpret_cast<hstring const *>(contentKeyIdStrings), reinterpret_cast<hstring const *>(contentKeyIdStrings) + __contentKeyIdStringsSize), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const*>(&contentEncryptionAlgorithm), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&licenseAcquisitionUrl), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&licenseAcquisitionUserInterfaceUrl), *reinterpret_cast<hstring const*>(&customAttributes), *reinterpret_cast<winrt::guid const*>(&domainServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver>
    {
        int32_t __stdcall ServiceRequest(void* contentHeader, void** serviceRequest) noexcept final try
        {
            clear_abi(serviceRequest);
            typename D::abi_guard guard(this->shim());
            *serviceRequest = detach_from<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>(this->shim().ServiceRequest(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain>
    {
        int32_t __stdcall get_AccountId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().AccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Revision(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Revision());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainJoinUrl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().DomainJoinUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory>
    {
        int32_t __stdcall CreateInstance(winrt::guid domainAccountId, void** domainIterable) noexcept final try
        {
            clear_abi(domainIterable);
            typename D::abi_guard guard(this->shim());
            *domainIterable = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable>(this->shim().CreateInstance(*reinterpret_cast<winrt::guid const*>(&domainAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest>
    {
        int32_t __stdcall get_DomainAccountId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DomainAccountId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DomainAccountId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainFriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DomainFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DomainFriendlyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DomainFriendlyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainServiceId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DomainServiceId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DomainServiceId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest>
    {
        int32_t __stdcall get_DomainAccountId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DomainAccountId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DomainAccountId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainServiceId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DomainServiceId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DomainServiceId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator>
    {
        int32_t __stdcall GenerateData(winrt::guid guidCPSystemId, uint32_t countOfStreams, void* configuration, int32_t format, uint32_t* __dataBytesSize, uint8_t** dataBytes) noexcept final try
        {
            clear_abi(dataBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__dataBytesSize, *dataBytes) = detach_abi(this->shim().GenerateData(*reinterpret_cast<winrt::guid const*>(&guidCPSystemId), countOfStreams, *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration), *reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest>
    {
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense>
    {
        int32_t __stdcall get_FullyEvaluated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().FullyEvaluated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsableForPlay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UsableForPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpireAfterFirstPlay(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExpireAfterFirstPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainAccountID(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainAccountID());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChainDepth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ChainDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetKIDAtChainDepth(uint32_t chainDepth, winrt::guid* kid) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *kid = detach_from<winrt::guid>(this->shim().GetKIDAtChainDepth(chainDepth));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2>
    {
        int32_t __stdcall get_SecureStopId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().SecureStopId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SecurityLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SecurityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InMemoryOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().InMemoryOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpiresInRealTime(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ExpiresInRealTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>
    {
        int32_t __stdcall get_ContentHeader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader>(this->shim().ContentHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentHeader(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentHeader(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainServiceId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DomainServiceId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DomainServiceId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2>
    {
        int32_t __stdcall get_SessionId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3>
    {
        int32_t __stdcall CreateLicenseIterable(void* contentHeader, bool fullyEvaluated, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>(this->shim().CreateLicenseIterable(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader), fullyEvaluated));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory>
    {
        int32_t __stdcall CreateInstance(void* contentHeader, bool fullyEvaluated, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader), fullyEvaluated));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement>
    {
        int32_t __stdcall DeleteLicenses(void* contentHeader, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteLicenses(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession>
    {
        int32_t __stdcall CreateLAServiceRequest(void** serviceRequest) noexcept final try
        {
            clear_abi(serviceRequest);
            typename D::abi_guard guard(this->shim());
            *serviceRequest = detach_from<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest>(this->shim().CreateLAServiceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureMediaProtectionManager(void* mpm) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureMediaProtectionManager(*reinterpret_cast<winrt::Windows::Media::Protection::MediaProtectionManager const*>(&mpm));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2>
    {
        int32_t __stdcall CreateLicenseIterable(void* contentHeader, bool fullyEvaluated, void** licenseIterable) noexcept final try
        {
            clear_abi(licenseIterable);
            typename D::abi_guard guard(this->shim());
            *licenseIterable = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable>(this->shim().CreateLicenseIterable(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const*>(&contentHeader), fullyEvaluated));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory>
    {
        int32_t __stdcall CreateInstance(void* configuration, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest>
    {
        int32_t __stdcall get_MeteringCertificate(uint32_t* __meteringCertBytesSize, uint8_t** meteringCertBytes) noexcept final try
        {
            clear_abi(meteringCertBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__meteringCertBytesSize, *meteringCertBytes) = detach_abi(this->shim().MeteringCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MeteringCertificate(uint32_t __meteringCertBytesSize, uint8_t* meteringCertBytes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MeteringCertificate(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(meteringCertBytes), reinterpret_cast<uint8_t const *>(meteringCertBytes) + __meteringCertBytesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory>
    {
        int32_t __stdcall CreateInstance(uint32_t __publisherCertBytesSize, uint8_t* publisherCertBytes, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable>(this->shim().CreateInstance(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(publisherCertBytes), reinterpret_cast<uint8_t const *>(publisherCertBytes) + __publisherCertBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest>
    {
        int32_t __stdcall get_SessionID(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().SessionID());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpdateTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().UpdateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Stopped(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Stopped());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublisherCertificate(uint32_t* __publisherCertBytesSize, uint8_t** publisherCertBytes) noexcept final try
        {
            clear_abi(publisherCertBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__publisherCertBytesSize, *publisherCertBytes) = detach_abi(this->shim().PublisherCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory>
    {
        int32_t __stdcall CreateInstance(uint32_t __publisherCertBytesSize, uint8_t* publisherCertBytes, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest>(this->shim().CreateInstance(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(publisherCertBytes), reinterpret_cast<uint8_t const *>(publisherCertBytes) + __publisherCertBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceFromSessionID(winrt::guid sessionID, uint32_t __publisherCertBytesSize, uint8_t* publisherCertBytes, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest>(this->shim().CreateInstanceFromSessionID(*reinterpret_cast<winrt::guid const*>(&sessionID), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(publisherCertBytes), reinterpret_cast<uint8_t const *>(publisherCertBytes) + __publisherCertBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Uri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseCustomData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ResponseCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChallengeCustomData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ChallengeCustomData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChallengeCustomData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChallengeCustomData(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BeginServiceRequest(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().BeginServiceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NextServiceRequest(void** serviceRequest) noexcept final try
        {
            clear_abi(serviceRequest);
            typename D::abi_guard guard(this->shim());
            *serviceRequest = detach_from<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest>(this->shim().NextServiceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GenerateManualEnablingChallenge(void** challengeMessage) noexcept final try
        {
            clear_abi(challengeMessage);
            typename D::abi_guard guard(this->shim());
            *challengeMessage = detach_from<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage>(this->shim().GenerateManualEnablingChallenge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessManualEnablingResponse(uint32_t __responseBytesSize, uint8_t* responseBytes, winrt::hresult* result) noexcept final try
        {
            zero_abi<winrt::hresult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::hresult>(this->shim().ProcessManualEnablingResponse(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseBytes), reinterpret_cast<uint8_t const *>(responseBytes) + __responseBytesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage>
    {
        int32_t __stdcall GetMessageBody(uint32_t* __messageBodyBytesSize, uint8_t** messageBodyBytes) noexcept final try
        {
            clear_abi(messageBodyBytes);
            typename D::abi_guard guard(this->shim());
            std::tie(*__messageBodyBytesSize, *messageBodyBytes) = detach_abi(this->shim().GetMessageBody());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MessageHeaders(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().MessageHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** messageUri) noexcept final try
        {
            clear_abi(messageUri);
            typename D::abi_guard guard(this->shim());
            *messageUri = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics>
    {
        int32_t __stdcall get_DomainJoinServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainJoinServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DomainLeaveServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().DomainLeaveServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndividualizationServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().IndividualizationServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LicenseAcquirerServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().LicenseAcquirerServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MeteringReportServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().MeteringReportServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RevocationServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().RevocationServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaProtectionSystemId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().MediaProtectionSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlayReadySecurityVersion(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PlayReadySecurityVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2>
    {
        int32_t __stdcall get_PlayReadyCertificateSecurityLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PlayReadyCertificateSecurityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3>
    {
        int32_t __stdcall get_SecureStopServiceRequestType(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().SecureStopServiceRequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckSupportedHardware(int32_t hwdrmFeature, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CheckSupportedHardware(*reinterpret_cast<winrt::Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const*>(&hwdrmFeature)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4>
    {
        int32_t __stdcall get_InputTrustAuthorityToCreate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InputTrustAuthorityToCreate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProtectionSystemId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ProtectionSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5> : produce_base<D, winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5>
    {
        int32_t __stdcall get_HardwareDRMDisabledAtTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().HardwareDRMDisabledAtTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardwareDRMDisabledUntilTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().HardwareDRMDisabledUntilTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetHardwareDRMDisabled() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetHardwareDRMDisabled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Protection::PlayReady
{
    inline NDClient::NDClient(winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine const& downloadEngine, winrt::Windows::Media::Protection::PlayReady::INDStreamParser const& streamParser, winrt::Windows::Media::Protection::PlayReady::INDMessenger const& pMessenger) :
        NDClient(impl::call_factory<NDClient, INDClientFactory>([&](INDClientFactory const& f) { return f.CreateInstance(downloadEngine, streamParser, pMessenger); }))
    {
    }
    inline NDCustomData::NDCustomData(array_view<uint8_t const> customDataTypeIDBytes, array_view<uint8_t const> customDataBytes) :
        NDCustomData(impl::call_factory<NDCustomData, INDCustomDataFactory>([&](INDCustomDataFactory const& f) { return f.CreateInstance(customDataTypeIDBytes, customDataBytes); }))
    {
    }
    inline NDDownloadEngineNotifier::NDDownloadEngineNotifier() :
        NDDownloadEngineNotifier(impl::call_factory_cast<NDDownloadEngineNotifier(*)(winrt::Windows::Foundation::IActivationFactory const&), NDDownloadEngineNotifier>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NDDownloadEngineNotifier>(); }))
    {
    }
    inline NDLicenseFetchDescriptor::NDLicenseFetchDescriptor(winrt::Windows::Media::Protection::PlayReady::NDContentIDType const& contentIDType, array_view<uint8_t const> contentIDBytes, winrt::Windows::Media::Protection::PlayReady::INDCustomData const& licenseFetchChallengeCustomData) :
        NDLicenseFetchDescriptor(impl::call_factory<NDLicenseFetchDescriptor, INDLicenseFetchDescriptorFactory>([&](INDLicenseFetchDescriptorFactory const& f) { return f.CreateInstance(contentIDType, contentIDBytes, licenseFetchChallengeCustomData); }))
    {
    }
    inline NDStorageFileHelper::NDStorageFileHelper() :
        NDStorageFileHelper(impl::call_factory_cast<NDStorageFileHelper(*)(winrt::Windows::Foundation::IActivationFactory const&), NDStorageFileHelper>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NDStorageFileHelper>(); }))
    {
    }
    inline NDStreamParserNotifier::NDStreamParserNotifier() :
        NDStreamParserNotifier(impl::call_factory_cast<NDStreamParserNotifier(*)(winrt::Windows::Foundation::IActivationFactory const&), NDStreamParserNotifier>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NDStreamParserNotifier>(); }))
    {
    }
    inline NDTCPMessenger::NDTCPMessenger(param::hstring const& remoteHostName, uint32_t remoteHostPort) :
        NDTCPMessenger(impl::call_factory<NDTCPMessenger, INDTCPMessengerFactory>([&](INDTCPMessengerFactory const& f) { return f.CreateInstance(remoteHostName, remoteHostPort); }))
    {
    }
    inline PlayReadyContentHeader::PlayReadyContentHeader(array_view<uint8_t const> headerBytes, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) :
        PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, IPlayReadyContentHeaderFactory>([&](IPlayReadyContentHeaderFactory const& f) { return f.CreateInstanceFromWindowsMediaDrmHeader(headerBytes, licenseAcquisitionUrl, licenseAcquisitionUserInterfaceUrl, customAttributes, domainServiceId); }))
    {
    }
    inline PlayReadyContentHeader::PlayReadyContentHeader(winrt::guid const& contentKeyId, param::hstring const& contentKeyIdString, winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) :
        PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, IPlayReadyContentHeaderFactory>([&](IPlayReadyContentHeaderFactory const& f) { return f.CreateInstanceFromComponents(contentKeyId, contentKeyIdString, contentEncryptionAlgorithm, licenseAcquisitionUrl, licenseAcquisitionUserInterfaceUrl, customAttributes, domainServiceId); }))
    {
    }
    inline PlayReadyContentHeader::PlayReadyContentHeader(array_view<uint8_t const> headerBytes) :
        PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, IPlayReadyContentHeaderFactory>([&](IPlayReadyContentHeaderFactory const& f) { return f.CreateInstanceFromPlayReadyHeader(headerBytes); }))
    {
    }
    inline PlayReadyContentHeader::PlayReadyContentHeader(uint32_t dwFlags, array_view<winrt::guid const> contentKeyIds, array_view<hstring const> contentKeyIdStrings, winrt::Windows::Media::Protection::PlayReady::PlayReadyEncryptionAlgorithm const& contentEncryptionAlgorithm, winrt::Windows::Foundation::Uri const& licenseAcquisitionUrl, winrt::Windows::Foundation::Uri const& licenseAcquisitionUserInterfaceUrl, param::hstring const& customAttributes, winrt::guid const& domainServiceId) :
        PlayReadyContentHeader(impl::call_factory<PlayReadyContentHeader, IPlayReadyContentHeaderFactory2>([&](IPlayReadyContentHeaderFactory2 const& f) { return f.CreateInstanceFromComponents2(dwFlags, contentKeyIds, contentKeyIdStrings, contentEncryptionAlgorithm, licenseAcquisitionUrl, licenseAcquisitionUserInterfaceUrl, customAttributes, domainServiceId); }))
    {
    }
    inline auto PlayReadyContentResolver::ServiceRequest(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader)
    {
        return impl::call_factory<PlayReadyContentResolver, IPlayReadyContentResolver>([&](IPlayReadyContentResolver const& f) { return f.ServiceRequest(contentHeader); });
    }
    inline PlayReadyDomainIterable::PlayReadyDomainIterable(winrt::guid const& domainAccountId) :
        PlayReadyDomainIterable(impl::call_factory<PlayReadyDomainIterable, IPlayReadyDomainIterableFactory>([&](IPlayReadyDomainIterableFactory const& f) { return f.CreateInstance(domainAccountId); }))
    {
    }
    inline PlayReadyDomainJoinServiceRequest::PlayReadyDomainJoinServiceRequest() :
        PlayReadyDomainJoinServiceRequest(impl::call_factory_cast<PlayReadyDomainJoinServiceRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyDomainJoinServiceRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyDomainJoinServiceRequest>(); }))
    {
    }
    inline PlayReadyDomainLeaveServiceRequest::PlayReadyDomainLeaveServiceRequest() :
        PlayReadyDomainLeaveServiceRequest(impl::call_factory_cast<PlayReadyDomainLeaveServiceRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyDomainLeaveServiceRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyDomainLeaveServiceRequest>(); }))
    {
    }
    inline PlayReadyITADataGenerator::PlayReadyITADataGenerator() :
        PlayReadyITADataGenerator(impl::call_factory_cast<PlayReadyITADataGenerator(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyITADataGenerator>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyITADataGenerator>(); }))
    {
    }
    inline PlayReadyIndividualizationServiceRequest::PlayReadyIndividualizationServiceRequest() :
        PlayReadyIndividualizationServiceRequest(impl::call_factory_cast<PlayReadyIndividualizationServiceRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyIndividualizationServiceRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyIndividualizationServiceRequest>(); }))
    {
    }
    inline PlayReadyLicenseAcquisitionServiceRequest::PlayReadyLicenseAcquisitionServiceRequest() :
        PlayReadyLicenseAcquisitionServiceRequest(impl::call_factory_cast<PlayReadyLicenseAcquisitionServiceRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyLicenseAcquisitionServiceRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyLicenseAcquisitionServiceRequest>(); }))
    {
    }
    inline PlayReadyLicenseIterable::PlayReadyLicenseIterable() :
        PlayReadyLicenseIterable(impl::call_factory_cast<PlayReadyLicenseIterable(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyLicenseIterable>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyLicenseIterable>(); }))
    {
    }
    inline PlayReadyLicenseIterable::PlayReadyLicenseIterable(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader, bool fullyEvaluated) :
        PlayReadyLicenseIterable(impl::call_factory<PlayReadyLicenseIterable, IPlayReadyLicenseIterableFactory>([&](IPlayReadyLicenseIterableFactory const& f) { return f.CreateInstance(contentHeader, fullyEvaluated); }))
    {
    }
    inline auto PlayReadyLicenseManagement::DeleteLicenses(winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader const& contentHeader)
    {
        return impl::call_factory<PlayReadyLicenseManagement, IPlayReadyLicenseManagement>([&](IPlayReadyLicenseManagement const& f) { return f.DeleteLicenses(contentHeader); });
    }
    inline PlayReadyLicenseSession::PlayReadyLicenseSession(winrt::Windows::Foundation::Collections::IPropertySet const& configuration) :
        PlayReadyLicenseSession(impl::call_factory<PlayReadyLicenseSession, IPlayReadyLicenseSessionFactory>([&](IPlayReadyLicenseSessionFactory const& f) { return f.CreateInstance(configuration); }))
    {
    }
    inline PlayReadyMeteringReportServiceRequest::PlayReadyMeteringReportServiceRequest() :
        PlayReadyMeteringReportServiceRequest(impl::call_factory_cast<PlayReadyMeteringReportServiceRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyMeteringReportServiceRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyMeteringReportServiceRequest>(); }))
    {
    }
    inline PlayReadyRevocationServiceRequest::PlayReadyRevocationServiceRequest() :
        PlayReadyRevocationServiceRequest(impl::call_factory_cast<PlayReadyRevocationServiceRequest(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayReadyRevocationServiceRequest>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayReadyRevocationServiceRequest>(); }))
    {
    }
    inline PlayReadySecureStopIterable::PlayReadySecureStopIterable(array_view<uint8_t const> publisherCertBytes) :
        PlayReadySecureStopIterable(impl::call_factory<PlayReadySecureStopIterable, IPlayReadySecureStopIterableFactory>([&](IPlayReadySecureStopIterableFactory const& f) { return f.CreateInstance(publisherCertBytes); }))
    {
    }
    inline PlayReadySecureStopServiceRequest::PlayReadySecureStopServiceRequest(array_view<uint8_t const> publisherCertBytes) :
        PlayReadySecureStopServiceRequest(impl::call_factory<PlayReadySecureStopServiceRequest, IPlayReadySecureStopServiceRequestFactory>([&](IPlayReadySecureStopServiceRequestFactory const& f) { return f.CreateInstance(publisherCertBytes); }))
    {
    }
    inline PlayReadySecureStopServiceRequest::PlayReadySecureStopServiceRequest(winrt::guid const& sessionID, array_view<uint8_t const> publisherCertBytes) :
        PlayReadySecureStopServiceRequest(impl::call_factory<PlayReadySecureStopServiceRequest, IPlayReadySecureStopServiceRequestFactory>([&](IPlayReadySecureStopServiceRequestFactory const& f) { return f.CreateInstanceFromSessionID(sessionID, publisherCertBytes); }))
    {
    }
    inline auto PlayReadyStatics::DomainJoinServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.DomainJoinServiceRequestType(); });
    }
    inline auto PlayReadyStatics::DomainLeaveServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.DomainLeaveServiceRequestType(); });
    }
    inline auto PlayReadyStatics::IndividualizationServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.IndividualizationServiceRequestType(); });
    }
    inline auto PlayReadyStatics::LicenseAcquirerServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.LicenseAcquirerServiceRequestType(); });
    }
    inline auto PlayReadyStatics::MeteringReportServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.MeteringReportServiceRequestType(); });
    }
    inline auto PlayReadyStatics::RevocationServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.RevocationServiceRequestType(); });
    }
    inline auto PlayReadyStatics::MediaProtectionSystemId()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.MediaProtectionSystemId(); });
    }
    inline auto PlayReadyStatics::PlayReadySecurityVersion()
    {
        return impl::call_factory_cast<uint32_t(*)(IPlayReadyStatics const&), PlayReadyStatics, IPlayReadyStatics>([](IPlayReadyStatics const& f) { return f.PlayReadySecurityVersion(); });
    }
    inline auto PlayReadyStatics::PlayReadyCertificateSecurityLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IPlayReadyStatics2 const&), PlayReadyStatics, IPlayReadyStatics2>([](IPlayReadyStatics2 const& f) { return f.PlayReadyCertificateSecurityLevel(); });
    }
    inline auto PlayReadyStatics::SecureStopServiceRequestType()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics3 const&), PlayReadyStatics, IPlayReadyStatics3>([](IPlayReadyStatics3 const& f) { return f.SecureStopServiceRequestType(); });
    }
    inline auto PlayReadyStatics::CheckSupportedHardware(winrt::Windows::Media::Protection::PlayReady::PlayReadyHardwareDRMFeatures const& hwdrmFeature)
    {
        return impl::call_factory<PlayReadyStatics, IPlayReadyStatics3>([&](IPlayReadyStatics3 const& f) { return f.CheckSupportedHardware(hwdrmFeature); });
    }
    inline auto PlayReadyStatics::InputTrustAuthorityToCreate()
    {
        return impl::call_factory_cast<hstring(*)(IPlayReadyStatics4 const&), PlayReadyStatics, IPlayReadyStatics4>([](IPlayReadyStatics4 const& f) { return f.InputTrustAuthorityToCreate(); });
    }
    inline auto PlayReadyStatics::ProtectionSystemId()
    {
        return impl::call_factory_cast<winrt::guid(*)(IPlayReadyStatics4 const&), PlayReadyStatics, IPlayReadyStatics4>([](IPlayReadyStatics4 const& f) { return f.ProtectionSystemId(); });
    }
    inline auto PlayReadyStatics::HardwareDRMDisabledAtTime()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>(*)(IPlayReadyStatics5 const&), PlayReadyStatics, IPlayReadyStatics5>([](IPlayReadyStatics5 const& f) { return f.HardwareDRMDisabledAtTime(); });
    }
    inline auto PlayReadyStatics::HardwareDRMDisabledUntilTime()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>(*)(IPlayReadyStatics5 const&), PlayReadyStatics, IPlayReadyStatics5>([](IPlayReadyStatics5 const& f) { return f.HardwareDRMDisabledUntilTime(); });
    }
    inline auto PlayReadyStatics::ResetHardwareDRMDisabled()
    {
        impl::call_factory_cast<void(*)(IPlayReadyStatics5 const&), PlayReadyStatics, IPlayReadyStatics5>([](IPlayReadyStatics5 const& f) { return f.ResetHardwareDRMDisabled(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDClient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDClientFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDClosedCaptionDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDCustomData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDCustomDataFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDDownloadEngineNotifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchDescriptorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDLicenseFetchResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDMessenger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDProximityDetectionCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDRegistrationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDSendResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStartResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStorageFileHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStreamParser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDStreamParserNotifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDTCPMessengerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::INDTransmitterProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentHeaderFactory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyContentResolver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomain> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainIterableFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainJoinServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyDomainLeaveServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyITADataGenerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyIndividualizationServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicense2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseAcquisitionServiceRequest3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseIterableFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseManagement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSession2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyLicenseSessionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyMeteringReportServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyRevocationServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopIterableFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySecureStopServiceRequestFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadySoapMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::IPlayReadyStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDClient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDCustomData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDDownloadEngineNotifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDLicenseFetchDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDStorageFileHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDStreamParserNotifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::NDTCPMessenger> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentHeader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyContentResolver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomain> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterable> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainIterator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainJoinServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyDomainLeaveServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyITADataGenerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyIndividualizationServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicense> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseAcquisitionServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterable> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseIterator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseManagement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyLicenseSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyMeteringReportServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyRevocationServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterable> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopIterator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySecureStopServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadySoapMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::PlayReady::PlayReadyStatics> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
