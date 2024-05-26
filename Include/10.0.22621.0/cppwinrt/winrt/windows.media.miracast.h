// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Miracast_H
#define WINRT_Windows_Media_Miracast_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.Miracast.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverSettings) consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetDefaultSettings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->GetDefaultSettings(&result));
        return winrt::Windows::Media::Miracast::MiracastReceiverSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverSettings) consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetCurrentSettings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->GetCurrentSettings(&result));
        return winrt::Windows::Media::Miracast::MiracastReceiverSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSettings>) consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetCurrentSettingsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->GetCurrentSettingsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSettings>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult) consume_Windows_Media_Miracast_IMiracastReceiver<D>::DisconnectAllAndApplySettings(winrt::Windows::Media::Miracast::MiracastReceiverSettings const& settings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->DisconnectAllAndApplySettings(*(void**)(&settings), &result));
        return winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult>) consume_Windows_Media_Miracast_IMiracastReceiver<D>::DisconnectAllAndApplySettingsAsync(winrt::Windows::Media::Miracast::MiracastReceiverSettings const& settings) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->DisconnectAllAndApplySettingsAsync(*(void**)(&settings), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverStatus) consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetStatus() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->GetStatus(&result));
        return winrt::Windows::Media::Miracast::MiracastReceiverStatus{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverStatus>) consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetStatusAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->GetStatusAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->add_StatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged_revoker consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverSession) consume_Windows_Media_Miracast_IMiracastReceiver<D>::CreateSession(winrt::Windows::ApplicationModel::Core::CoreApplicationView const& view) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->CreateSession(*(void**)(&view), &result));
        return winrt::Windows::Media::Miracast::MiracastReceiverSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSession>) consume_Windows_Media_Miracast_IMiracastReceiver<D>::CreateSessionAsync(winrt::Windows::ApplicationModel::Core::CoreApplicationView const& view) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->CreateSessionAsync(*(void**)(&view), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSession>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiver<D>::ClearKnownTransmitters() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->ClearKnownTransmitters());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiver<D>::RemoveKnownTransmitter(winrt::Windows::Media::Miracast::MiracastTransmitter const& transmitter) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiver)->RemoveKnownTransmitter(*(void**)(&transmitter)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsStatus) consume_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult<D>::Status() const
    {
        winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Disconnect(winrt::Windows::Media::Miracast::MiracastReceiverDisconnectReason const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->Disconnect(static_cast<int32_t>(reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Disconnect(winrt::Windows::Media::Miracast::MiracastReceiverDisconnectReason const& reason, param::hstring const& message) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->DisconnectWithMessage(static_cast<int32_t>(reason), *(void**)(&message)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::PauseAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->PauseAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::ResumeAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->ResumeAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastTransmitter) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Transmitter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->get_Transmitter(&value));
        return winrt::Windows::Media::Miracast::MiracastTransmitter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverInputDevices) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::InputDevices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->get_InputDevices(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverInputDevices{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::CursorImageChannel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->get_CursorImageChannel(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverStreamControl) consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::StreamControl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnection)->get_StreamControl(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverStreamControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverConnection) consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs)->get_Connection(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>::Pin() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs)->get_Pin(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::MaxImageSize() const
    {
        winrt::Windows::Graphics::SizeInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_MaxImageSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::PointInt32) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::Position() const
    {
        winrt::Windows::Graphics::PointInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_ImageStream(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->add_ImageStreamChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged_revoker consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ImageStreamChanged_revoker>(this, ImageStreamChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->remove_ImageStreamChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->add_PositionChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged_revoker consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->remove_PositionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::MaxImageSize() const
    {
        winrt::Windows::Graphics::SizeInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->get_MaxImageSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::MaxImageSize(winrt::Windows::Graphics::SizeInt32 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->put_MaxImageSize(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverConnection) consume_Windows_Media_Miracast_IMiracastReceiverDisconnectedEventArgs<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs)->get_Connection(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::TransmitInput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_TransmitInput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::TransmitInput(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->put_TransmitInput(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::IsRequestedByTransmitter() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_IsRequestedByTransmitter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::IsTransmittingInput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_IsTransmittingInput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Mode() const
    {
        winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Mode(winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed_revoker consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice) consume_Windows_Media_Miracast_IMiracastReceiverInputDevices<D>::Keyboard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices)->get_Keyboard(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice) consume_Windows_Media_Miracast_IMiracastReceiverInputDevices<D>::GameController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices)->get_GameController(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::TransmitInput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->get_TransmitInput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::TransmitInput(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->put_TransmitInput(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::IsRequestedByTransmitter() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->get_IsRequestedByTransmitter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::IsTransmittingInput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->get_IsTransmittingInput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed_revoker consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverConnection) consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->get_Connection(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::MediaSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->get_MediaSource(&value));
        return winrt::Windows::Media::Core::MediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings) consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::CursorImageChannelSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->get_CursorImageChannelSettings(&value));
        return winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->add_ConnectionCreated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated_revoker consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionCreated_revoker>(this, ConnectionCreated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->remove_ConnectionCreated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->add_MediaSourceCreated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated_revoker consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, MediaSourceCreated_revoker>(this, MediaSourceCreated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->remove_MediaSourceCreated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->add_Disconnected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected_revoker consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Disconnected_revoker>(this, Disconnected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->remove_Disconnected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::AllowConnectionTakeover() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->get_AllowConnectionTakeover(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::AllowConnectionTakeover(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->put_AllowConnectionTakeover(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MaxSimultaneousConnections() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->get_MaxSimultaneousConnections(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MaxSimultaneousConnections(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->put_MaxSimultaneousConnections(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Start() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->Start(&result));
        return winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult>) consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSession)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverSessionStartStatus) consume_Windows_Media_Miracast_IMiracastReceiverSessionStartResult<D>::Status() const
    {
        winrt::Windows::Media::Miracast::MiracastReceiverSessionStartStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Miracast_IMiracastReceiverSessionStartResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::FriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->get_FriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::FriendlyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->put_FriendlyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->get_ModelName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->put_ModelName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->get_ModelNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelNumber(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->put_ModelNumber(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::AuthorizationMethod() const
    {
        winrt::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->get_AuthorizationMethod(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::AuthorizationMethod(winrt::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->put_AuthorizationMethod(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::RequireAuthorizationFromKnownTransmitters() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->get_RequireAuthorizationFromKnownTransmitters(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::RequireAuthorizationFromKnownTransmitters(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverSettings)->put_RequireAuthorizationFromKnownTransmitters(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverListeningStatus) consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::ListeningStatus() const
    {
        winrt::Windows::Media::Miracast::MiracastReceiverListeningStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStatus)->get_ListeningStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverWiFiStatus) consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::WiFiStatus() const
    {
        winrt::Windows::Media::Miracast::MiracastReceiverWiFiStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStatus)->get_WiFiStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::IsConnectionTakeoverSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStatus)->get_IsConnectionTakeoverSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::MaxSimultaneousConnections() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStatus)->get_MaxSimultaneousConnections(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Miracast::MiracastTransmitter>) consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::KnownTransmitters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStatus)->get_KnownTransmitters(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Miracast::MiracastTransmitter>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings) consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::GetVideoStreamSettings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl)->GetVideoStreamSettings(&result));
        return winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>) consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::GetVideoStreamSettingsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl)->GetVideoStreamSettingsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::SuggestVideoStreamSettings(winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const& settings) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl)->SuggestVideoStreamSettings(*(void**)(&settings)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::SuggestVideoStreamSettingsAsync(winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const& settings) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl)->SuggestVideoStreamSettingsAsync(*(void**)(&settings), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::MuteAudio() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl)->get_MuteAudio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::MuteAudio(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl)->put_MuteAudio(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Size() const
    {
        winrt::Windows::Graphics::SizeInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Size(winrt::Windows::Graphics::SizeInt32 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->put_Size(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Bitrate() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->get_Bitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Bitrate(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->put_Bitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::AuthorizationStatus() const
    {
        winrt::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->get_AuthorizationStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::AuthorizationStatus(winrt::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->put_AuthorizationStatus(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Miracast::MiracastReceiverConnection>) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::GetConnections() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->GetConnections(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Miracast::MiracastReceiverConnection>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::MacAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->get_MacAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_Miracast_IMiracastTransmitter<D>::LastConnectionTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Miracast::IMiracastTransmitter)->get_LastConnectionTime(put_abi(value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiver> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiver>
    {
        int32_t __stdcall GetDefaultSettings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverSettings>(this->shim().GetDefaultSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentSettings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentSettingsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSettings>>(this->shim().GetCurrentSettingsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisconnectAllAndApplySettings(void* settings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult>(this->shim().DisconnectAllAndApplySettings(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisconnectAllAndApplySettingsAsync(void* settings, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult>>(this->shim().DisconnectAllAndApplySettingsAsync(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStatus(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverStatus>(this->shim().GetStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStatusAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverStatus>>(this->shim().GetStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiver, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CreateSession(void* view, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverSession>(this->shim().CreateSession(*reinterpret_cast<winrt::Windows::ApplicationModel::Core::CoreApplicationView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSessionAsync(void* view, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSession>>(this->shim().CreateSessionAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Core::CoreApplicationView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearKnownTransmitters() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearKnownTransmitters();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveKnownTransmitter(void* transmitter) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveKnownTransmitter(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastTransmitter const*>(&transmitter));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverConnection> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverConnection>
    {
        int32_t __stdcall Disconnect(int32_t reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disconnect(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverDisconnectReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisconnectWithMessage(int32_t reason, void* message) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disconnect(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverDisconnectReason const*>(&reason), *reinterpret_cast<hstring const*>(&message));
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
        int32_t __stdcall PauseAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().PauseAsync());
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
        int32_t __stdcall ResumeAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ResumeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Transmitter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastTransmitter>(this->shim().Transmitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputDevices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverInputDevices>(this->shim().InputDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CursorImageChannel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel>(this->shim().CursorImageChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StreamControl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverStreamControl>(this->shim().StreamControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs>
    {
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pin(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Pin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxImageSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::SizeInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::SizeInt32>(this->shim().MaxImageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(struct struct_Windows_Graphics_PointInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::PointInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::PointInt32>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ImageStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().ImageStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ImageStreamChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ImageStreamChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ImageStreamChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImageStreamChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PositionChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PositionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxImageSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::SizeInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::SizeInt32>(this->shim().MaxImageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxImageSize(struct struct_Windows_Graphics_SizeInt32 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxImageSize(*reinterpret_cast<winrt::Windows::Graphics::SizeInt32 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs>
    {
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>
    {
        int32_t __stdcall get_TransmitInput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TransmitInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransmitInput(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransmitInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRequestedByTransmitter(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRequestedByTransmitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTransmittingInput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTransmittingInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices>
    {
        int32_t __stdcall get_Keyboard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice>(this->shim().Keyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GameController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice>(this->shim().GameController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>
    {
        int32_t __stdcall get_TransmitInput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TransmitInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransmitInput(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransmitInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRequestedByTransmitter(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRequestedByTransmitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTransmittingInput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTransmittingInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs>
    {
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().MediaSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CursorImageChannelSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings>(this->shim().CursorImageChannelSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverSession> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverSession>
    {
        int32_t __stdcall add_ConnectionCreated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionCreated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionCreated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionCreated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MediaSourceCreated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaSourceCreated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaSourceCreated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaSourceCreated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Disconnected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Disconnected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Miracast::MiracastReceiverSession, winrt::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Disconnected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disconnected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_AllowConnectionTakeover(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowConnectionTakeover());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowConnectionTakeover(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowConnectionTakeover(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSimultaneousConnections(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxSimultaneousConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxSimultaneousConnections(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxSimultaneousConnections(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult>(this->shim().Start());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverSettings> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverSettings>
    {
        int32_t __stdcall get_FriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FriendlyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FriendlyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ModelName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ModelName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModelNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ModelNumber(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ModelNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthorizationMethod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod>(this->shim().AuthorizationMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AuthorizationMethod(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthorizationMethod(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequireAuthorizationFromKnownTransmitters(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().RequireAuthorizationFromKnownTransmitters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequireAuthorizationFromKnownTransmitters(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequireAuthorizationFromKnownTransmitters(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverStatus> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverStatus>
    {
        int32_t __stdcall get_ListeningStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverListeningStatus>(this->shim().ListeningStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WiFiStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverWiFiStatus>(this->shim().WiFiStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConnectionTakeoverSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConnectionTakeoverSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSimultaneousConnections(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxSimultaneousConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KnownTransmitters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Miracast::MiracastTransmitter>>(this->shim().KnownTransmitters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl>
    {
        int32_t __stdcall GetVideoStreamSettings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>(this->shim().GetVideoStreamSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetVideoStreamSettingsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>>(this->shim().GetVideoStreamSettingsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SuggestVideoStreamSettings(void* settings) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestVideoStreamSettings(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SuggestVideoStreamSettingsAsync(void* settings, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SuggestVideoStreamSettingsAsync(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MuteAudio(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().MuteAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MuteAudio(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MuteAudio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings>
    {
        int32_t __stdcall get_Size(struct struct_Windows_Graphics_SizeInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::SizeInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::SizeInt32>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Size(struct struct_Windows_Graphics_SizeInt32 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Size(*reinterpret_cast<winrt::Windows::Graphics::SizeInt32 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bitrate(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Bitrate(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Miracast::IMiracastTransmitter> : produce_base<D, winrt::Windows::Media::Miracast::IMiracastTransmitter>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthorizationStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus>(this->shim().AuthorizationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AuthorizationStatus(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthorizationStatus(*reinterpret_cast<winrt::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConnections(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Miracast::MiracastReceiverConnection>>(this->shim().GetConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MacAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MacAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastConnectionTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastConnectionTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Miracast
{
    inline MiracastReceiver::MiracastReceiver() :
        MiracastReceiver(impl::call_factory_cast<MiracastReceiver(*)(winrt::Windows::Foundation::IActivationFactory const&), MiracastReceiver>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MiracastReceiver>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::IMiracastTransmitter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverInputDevices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverStreamControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Miracast::MiracastTransmitter> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
