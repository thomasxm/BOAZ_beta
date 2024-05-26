// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_DialProtocol_H
#define WINRT_Windows_Media_DialProtocol_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.Media.DialProtocol.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_DialProtocol_IDialApp<D>::AppName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialApp)->get_AppName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppLaunchResult>) consume_Windows_Media_DialProtocol_IDialApp<D>::RequestLaunchAsync(param::hstring const& appArgument) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialApp)->RequestLaunchAsync(*(void**)(&appArgument), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppLaunchResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppStopResult>) consume_Windows_Media_DialProtocol_IDialApp<D>::StopAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialApp)->StopAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppStopResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppStateDetails>) consume_Windows_Media_DialProtocol_IDialApp<D>::GetAppStateAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialApp)->GetAppStateAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppStateDetails>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::DialProtocol::DialAppState) consume_Windows_Media_DialProtocol_IDialAppStateDetails<D>::State() const
    {
        winrt::Windows::Media::DialProtocol::DialAppState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialAppStateDetails)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_DialProtocol_IDialAppStateDetails<D>::FullXml() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialAppStateDetails)->get_FullXml(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_DialProtocol_IDialDevice<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevice)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::DialProtocol::DialApp) consume_Windows_Media_DialProtocol_IDialDevice<D>::GetDialApp(param::hstring const& appName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevice)->GetDialApp(*(void**)(&appName), &value));
        return winrt::Windows::Media::DialProtocol::DialApp{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_DialProtocol_IDialDevice2<D>::FriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevice2)->get_FriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Media_DialProtocol_IDialDevice2<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevice2)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::DialProtocol::DialDevicePickerFilter) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Filter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->get_Filter(&value));
        return winrt::Windows::Media::DialProtocol::DialDevicePickerFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePickerAppearance) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Appearance() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->get_Appearance(&value));
        return winrt::Windows::Devices::Enumeration::DevicePickerAppearance{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->add_DialDeviceSelected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected_revoker consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DialDeviceSelected_revoker>(this, DialDeviceSelected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDeviceSelected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->remove_DialDeviceSelected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->add_DisconnectButtonClicked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked_revoker consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DisconnectButtonClicked_revoker>(this, DisconnectButtonClicked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DisconnectButtonClicked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->remove_DisconnectButtonClicked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->add_DialDevicePickerDismissed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed_revoker consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DialDevicePickerDismissed_revoker>(this, DialDevicePickerDismissed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::DialDevicePickerDismissed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->remove_DialDevicePickerDismissed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Show(winrt::Windows::Foundation::Rect const& selection) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->Show(impl::bind_in(selection)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Show(winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->ShowWithPlacement(impl::bind_in(selection), static_cast<int32_t>(preferredPlacement)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::PickSingleDialDeviceAsync(winrt::Windows::Foundation::Rect const& selection) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->PickSingleDialDeviceAsync(impl::bind_in(selection), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::PickSingleDialDeviceAsync(winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->PickSingleDialDeviceAsyncWithPlacement(impl::bind_in(selection), static_cast<int32_t>(preferredPlacement), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::Hide() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->Hide());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_DialProtocol_IDialDevicePicker<D>::SetDisplayStatus(winrt::Windows::Media::DialProtocol::DialDevice const& device, winrt::Windows::Media::DialProtocol::DialDeviceDisplayStatus const& status) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePicker)->SetDisplayStatus(*(void**)(&device), static_cast<int32_t>(status)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Media_DialProtocol_IDialDevicePickerFilter<D>::SupportedAppNames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter)->get_SupportedAppNames(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::DialProtocol::DialDevice) consume_Windows_Media_DialProtocol_IDialDeviceSelectedEventArgs<D>::SelectedDialDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs)->get_SelectedDialDevice(&value));
        return winrt::Windows::Media::DialProtocol::DialDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>::GetDeviceSelector(param::hstring const& appName) const
    {
        void* selector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDeviceStatics)->GetDeviceSelector(*(void**)(&appName), &selector));
        return hstring{ selector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>) consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>::FromIdAsync(param::hstring const& value) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDeviceStatics)->FromIdAsync(*(void**)(&value), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_DialProtocol_IDialDeviceStatics<D>::DeviceInfoSupportsDialAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& device) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDeviceStatics)->DeviceInfoSupportsDialAsync(*(void**)(&device), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::DialProtocol::DialDevice) consume_Windows_Media_DialProtocol_IDialDisconnectButtonClickedEventArgs<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs)->get_Device(&value));
        return winrt::Windows::Media::DialProtocol::DialDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>) consume_Windows_Media_DialProtocol_IDialReceiverApp<D>::GetAdditionalDataAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialReceiverApp)->GetAdditionalDataAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_DialProtocol_IDialReceiverApp<D>::SetAdditionalDataAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& additionalData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialReceiverApp)->SetAdditionalDataAsync(*(void**)(&additionalData), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Media_DialProtocol_IDialReceiverApp2<D>::GetUniqueDeviceNameAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialReceiverApp2)->GetUniqueDeviceNameAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::DialProtocol::DialReceiverApp) consume_Windows_Media_DialProtocol_IDialReceiverAppStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::DialProtocol::IDialReceiverAppStatics)->get_Current(&value));
        return winrt::Windows::Media::DialProtocol::DialReceiverApp{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialApp> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialApp>
    {
        int32_t __stdcall get_AppName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestLaunchAsync(void* appArgument, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppLaunchResult>>(this->shim().RequestLaunchAsync(*reinterpret_cast<hstring const*>(&appArgument)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppStopResult>>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAppStateAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialAppStateDetails>>(this->shim().GetAppStateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialAppStateDetails> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialAppStateDetails>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::DialProtocol::DialAppState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FullXml(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FullXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDevice> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDevice>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDialApp(void* appName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::DialProtocol::DialApp>(this->shim().GetDialApp(*reinterpret_cast<hstring const*>(&appName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDevice2> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDevice2>
    {
        int32_t __stdcall get_FriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDevicePicker> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDevicePicker>
    {
        int32_t __stdcall get_Filter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::DialProtocol::DialDevicePickerFilter>(this->shim().Filter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Appearance(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DevicePickerAppearance>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DialDeviceSelected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DialDeviceSelected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DialDeviceSelected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DialDeviceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DisconnectButtonClicked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DisconnectButtonClicked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DisconnectButtonClicked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisconnectButtonClicked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DialDevicePickerDismissed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DialDevicePickerDismissed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::DialProtocol::DialDevicePicker, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DialDevicePickerDismissed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DialDevicePickerDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Show(winrt::Windows::Foundation::Rect selection) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Show(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowWithPlacement(winrt::Windows::Foundation::Rect selection, int32_t preferredPlacement) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Show(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&preferredPlacement));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleDialDeviceAsync(winrt::Windows::Foundation::Rect selection, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>>(this->shim().PickSingleDialDeviceAsync(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleDialDeviceAsyncWithPlacement(winrt::Windows::Foundation::Rect selection, int32_t preferredPlacement, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>>(this->shim().PickSingleDialDeviceAsync(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&preferredPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Hide() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hide();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDisplayStatus(void* device, int32_t status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDisplayStatus(*reinterpret_cast<winrt::Windows::Media::DialProtocol::DialDevice const*>(&device), *reinterpret_cast<winrt::Windows::Media::DialProtocol::DialDeviceDisplayStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter>
    {
        int32_t __stdcall get_SupportedAppNames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedAppNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs>
    {
        int32_t __stdcall get_SelectedDialDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::DialProtocol::DialDevice>(this->shim().SelectedDialDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDeviceStatics> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDeviceStatics>
    {
        int32_t __stdcall GetDeviceSelector(void* appName, void** selector) noexcept final try
        {
            clear_abi(selector);
            typename D::abi_guard guard(this->shim());
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&appName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* value, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::DialProtocol::DialDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeviceInfoSupportsDialAsync(void* device, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().DeviceInfoSupportsDialAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::DialProtocol::DialDevice>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialReceiverApp> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialReceiverApp>
    {
        int32_t __stdcall GetAdditionalDataAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>>(this->shim().GetAdditionalDataAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAdditionalDataAsync(void* additionalData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetAdditionalDataAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&additionalData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialReceiverApp2> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialReceiverApp2>
    {
        int32_t __stdcall GetUniqueDeviceNameAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetUniqueDeviceNameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::DialProtocol::IDialReceiverAppStatics> : produce_base<D, winrt::Windows::Media::DialProtocol::IDialReceiverAppStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::DialProtocol::DialReceiverApp>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::DialProtocol
{
    inline auto DialDevice::GetDeviceSelector(param::hstring const& appName)
    {
        return impl::call_factory<DialDevice, IDialDeviceStatics>([&](IDialDeviceStatics const& f) { return f.GetDeviceSelector(appName); });
    }
    inline auto DialDevice::FromIdAsync(param::hstring const& value)
    {
        return impl::call_factory<DialDevice, IDialDeviceStatics>([&](IDialDeviceStatics const& f) { return f.FromIdAsync(value); });
    }
    inline auto DialDevice::DeviceInfoSupportsDialAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& device)
    {
        return impl::call_factory<DialDevice, IDialDeviceStatics>([&](IDialDeviceStatics const& f) { return f.DeviceInfoSupportsDialAsync(device); });
    }
    inline DialDevicePicker::DialDevicePicker() :
        DialDevicePicker(impl::call_factory_cast<DialDevicePicker(*)(winrt::Windows::Foundation::IActivationFactory const&), DialDevicePicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DialDevicePicker>(); }))
    {
    }
    inline auto DialReceiverApp::Current()
    {
        return impl::call_factory_cast<winrt::Windows::Media::DialProtocol::DialReceiverApp(*)(IDialReceiverAppStatics const&), DialReceiverApp, IDialReceiverAppStatics>([](IDialReceiverAppStatics const& f) { return f.Current(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialAppStateDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevice2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevicePicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDevicePickerFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDeviceSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialDisconnectButtonClickedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialReceiverApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialReceiverApp2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::IDialReceiverAppStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialApp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialAppStateDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialDevicePicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialDevicePickerFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialDeviceSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialDisconnectButtonClickedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::DialProtocol::DialReceiverApp> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
