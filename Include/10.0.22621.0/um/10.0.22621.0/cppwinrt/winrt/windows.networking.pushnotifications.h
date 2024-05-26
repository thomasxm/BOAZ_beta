// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_PushNotifications_H
#define WINRT_Windows_Networking_PushNotifications_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Networking.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.Networking.PushNotifications.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannel)->get_Uri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::ExpirationTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannel)->get_ExpirationTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannel)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannel, winrt::Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannel)->add_PushNotificationReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived_revoker consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannel, winrt::Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PushNotificationReceived_revoker>(this, PushNotificationReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannel)->remove_PushNotificationReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::CreatePushNotificationChannelForApplicationAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->CreatePushNotificationChannelForApplicationAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->CreatePushNotificationChannelForApplicationAsyncWithId(*(void**)(&applicationId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->CreatePushNotificationChannelForSecondaryTileAsync(*(void**)(&tileId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser2<D>::CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(winrt::Windows::Storage::Streams::IBuffer const& appServerKey, param::hstring const& channelId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2)->CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(*(void**)(&appServerKey), *(void**)(&channelId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser2<D>::CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(winrt::Windows::Storage::Streams::IBuffer const& appServerKey, param::hstring const& channelId, param::hstring const& appId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2)->CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsyncWithId(*(void**)(&appServerKey), *(void**)(&channelId), *(void**)(&appId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>::CreatePushNotificationChannelForApplicationAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics)->CreatePushNotificationChannelForApplicationAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>::CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics)->CreatePushNotificationChannelForApplicationAsyncWithId(*(void**)(&applicationId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>::CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics)->CreatePushNotificationChannelForSecondaryTileAsync(*(void**)(&tileId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics2<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics3<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3)->GetDefault(&result));
        return winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics4<D>::ChannelsRevoked(winrt::Windows::Foundation::EventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannelsRevokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics4)->add_ChannelsRevoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics4<D>::ChannelsRevoked_revoker consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics4<D>::ChannelsRevoked(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannelsRevokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ChannelsRevoked_revoker>(this, ChannelsRevoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics4<D>::ChannelsRevoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics4)->remove_ChannelsRevoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::PushNotifications::PushNotificationType) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::NotificationType() const
    {
        winrt::Windows::Networking::PushNotifications::PushNotificationType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_NotificationType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotification) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::ToastNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_ToastNotification(&value));
        return winrt::Windows::UI::Notifications::ToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileNotification) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::TileNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_TileNotification(&value));
        return winrt::Windows::UI::Notifications::TileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::BadgeNotification) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::BadgeNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_BadgeNotification(&value));
        return winrt::Windows::UI::Notifications::BadgeNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::PushNotifications::RawNotification) consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::RawNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_RawNotification(&value));
        return winrt::Windows::Networking::PushNotifications::RawNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_PushNotifications_IRawNotification<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IRawNotification)->get_Content(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) consume_Windows_Networking_PushNotifications_IRawNotification2<D>::Headers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IRawNotification2)->get_Headers(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_PushNotifications_IRawNotification2<D>::ChannelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IRawNotification2)->get_ChannelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Networking_PushNotifications_IRawNotification3<D>::ContentBytes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::PushNotifications::IRawNotification3)->get_ContentBytes(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannel> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannel>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().ExpirationTime());
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
        int32_t __stdcall add_PushNotificationReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PushNotificationReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannel, winrt::Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PushNotificationReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PushNotificationReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser>
    {
        int32_t __stdcall CreatePushNotificationChannelForApplicationAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePushNotificationChannelForApplicationAsyncWithId(void* applicationId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePushNotificationChannelForSecondaryTileAsync(void* tileId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2>
    {
        int32_t __stdcall CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(void* appServerKey, void* channelId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&appServerKey), *reinterpret_cast<hstring const*>(&channelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsyncWithId(void* appServerKey, void* channelId, void* appId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&appServerKey), *reinterpret_cast<hstring const*>(&channelId), *reinterpret_cast<hstring const*>(&appId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>
    {
        int32_t __stdcall CreatePushNotificationChannelForApplicationAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePushNotificationChannelForApplicationAsyncWithId(void* applicationId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePushNotificationChannelForSecondaryTileAsync(void* tileId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics4> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics4>
    {
        int32_t __stdcall add_ChannelsRevoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ChannelsRevoked(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannelsRevokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ChannelsRevoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChannelsRevoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelsRevokedEventArgs> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelsRevokedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs> : produce_base<D, winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs>
    {
        int32_t __stdcall put_Cancel(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cancel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NotificationType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::PushNotifications::PushNotificationType>(this->shim().NotificationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToastNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotification>(this->shim().ToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TileNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileNotification>(this->shim().TileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BadgeNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::BadgeNotification>(this->shim().BadgeNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::PushNotifications::RawNotification>(this->shim().RawNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IRawNotification> : produce_base<D, winrt::Windows::Networking::PushNotifications::IRawNotification>
    {
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IRawNotification2> : produce_base<D, winrt::Windows::Networking::PushNotifications::IRawNotification2>
    {
        int32_t __stdcall get_Headers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChannelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ChannelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::PushNotifications::IRawNotification3> : produce_base<D, winrt::Windows::Networking::PushNotifications::IRawNotification3>
    {
        int32_t __stdcall get_ContentBytes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ContentBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Networking::PushNotifications
{
    inline auto PushNotificationChannelManager::CreatePushNotificationChannelForApplicationAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::PushNotifications::PushNotificationChannel>(*)(IPushNotificationChannelManagerStatics const&), PushNotificationChannelManager, IPushNotificationChannelManagerStatics>([](IPushNotificationChannelManagerStatics const& f) { return f.CreatePushNotificationChannelForApplicationAsync(); });
    }
    inline auto PushNotificationChannelManager::CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId)
    {
        return impl::call_factory<PushNotificationChannelManager, IPushNotificationChannelManagerStatics>([&](IPushNotificationChannelManagerStatics const& f) { return f.CreatePushNotificationChannelForApplicationAsync(applicationId); });
    }
    inline auto PushNotificationChannelManager::CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId)
    {
        return impl::call_factory<PushNotificationChannelManager, IPushNotificationChannelManagerStatics>([&](IPushNotificationChannelManagerStatics const& f) { return f.CreatePushNotificationChannelForSecondaryTileAsync(tileId); });
    }
    inline auto PushNotificationChannelManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<PushNotificationChannelManager, IPushNotificationChannelManagerStatics2>([&](IPushNotificationChannelManagerStatics2 const& f) { return f.GetForUser(user); });
    }
    inline auto PushNotificationChannelManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser(*)(IPushNotificationChannelManagerStatics3 const&), PushNotificationChannelManager, IPushNotificationChannelManagerStatics3>([](IPushNotificationChannelManagerStatics3 const& f) { return f.GetDefault(); });
    }
    inline auto PushNotificationChannelManager::ChannelsRevoked(winrt::Windows::Foundation::EventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannelsRevokedEventArgs> const& handler)
    {
        return impl::call_factory<PushNotificationChannelManager, IPushNotificationChannelManagerStatics4>([&](IPushNotificationChannelManagerStatics4 const& f) { return f.ChannelsRevoked(handler); });
    }
    inline PushNotificationChannelManager::ChannelsRevoked_revoker PushNotificationChannelManager::ChannelsRevoked(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Networking::PushNotifications::PushNotificationChannelsRevokedEventArgs> const& handler)
    {
        auto f = get_activation_factory<PushNotificationChannelManager, winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics4>();
        return { f, f.ChannelsRevoked(handler) };
    }
    inline auto PushNotificationChannelManager::ChannelsRevoked(winrt::event_token const& token)
    {
        impl::call_factory<PushNotificationChannelManager, IPushNotificationChannelManagerStatics4>([&](IPushNotificationChannelManagerStatics4 const& f) { return f.ChannelsRevoked(token); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelsRevokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IRawNotification> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IRawNotification2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::IRawNotification3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannelsRevokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::PushNotifications::RawNotification> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
