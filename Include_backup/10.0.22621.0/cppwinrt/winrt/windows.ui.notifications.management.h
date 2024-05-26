// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_Management_H
#define WINRT_Windows_UI_Notifications_Management_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Notifications.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.UI.Notifications.Management.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::GetAccessStatus() const
    {
        winrt::Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->GetAccessStatus(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::Management::UserNotificationListener, winrt::Windows::UI::Notifications::UserNotificationChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->add_NotificationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged_revoker consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::Management::UserNotificationListener, winrt::Windows::UI::Notifications::UserNotificationChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NotificationChanged_revoker>(this, NotificationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->remove_NotificationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::UserNotification>>) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::GetNotificationsAsync(winrt::Windows::UI::Notifications::NotificationKinds const& kinds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->GetNotificationsAsync(static_cast<uint32_t>(kinds), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::UserNotification>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::UserNotification) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::GetNotification(uint32_t notificationId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->GetNotification(notificationId, &result));
        return winrt::Windows::UI::Notifications::UserNotification{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::ClearNotifications() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->ClearNotifications());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::RemoveNotification(uint32_t notificationId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListener)->RemoveNotification(notificationId));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::Management::UserNotificationListener) consume_Windows_UI_Notifications_Management_IUserNotificationListenerStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Notifications::Management::IUserNotificationListenerStatics)->get_Current(&value));
        return winrt::Windows::UI::Notifications::Management::UserNotificationListener{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::Management::IUserNotificationListener> : produce_base<D, winrt::Windows::UI::Notifications::Management::IUserNotificationListener>
    {
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAccessStatus(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>(this->shim().GetAccessStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_NotificationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NotificationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Notifications::Management::UserNotificationListener, winrt::Windows::UI::Notifications::UserNotificationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NotificationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotificationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetNotificationsAsync(uint32_t kinds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Notifications::UserNotification>>>(this->shim().GetNotificationsAsync(*reinterpret_cast<winrt::Windows::UI::Notifications::NotificationKinds const*>(&kinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNotification(uint32_t notificationId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Notifications::UserNotification>(this->shim().GetNotification(notificationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearNotifications() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearNotifications();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveNotification(uint32_t notificationId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveNotification(notificationId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Notifications::Management::IUserNotificationListenerStatics> : produce_base<D, winrt::Windows::UI::Notifications::Management::IUserNotificationListenerStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::Management::UserNotificationListener>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management
{
    inline auto UserNotificationListener::Current()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Notifications::Management::UserNotificationListener(*)(IUserNotificationListenerStatics const&), UserNotificationListener, IUserNotificationListenerStatics>([](IUserNotificationListenerStatics const& f) { return f.Current(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Notifications::Management::IUserNotificationListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::Management::IUserNotificationListenerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Notifications::Management::UserNotificationListener> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
