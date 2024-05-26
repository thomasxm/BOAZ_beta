// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Enumeration_Pnp_H
#define WINRT_Windows_Devices_Enumeration_Pnp_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Enumeration.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.Pnp.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType) consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Type() const
    {
        winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObject)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObject)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObject)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Update(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate const& updateInfo) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObject)->Update(*(void**)(&updateInfo)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObject>) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::CreateFromIdAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::hstring const& id, param::async_iterable<hstring> const& requestedProperties) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->CreateFromIdAsync(static_cast<int32_t>(type), *(void**)(&id), *(void**)(&requestedProperties), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObject>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection>) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::FindAllAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->FindAllAsync(static_cast<int32_t>(type), *(void**)(&requestedProperties), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection>) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::FindAllAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->FindAllAsyncAqsFilter(static_cast<int32_t>(type), *(void**)(&requestedProperties), *(void**)(&aqsFilter), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::CreateWatcher(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties) const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->CreateWatcher(static_cast<int32_t>(type), *(void**)(&requestedProperties), &watcher));
        return winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::CreateWatcher(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter) const
    {
        void* watcher{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->CreateWatcherAqsFilter(static_cast<int32_t>(type), *(void**)(&requestedProperties), *(void**)(&aqsFilter), &watcher));
        return winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher{ watcher, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>::Type() const
    {
        winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObject> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObject> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceWatcherStatus) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Status() const
    {
        winrt::Windows::Devices::Enumeration::DeviceWatcherStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->Stop());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObject> : produce_base<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObject>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Update(void* updateInfo) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Update(*reinterpret_cast<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate const*>(&updateInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics> : produce_base<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>
    {
        int32_t __stdcall CreateFromIdAsync(int32_t type, void* id, void* requestedProperties, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObject>>(this->shim().CreateFromIdAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<hstring const*>(&id), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsync(int32_t type, void* requestedProperties, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection>>(this->shim().FindAllAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsyncAqsFilter(int32_t type, void* requestedProperties, void* aqsFilter, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection>>(this->shim().FindAllAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties), *reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcher(int32_t type, void* requestedProperties, void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>(this->shim().CreateWatcher(*reinterpret_cast<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcherAqsFilter(int32_t type, void* requestedProperties, void* aqsFilter, void** watcher) noexcept final try
        {
            clear_abi(watcher);
            typename D::abi_guard guard(this->shim());
            *watcher = detach_from<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>(this->shim().CreateWatcher(*reinterpret_cast<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties), *reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate> : produce_base<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher> : produce_base<D, winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObject> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Status(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Devices::Enumeration::DeviceWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration::Pnp
{
    inline auto PnpObject::CreateFromIdAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::hstring const& id, param::async_iterable<hstring> const& requestedProperties)
    {
        return impl::call_factory<PnpObject, IPnpObjectStatics>([&](IPnpObjectStatics const& f) { return f.CreateFromIdAsync(type, id, requestedProperties); });
    }
    inline auto PnpObject::FindAllAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties)
    {
        return impl::call_factory<PnpObject, IPnpObjectStatics>([&](IPnpObjectStatics const& f) { return f.FindAllAsync(type, requestedProperties); });
    }
    inline auto PnpObject::FindAllAsync(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter)
    {
        return impl::call_factory<PnpObject, IPnpObjectStatics>([&](IPnpObjectStatics const& f) { return f.FindAllAsync(type, requestedProperties, aqsFilter); });
    }
    inline auto PnpObject::CreateWatcher(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties)
    {
        return impl::call_factory<PnpObject, IPnpObjectStatics>([&](IPnpObjectStatics const& f) { return f.CreateWatcher(type, requestedProperties); });
    }
    inline auto PnpObject::CreateWatcher(winrt::Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter)
    {
        return impl::call_factory<PnpObject, IPnpObjectStatics>([&](IPnpObjectStatics const& f) { return f.CreateWatcher(type, requestedProperties, aqsFilter); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
