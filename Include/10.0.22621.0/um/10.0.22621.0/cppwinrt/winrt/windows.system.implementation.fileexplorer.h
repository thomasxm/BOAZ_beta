// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Implementation_FileExplorer_H
#define WINRT_Windows_System_Implementation_FileExplorer_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.System.Implementation.FileExplorer.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderEventReceivedEventArgs<D>::Json() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgs)->get_Json(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderEventReceivedEventArgsFactory<D>::CreateInstance(param::hstring const& json) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgsFactory)->CreateInstance(*(void**)(&json), &value));
        return winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderEventSource<D>::EventReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource, winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource)->add_EventReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderEventSource<D>::EventReceived_revoker consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderEventSource<D>::EventReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource, winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, EventReceived_revoker>(this, EventReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderEventSource<D>::EventReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource)->remove_EventReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderHandlerFactory<D>::GetHttpRequestProvider(param::hstring const& syncRootId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHandlerFactory)->GetHttpRequestProvider(*(void**)(&syncRootId), &result));
        return winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderHandlerFactory<D>::GetEventSource(param::hstring const& syncRootId, param::hstring const& eventName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHandlerFactory)->GetEventSource(*(void**)(&syncRootId), *(void**)(&eventName), &result));
        return winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::Http::HttpResponseMessage>) consume_Windows_System_Implementation_FileExplorer_ISysStorageProviderHttpRequestProvider<D>::SendRequestAsync(winrt::Windows::Web::Http::HttpRequestMessage const& request) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider)->SendRequestAsync(*(void**)(&request), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::Http::HttpResponseMessage>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgs> : produce_base<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgs>
    {
        int32_t __stdcall get_Json(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Json());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgsFactory> : produce_base<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* json, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&json)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource> : produce_base<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource>
    {
        int32_t __stdcall add_EventReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EventReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource, winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EventReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EventReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
    template <typename D>
    struct produce<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHandlerFactory> : produce_base<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHandlerFactory>
    {
        int32_t __stdcall GetHttpRequestProvider(void* syncRootId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider>(this->shim().GetHttpRequestProvider(*reinterpret_cast<hstring const*>(&syncRootId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEventSource(void* syncRootId, void* eventName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource>(this->shim().GetEventSource(*reinterpret_cast<hstring const*>(&syncRootId), *reinterpret_cast<hstring const*>(&eventName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider> : produce_base<D, winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider>
    {
        int32_t __stdcall SendRequestAsync(void* request, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Web::Http::HttpResponseMessage>>(this->shim().SendRequestAsync(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::System::Implementation::FileExplorer
{
    inline SysStorageProviderEventReceivedEventArgs::SysStorageProviderEventReceivedEventArgs(param::hstring const& json) :
        SysStorageProviderEventReceivedEventArgs(impl::call_factory<SysStorageProviderEventReceivedEventArgs, ISysStorageProviderEventReceivedEventArgsFactory>([&](ISysStorageProviderEventReceivedEventArgsFactory const& f) { return f.CreateInstance(json); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHandlerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderHttpRequestProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Implementation::FileExplorer::SysStorageProviderEventReceivedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
