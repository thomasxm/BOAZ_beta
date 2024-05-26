// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Diagnostics_DevicePortal_H
#define WINRT_Windows_System_Diagnostics_DevicePortal_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.Diagnostics.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.System.Diagnostics.DevicePortal.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed_revoker consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->add_RequestReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived_revoker consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RequestReceived_revoker>(this, RequestReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->remove_RequestReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionClosedEventArgs<D>::Reason() const
    {
        winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpRequestMessage) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionRequestReceivedEventArgs<D>::RequestMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs)->get_RequestMessage(&value));
        return winrt::Windows::Web::Http::HttpRequestMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpResponseMessage) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionRequestReceivedEventArgs<D>::ResponseMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs)->get_ResponseMessage(&value));
        return winrt::Windows::Web::Http::HttpResponseMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionStatics<D>::GetForAppServiceConnection(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics)->GetForAppServiceConnection(*(void**)(&appServiceConnection), &value));
        return winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerMessageWebSocket) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerMessageWebSocketForRequest(winrt::Windows::Web::Http::HttpRequestMessage const& request) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerMessageWebSocketForRequest(*(void**)(&request), &result));
        return winrt::Windows::Networking::Sockets::ServerMessageWebSocket{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerMessageWebSocket) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerMessageWebSocketForRequest(winrt::Windows::Web::Http::HttpRequestMessage const& request, winrt::Windows::Networking::Sockets::SocketMessageType const& messageType, param::hstring const& protocol) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerMessageWebSocketForRequest2(*(void**)(&request), static_cast<int32_t>(messageType), *(void**)(&protocol), &result));
        return winrt::Windows::Networking::Sockets::ServerMessageWebSocket{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerMessageWebSocket) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerMessageWebSocketForRequest(winrt::Windows::Web::Http::HttpRequestMessage const& request, winrt::Windows::Networking::Sockets::SocketMessageType const& messageType, param::hstring const& protocol, uint32_t outboundBufferSizeInBytes, uint32_t maxMessageSize, winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode const& receiveMode) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerMessageWebSocketForRequest3(*(void**)(&request), static_cast<int32_t>(messageType), *(void**)(&protocol), outboundBufferSizeInBytes, maxMessageSize, static_cast<int32_t>(receiveMode), &result));
        return winrt::Windows::Networking::Sockets::ServerMessageWebSocket{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerStreamWebSocket) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerStreamWebSocketForRequest(winrt::Windows::Web::Http::HttpRequestMessage const& request) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerStreamWebSocketForRequest(*(void**)(&request), &result));
        return winrt::Windows::Networking::Sockets::ServerStreamWebSocket{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::ServerStreamWebSocket) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerStreamWebSocketForRequest(winrt::Windows::Web::Http::HttpRequestMessage const& request, param::hstring const& protocol, uint32_t outboundBufferSizeInBytes, bool noDelay) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerStreamWebSocketForRequest2(*(void**)(&request), *(void**)(&protocol), outboundBufferSizeInBytes, noDelay, &result));
        return winrt::Windows::Networking::Sockets::ServerStreamWebSocket{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>::IsWebSocketUpgradeRequest() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs)->get_IsWebSocketUpgradeRequest(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>::WebSocketProtocolsRequested() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs)->get_WebSocketProtocolsRequested(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection> : produce_base<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RequestReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RequestReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RequestReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs> : produce_base<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs> : produce_base<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs>
    {
        int32_t __stdcall get_RequestMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpResponseMessage>(this->shim().ResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics> : produce_base<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>
    {
        int32_t __stdcall GetForAppServiceConnection(void* appServiceConnection, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection>(this->shim().GetForAppServiceConnection(*reinterpret_cast<winrt::Windows::ApplicationModel::AppService::AppServiceConnection const*>(&appServiceConnection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection> : produce_base<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>
    {
        int32_t __stdcall GetServerMessageWebSocketForRequest(void* request, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::Sockets::ServerMessageWebSocket>(this->shim().GetServerMessageWebSocketForRequest(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetServerMessageWebSocketForRequest2(void* request, int32_t messageType, void* protocol, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::Sockets::ServerMessageWebSocket>(this->shim().GetServerMessageWebSocketForRequest(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketMessageType const*>(&messageType), *reinterpret_cast<hstring const*>(&protocol)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetServerMessageWebSocketForRequest3(void* request, int32_t messageType, void* protocol, uint32_t outboundBufferSizeInBytes, uint32_t maxMessageSize, int32_t receiveMode, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::Sockets::ServerMessageWebSocket>(this->shim().GetServerMessageWebSocketForRequest(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<winrt::Windows::Networking::Sockets::SocketMessageType const*>(&messageType), *reinterpret_cast<hstring const*>(&protocol), outboundBufferSizeInBytes, maxMessageSize, *reinterpret_cast<winrt::Windows::Networking::Sockets::MessageWebSocketReceiveMode const*>(&receiveMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetServerStreamWebSocketForRequest(void* request, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::Sockets::ServerStreamWebSocket>(this->shim().GetServerStreamWebSocketForRequest(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetServerStreamWebSocketForRequest2(void* request, void* protocol, uint32_t outboundBufferSizeInBytes, bool noDelay, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::Sockets::ServerStreamWebSocket>(this->shim().GetServerStreamWebSocketForRequest(*reinterpret_cast<winrt::Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<hstring const*>(&protocol), outboundBufferSizeInBytes, noDelay));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs> : produce_base<D, winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>
    {
        int32_t __stdcall get_IsWebSocketUpgradeRequest(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsWebSocketUpgradeRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WebSocketProtocolsRequested(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().WebSocketProtocolsRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::DevicePortal
{
    inline auto DevicePortalConnection::GetForAppServiceConnection(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection)
    {
        return impl::call_factory<DevicePortalConnection, IDevicePortalConnectionStatics>([&](IDevicePortalConnectionStatics const& f) { return f.GetForAppServiceConnection(appServiceConnection); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
