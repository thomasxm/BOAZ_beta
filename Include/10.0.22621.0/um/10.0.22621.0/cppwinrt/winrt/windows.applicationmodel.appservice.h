// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_AppService_H
#define WINRT_Windows_ApplicationModel_AppService_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>) consume_Windows_ApplicationModel_AppService_IAppServiceCatalogStatics<D>::FindAppServiceProvidersAsync(param::hstring const& appServiceName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceCatalogStatics)->FindAppServiceProvidersAsync(*(void**)(&appServiceName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppService::AppServiceClosedStatus) consume_Windows_ApplicationModel_AppService_IAppServiceClosedEventArgs<D>::Status() const
    {
        winrt::Windows::ApplicationModel::AppService::AppServiceClosedStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::AppServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->get_AppServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::AppServiceName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->put_AppServiceName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::PackageFamilyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->put_PackageFamilyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceConnectionStatus>) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::OpenAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->OpenAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceConnectionStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceResponse>) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::SendMessageAsync(winrt::Windows::Foundation::Collections::ValueSet const& message) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->SendMessageAsync(*(void**)(&message), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceResponse>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppService::AppServiceConnection, winrt::Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->add_RequestReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived_revoker consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppService::AppServiceConnection, winrt::Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RequestReceived_revoker>(this, RequestReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->remove_RequestReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppService::AppServiceConnection, winrt::Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->add_ServiceClosed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed_revoker consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppService::AppServiceConnection, winrt::Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ServiceClosed_revoker>(this, ServiceClosed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection)->remove_ServiceClosed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceConnectionStatus>) consume_Windows_ApplicationModel_AppService_IAppServiceConnection2<D>::OpenRemoteAsync(winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2)->OpenRemoteAsync(*(void**)(&remoteSystemConnectionRequest), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceConnectionStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_ApplicationModel_AppService_IAppServiceConnection2<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppService_IAppServiceConnection2<D>::User(winrt::Windows::System::User const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2)->put_User(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponse>) consume_Windows_ApplicationModel_AppService_IAppServiceConnectionStatics<D>::SendStatelessMessageAsync(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& connection, winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& connectionRequest, winrt::Windows::Foundation::Collections::ValueSet const& message) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceConnectionStatics)->SendStatelessMessageAsync(*(void**)(&connection), *(void**)(&connectionRequest), *(void**)(&message), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponse>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_AppService_IAppServiceDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_ApplicationModel_AppService_IAppServiceRequest<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceRequest)->get_Message(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceResponseStatus>) consume_Windows_ApplicationModel_AppService_IAppServiceRequest<D>::SendResponseAsync(winrt::Windows::Foundation::Collections::ValueSet const& message) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceRequest)->SendResponseAsync(*(void**)(&message), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceResponseStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppService::AppServiceRequest) consume_Windows_ApplicationModel_AppService_IAppServiceRequestReceivedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs)->get_Request(&value));
        return winrt::Windows::ApplicationModel::AppService::AppServiceRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppService::AppServiceDeferral) consume_Windows_ApplicationModel_AppService_IAppServiceRequestReceivedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs)->GetDeferral(&result));
        return winrt::Windows::ApplicationModel::AppService::AppServiceDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_ApplicationModel_AppService_IAppServiceResponse<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceResponse)->get_Message(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppService::AppServiceResponseStatus) consume_Windows_ApplicationModel_AppService_IAppServiceResponse<D>::Status() const
    {
        winrt::Windows::ApplicationModel::AppService::AppServiceResponseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceResponse)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails<D>::CallerPackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails)->get_CallerPackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppService::AppServiceConnection) consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails<D>::AppServiceConnection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails)->get_AppServiceConnection(&value));
        return winrt::Windows::ApplicationModel::AppService::AppServiceConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails2<D>::IsRemoteSystemConnection() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2)->get_IsRemoteSystemConnection(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails3<D>::CheckCallerForCapabilityAsync(param::hstring const& capabilityName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3)->CheckCallerForCapabilityAsync(*(void**)(&capabilityName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails4<D>::CallerRemoteConnectionToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4)->get_CallerRemoteConnectionToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_ApplicationModel_AppService_IStatelessAppServiceResponse<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse)->get_Message(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus) consume_Windows_ApplicationModel_AppService_IStatelessAppServiceResponse<D>::Status() const
    {
        winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceCatalogStatics> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceCatalogStatics>
    {
        int32_t __stdcall FindAppServiceProvidersAsync(void* appServiceName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::AppInfo>>>(this->shim().FindAppServiceProvidersAsync(*reinterpret_cast<hstring const*>(&appServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppService::AppServiceClosedStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceConnection> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceConnection>
    {
        int32_t __stdcall get_AppServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppServiceName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppServiceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PackageFamilyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceConnectionStatus>>(this->shim().OpenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendMessageAsync(void* message, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceResponse>>(this->shim().SendMessageAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RequestReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RequestReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppService::AppServiceConnection, winrt::Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RequestReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ServiceClosed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ServiceClosed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::AppService::AppServiceConnection, winrt::Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ServiceClosed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServiceClosed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2>
    {
        int32_t __stdcall OpenRemoteAsync(void* remoteSystemConnectionRequest, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceConnectionStatus>>(this->shim().OpenRemoteAsync(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest)));
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
        int32_t __stdcall put_User(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().User(*reinterpret_cast<winrt::Windows::System::User const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceConnectionStatics> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceConnectionStatics>
    {
        int32_t __stdcall SendStatelessMessageAsync(void* connection, void* connectionRequest, void* message, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponse>>(this->shim().SendStatelessMessageAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::AppService::AppServiceConnection const*>(&connection), *reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&connectionRequest), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceDeferral> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceRequest> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceRequest>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendResponseAsync(void* message, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::AppService::AppServiceResponseStatus>>(this->shim().SendResponseAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppService::AppServiceRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::AppService::AppServiceDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceResponse> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceResponse>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppService::AppServiceResponseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CallerPackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CallerPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppServiceConnection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppService::AppServiceConnection>(this->shim().AppServiceConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2>
    {
        int32_t __stdcall get_IsRemoteSystemConnection(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRemoteSystemConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3>
    {
        int32_t __stdcall CheckCallerForCapabilityAsync(void* capabilityName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().CheckCallerForCapabilityAsync(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4>
    {
        int32_t __stdcall get_CallerRemoteConnectionToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CallerRemoteConnectionToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse> : produce_base<D, winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppService
{
    inline auto AppServiceCatalog::FindAppServiceProvidersAsync(param::hstring const& appServiceName)
    {
        return impl::call_factory<AppServiceCatalog, IAppServiceCatalogStatics>([&](IAppServiceCatalogStatics const& f) { return f.FindAppServiceProvidersAsync(appServiceName); });
    }
    inline AppServiceConnection::AppServiceConnection() :
        AppServiceConnection(impl::call_factory_cast<AppServiceConnection(*)(winrt::Windows::Foundation::IActivationFactory const&), AppServiceConnection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AppServiceConnection>(); }))
    {
    }
    inline auto AppServiceConnection::SendStatelessMessageAsync(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& connection, winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& connectionRequest, winrt::Windows::Foundation::Collections::ValueSet const& message)
    {
        return impl::call_factory<AppServiceConnection, IAppServiceConnectionStatics>([&](IAppServiceConnectionStatics const& f) { return f.SendStatelessMessageAsync(connection, connectionRequest, message); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceCatalogStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceConnectionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceResponse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceCatalog> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceResponse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponse> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
