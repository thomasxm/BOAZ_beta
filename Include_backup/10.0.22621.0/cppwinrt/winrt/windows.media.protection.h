// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Protection_H
#define WINRT_Windows_Media_Protection_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::RevocationAndRenewalInformation) consume_Windows_Media_Protection_IComponentLoadFailedEventArgs<D>::Information() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs)->get_Information(&value));
        return winrt::Windows::Media::Protection::RevocationAndRenewalInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::MediaProtectionServiceCompletion) consume_Windows_Media_Protection_IComponentLoadFailedEventArgs<D>::Completion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs)->get_Completion(&value));
        return winrt::Windows::Media::Protection::MediaProtectionServiceCompletion{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Media::Protection::RenewalStatus, uint32_t>) consume_Windows_Media_Protection_IComponentRenewalStatics<D>::RenewSystemComponentsAsync(winrt::Windows::Media::Protection::RevocationAndRenewalInformation const& information) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IComponentRenewalStatics)->RenewSystemComponentsAsync(*(void**)(&information), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Media::Protection::RenewalStatus, uint32_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Protection_IHdcpSession<D>::IsEffectiveProtectionAtLeast(winrt::Windows::Media::Protection::HdcpProtection const& protection) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IHdcpSession)->IsEffectiveProtectionAtLeast(static_cast<int32_t>(protection), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::Protection::HdcpProtection>) consume_Windows_Media_Protection_IHdcpSession<D>::GetEffectiveProtection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IHdcpSession)->GetEffectiveProtection(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::Protection::HdcpProtection>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::HdcpSetProtectionResult>) consume_Windows_Media_Protection_IHdcpSession<D>::SetDesiredMinProtectionAsync(winrt::Windows::Media::Protection::HdcpProtection const& protection) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IHdcpSession)->SetDesiredMinProtectionAsync(static_cast<int32_t>(protection), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::HdcpSetProtectionResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_IHdcpSession<D>::ProtectionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::HdcpSession, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IHdcpSession)->add_ProtectionChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Protection_IHdcpSession<D>::ProtectionChanged_revoker consume_Windows_Media_Protection_IHdcpSession<D>::ProtectionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::HdcpSession, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ProtectionChanged_revoker>(this, ProtectionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_IHdcpSession<D>::ProtectionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IHdcpSession)->remove_ProtectionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_IMediaProtectionManager<D>::ServiceRequested(winrt::Windows::Media::Protection::ServiceRequestedEventHandler const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->add_ServiceRequested(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_Protection_IMediaProtectionManager<D>::ServiceRequested_revoker consume_Windows_Media_Protection_IMediaProtectionManager<D>::ServiceRequested(auto_revoke_t, winrt::Windows::Media::Protection::ServiceRequestedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ServiceRequested_revoker>(this, ServiceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_IMediaProtectionManager<D>::ServiceRequested(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->remove_ServiceRequested(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_IMediaProtectionManager<D>::RebootNeeded(winrt::Windows::Media::Protection::RebootNeededEventHandler const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->add_RebootNeeded(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_Protection_IMediaProtectionManager<D>::RebootNeeded_revoker consume_Windows_Media_Protection_IMediaProtectionManager<D>::RebootNeeded(auto_revoke_t, winrt::Windows::Media::Protection::RebootNeededEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, RebootNeeded_revoker>(this, RebootNeeded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_IMediaProtectionManager<D>::RebootNeeded(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->remove_RebootNeeded(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Protection_IMediaProtectionManager<D>::ComponentLoadFailed(winrt::Windows::Media::Protection::ComponentLoadFailedEventHandler const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->add_ComponentLoadFailed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_Protection_IMediaProtectionManager<D>::ComponentLoadFailed_revoker consume_Windows_Media_Protection_IMediaProtectionManager<D>::ComponentLoadFailed(auto_revoke_t, winrt::Windows::Media::Protection::ComponentLoadFailedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ComponentLoadFailed_revoker>(this, ComponentLoadFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_IMediaProtectionManager<D>::ComponentLoadFailed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->remove_ComponentLoadFailed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_Protection_IMediaProtectionManager<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionManager)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_Protection_IMediaProtectionPMPServer<D>::Properties() const
    {
        void* ppProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionPMPServer)->get_Properties(&ppProperties));
        return winrt::Windows::Foundation::Collections::IPropertySet{ ppProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::MediaProtectionPMPServer) consume_Windows_Media_Protection_IMediaProtectionPMPServerFactory<D>::CreatePMPServer(winrt::Windows::Foundation::Collections::IPropertySet const& pProperties) const
    {
        void* ppObject{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionPMPServerFactory)->CreatePMPServer(*(void**)(&pProperties), &ppObject));
        return winrt::Windows::Media::Protection::MediaProtectionPMPServer{ ppObject, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Protection_IMediaProtectionServiceCompletion<D>::Complete(bool success) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionServiceCompletion)->Complete(success));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_IMediaProtectionServiceRequest<D>::ProtectionSystem() const
    {
        winrt::guid system{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionServiceRequest)->get_ProtectionSystem(put_abi(system)));
        return system;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Media_Protection_IMediaProtectionServiceRequest<D>::Type() const
    {
        winrt::guid type{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IMediaProtectionServiceRequest)->get_Type(put_abi(type)));
        return type;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::ProtectionCapabilityResult) consume_Windows_Media_Protection_IProtectionCapabilities<D>::IsTypeSupported(param::hstring const& type, param::hstring const& keySystem) const
    {
        winrt::Windows::Media::Protection::ProtectionCapabilityResult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IProtectionCapabilities)->IsTypeSupported(*(void**)(&type), *(void**)(&keySystem), reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Protection::RevocationAndRenewalItem>) consume_Windows_Media_Protection_IRevocationAndRenewalInformation<D>::Items() const
    {
        void* items{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IRevocationAndRenewalInformation)->get_Items(&items));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Protection::RevocationAndRenewalItem>{ items, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::RevocationAndRenewalReasons) consume_Windows_Media_Protection_IRevocationAndRenewalItem<D>::Reasons() const
    {
        winrt::Windows::Media::Protection::RevocationAndRenewalReasons reasons{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IRevocationAndRenewalItem)->get_Reasons(reinterpret_cast<uint32_t*>(&reasons)));
        return reasons;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_IRevocationAndRenewalItem<D>::HeaderHash() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IRevocationAndRenewalItem)->get_HeaderHash(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_IRevocationAndRenewalItem<D>::PublicKeyHash() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IRevocationAndRenewalItem)->get_PublicKeyHash(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_IRevocationAndRenewalItem<D>::Name() const
    {
        void* name{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IRevocationAndRenewalItem)->get_Name(&name));
        return hstring{ name, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Protection_IRevocationAndRenewalItem<D>::RenewalId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IRevocationAndRenewalItem)->get_RenewalId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::IMediaProtectionServiceRequest) consume_Windows_Media_Protection_IServiceRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IServiceRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::Media::Protection::IMediaProtectionServiceRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::MediaProtectionServiceCompletion) consume_Windows_Media_Protection_IServiceRequestedEventArgs<D>::Completion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IServiceRequestedEventArgs)->get_Completion(&value));
        return winrt::Windows::Media::Protection::MediaProtectionServiceCompletion{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Protection_IServiceRequestedEventArgs2<D>::MediaPlaybackItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Protection::IServiceRequestedEventArgs2)->get_MediaPlaybackItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Media::Protection::ComponentLoadFailedEventHandler, H> final : implements_delegate<winrt::Windows::Media::Protection::ComponentLoadFailedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Media::Protection::ComponentLoadFailedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Media::Protection::MediaProtectionManager const*>(&sender), *reinterpret_cast<winrt::Windows::Media::Protection::ComponentLoadFailedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Media::Protection::RebootNeededEventHandler, H> final : implements_delegate<winrt::Windows::Media::Protection::RebootNeededEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Media::Protection::RebootNeededEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Media::Protection::MediaProtectionManager const*>(&sender));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Media::Protection::ServiceRequestedEventHandler, H> final : implements_delegate<winrt::Windows::Media::Protection::ServiceRequestedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Media::Protection::ServiceRequestedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Media::Protection::MediaProtectionManager const*>(&sender), *reinterpret_cast<winrt::Windows::Media::Protection::ServiceRequestedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs> : produce_base<D, winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs>
    {
        int32_t __stdcall get_Information(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::RevocationAndRenewalInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Completion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::MediaProtectionServiceCompletion>(this->shim().Completion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IComponentRenewalStatics> : produce_base<D, winrt::Windows::Media::Protection::IComponentRenewalStatics>
    {
        int32_t __stdcall RenewSystemComponentsAsync(void* information, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Media::Protection::RenewalStatus, uint32_t>>(this->shim().RenewSystemComponentsAsync(*reinterpret_cast<winrt::Windows::Media::Protection::RevocationAndRenewalInformation const*>(&information)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IHdcpSession> : produce_base<D, winrt::Windows::Media::Protection::IHdcpSession>
    {
        int32_t __stdcall IsEffectiveProtectionAtLeast(int32_t protection, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEffectiveProtectionAtLeast(*reinterpret_cast<winrt::Windows::Media::Protection::HdcpProtection const*>(&protection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEffectiveProtection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::Protection::HdcpProtection>>(this->shim().GetEffectiveProtection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDesiredMinProtectionAsync(int32_t protection, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Protection::HdcpSetProtectionResult>>(this->shim().SetDesiredMinProtectionAsync(*reinterpret_cast<winrt::Windows::Media::Protection::HdcpProtection const*>(&protection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ProtectionChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ProtectionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Protection::HdcpSession, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ProtectionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProtectionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IMediaProtectionManager> : produce_base<D, winrt::Windows::Media::Protection::IMediaProtectionManager>
    {
        int32_t __stdcall add_ServiceRequested(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ServiceRequested(*reinterpret_cast<winrt::Windows::Media::Protection::ServiceRequestedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ServiceRequested(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServiceRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_RebootNeeded(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().RebootNeeded(*reinterpret_cast<winrt::Windows::Media::Protection::RebootNeededEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RebootNeeded(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RebootNeeded(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ComponentLoadFailed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ComponentLoadFailed(*reinterpret_cast<winrt::Windows::Media::Protection::ComponentLoadFailedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ComponentLoadFailed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ComponentLoadFailed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IMediaProtectionPMPServer> : produce_base<D, winrt::Windows::Media::Protection::IMediaProtectionPMPServer>
    {
        int32_t __stdcall get_Properties(void** ppProperties) noexcept final try
        {
            clear_abi(ppProperties);
            typename D::abi_guard guard(this->shim());
            *ppProperties = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IMediaProtectionPMPServerFactory> : produce_base<D, winrt::Windows::Media::Protection::IMediaProtectionPMPServerFactory>
    {
        int32_t __stdcall CreatePMPServer(void* pProperties, void** ppObject) noexcept final try
        {
            clear_abi(ppObject);
            typename D::abi_guard guard(this->shim());
            *ppObject = detach_from<winrt::Windows::Media::Protection::MediaProtectionPMPServer>(this->shim().CreatePMPServer(*reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&pProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IMediaProtectionServiceCompletion> : produce_base<D, winrt::Windows::Media::Protection::IMediaProtectionServiceCompletion>
    {
        int32_t __stdcall Complete(bool success) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete(success);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest> : produce_base<D, winrt::Windows::Media::Protection::IMediaProtectionServiceRequest>
    {
        int32_t __stdcall get_ProtectionSystem(winrt::guid* system) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *system = detach_from<winrt::guid>(this->shim().ProtectionSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(winrt::guid* type) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *type = detach_from<winrt::guid>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IProtectionCapabilities> : produce_base<D, winrt::Windows::Media::Protection::IProtectionCapabilities>
    {
        int32_t __stdcall IsTypeSupported(void* type, void* keySystem, int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::ProtectionCapabilityResult>(this->shim().IsTypeSupported(*reinterpret_cast<hstring const*>(&type), *reinterpret_cast<hstring const*>(&keySystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IRevocationAndRenewalInformation> : produce_base<D, winrt::Windows::Media::Protection::IRevocationAndRenewalInformation>
    {
        int32_t __stdcall get_Items(void** items) noexcept final try
        {
            clear_abi(items);
            typename D::abi_guard guard(this->shim());
            *items = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Protection::RevocationAndRenewalItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IRevocationAndRenewalItem> : produce_base<D, winrt::Windows::Media::Protection::IRevocationAndRenewalItem>
    {
        int32_t __stdcall get_Reasons(uint32_t* reasons) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *reasons = detach_from<winrt::Windows::Media::Protection::RevocationAndRenewalReasons>(this->shim().Reasons());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderHash(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HeaderHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicKeyHash(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicKeyHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** name) noexcept final try
        {
            clear_abi(name);
            typename D::abi_guard guard(this->shim());
            *name = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenewalId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RenewalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IServiceRequestedEventArgs> : produce_base<D, winrt::Windows::Media::Protection::IServiceRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::IMediaProtectionServiceRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Completion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::MediaProtectionServiceCompletion>(this->shim().Completion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Protection::IServiceRequestedEventArgs2> : produce_base<D, winrt::Windows::Media::Protection::IServiceRequestedEventArgs2>
    {
        int32_t __stdcall get_MediaPlaybackItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().MediaPlaybackItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Protection
{
    constexpr auto operator|(RevocationAndRenewalReasons const left, RevocationAndRenewalReasons const right) noexcept
    {
        return static_cast<RevocationAndRenewalReasons>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(RevocationAndRenewalReasons& left, RevocationAndRenewalReasons const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(RevocationAndRenewalReasons const left, RevocationAndRenewalReasons const right) noexcept
    {
        return static_cast<RevocationAndRenewalReasons>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(RevocationAndRenewalReasons& left, RevocationAndRenewalReasons const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(RevocationAndRenewalReasons const value) noexcept
    {
        return static_cast<RevocationAndRenewalReasons>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(RevocationAndRenewalReasons const left, RevocationAndRenewalReasons const right) noexcept
    {
        return static_cast<RevocationAndRenewalReasons>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(RevocationAndRenewalReasons& left, RevocationAndRenewalReasons const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto ComponentRenewal::RenewSystemComponentsAsync(winrt::Windows::Media::Protection::RevocationAndRenewalInformation const& information)
    {
        return impl::call_factory<ComponentRenewal, IComponentRenewalStatics>([&](IComponentRenewalStatics const& f) { return f.RenewSystemComponentsAsync(information); });
    }
    inline HdcpSession::HdcpSession() :
        HdcpSession(impl::call_factory_cast<HdcpSession(*)(winrt::Windows::Foundation::IActivationFactory const&), HdcpSession>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<HdcpSession>(); }))
    {
    }
    inline MediaProtectionManager::MediaProtectionManager() :
        MediaProtectionManager(impl::call_factory_cast<MediaProtectionManager(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaProtectionManager>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaProtectionManager>(); }))
    {
    }
    inline MediaProtectionPMPServer::MediaProtectionPMPServer(winrt::Windows::Foundation::Collections::IPropertySet const& pProperties) :
        MediaProtectionPMPServer(impl::call_factory<MediaProtectionPMPServer, IMediaProtectionPMPServerFactory>([&](IMediaProtectionPMPServerFactory const& f) { return f.CreatePMPServer(pProperties); }))
    {
    }
    inline ProtectionCapabilities::ProtectionCapabilities() :
        ProtectionCapabilities(impl::call_factory_cast<ProtectionCapabilities(*)(winrt::Windows::Foundation::IActivationFactory const&), ProtectionCapabilities>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ProtectionCapabilities>(); }))
    {
    }
    template <typename L> ComponentLoadFailedEventHandler::ComponentLoadFailedEventHandler(L handler) :
        ComponentLoadFailedEventHandler(impl::make_delegate<ComponentLoadFailedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ComponentLoadFailedEventHandler::ComponentLoadFailedEventHandler(F* handler) :
        ComponentLoadFailedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ComponentLoadFailedEventHandler::ComponentLoadFailedEventHandler(O* object, M method) :
        ComponentLoadFailedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ComponentLoadFailedEventHandler::ComponentLoadFailedEventHandler(com_ptr<O>&& object, M method) :
        ComponentLoadFailedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ComponentLoadFailedEventHandler::ComponentLoadFailedEventHandler(weak_ref<O>&& object, M method) :
        ComponentLoadFailedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ComponentLoadFailedEventHandler::operator()(winrt::Windows::Media::Protection::MediaProtectionManager const& sender, winrt::Windows::Media::Protection::ComponentLoadFailedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ComponentLoadFailedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> RebootNeededEventHandler::RebootNeededEventHandler(L handler) :
        RebootNeededEventHandler(impl::make_delegate<RebootNeededEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> RebootNeededEventHandler::RebootNeededEventHandler(F* handler) :
        RebootNeededEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> RebootNeededEventHandler::RebootNeededEventHandler(O* object, M method) :
        RebootNeededEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> RebootNeededEventHandler::RebootNeededEventHandler(com_ptr<O>&& object, M method) :
        RebootNeededEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> RebootNeededEventHandler::RebootNeededEventHandler(weak_ref<O>&& object, M method) :
        RebootNeededEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto RebootNeededEventHandler::operator()(winrt::Windows::Media::Protection::MediaProtectionManager const& sender) const
    {
        check_hresult((*(impl::abi_t<RebootNeededEventHandler>**)this)->Invoke(*(void**)(&sender)));
    }
    template <typename L> ServiceRequestedEventHandler::ServiceRequestedEventHandler(L handler) :
        ServiceRequestedEventHandler(impl::make_delegate<ServiceRequestedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ServiceRequestedEventHandler::ServiceRequestedEventHandler(F* handler) :
        ServiceRequestedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ServiceRequestedEventHandler::ServiceRequestedEventHandler(O* object, M method) :
        ServiceRequestedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ServiceRequestedEventHandler::ServiceRequestedEventHandler(com_ptr<O>&& object, M method) :
        ServiceRequestedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ServiceRequestedEventHandler::ServiceRequestedEventHandler(weak_ref<O>&& object, M method) :
        ServiceRequestedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ServiceRequestedEventHandler::operator()(winrt::Windows::Media::Protection::MediaProtectionManager const& sender, winrt::Windows::Media::Protection::ServiceRequestedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<ServiceRequestedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IComponentRenewalStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IHdcpSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IMediaProtectionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IMediaProtectionPMPServer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IMediaProtectionPMPServerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IMediaProtectionServiceCompletion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IMediaProtectionServiceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IProtectionCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IRevocationAndRenewalInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IRevocationAndRenewalItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IServiceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::IServiceRequestedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::ComponentLoadFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::ComponentRenewal> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::HdcpSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::MediaProtectionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::MediaProtectionPMPServer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::MediaProtectionServiceCompletion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::ProtectionCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::RevocationAndRenewalInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::RevocationAndRenewalItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Protection::ServiceRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
