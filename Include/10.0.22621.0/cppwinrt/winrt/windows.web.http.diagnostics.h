// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_Http_Diagnostics_H
#define WINRT_Windows_Web_Http_Diagnostics_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Web.Http.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.Diagnostics.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Web.Http.Diagnostics.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->add_RequestSent(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent_revoker consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RequestSent_revoker>(this, RequestSent(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->remove_RequestSent(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->add_ResponseReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived_revoker consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ResponseReceived_revoker>(this, ResponseReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->remove_ResponseReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->add_RequestResponseCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted_revoker consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RequestResponseCompleted_revoker>(this, RequestResponseCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->remove_RequestResponseCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::ActivityId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_ActivityId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::Timestamps() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_Timestamps(&value));
        return winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::RequestedUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_RequestedUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::ProcessId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_ProcessId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::ThreadId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_ThreadId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::Initiator() const
    {
        winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_Initiator(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::SourceLocations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_SourceLocations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::CacheCheckedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_CacheCheckedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ConnectionInitiatedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ConnectionInitiatedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::NameResolvedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_NameResolvedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::SslNegotiatedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_SslNegotiatedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ConnectionCompletedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ConnectionCompletedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::RequestSentTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_RequestSentTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::RequestCompletedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_RequestCompletedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ResponseReceivedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ResponseReceivedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ResponseCompletedTimestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ResponseCompletedTimestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::ActivityId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_ActivityId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpRequestMessage) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_Message(&value));
        return winrt::Windows::Web::Http::HttpRequestMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::ProcessId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_ProcessId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::ThreadId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_ThreadId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::Initiator() const
    {
        winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_Initiator(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::SourceLocations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_SourceLocations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>::ActivityId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs)->get_ActivityId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpResponseMessage) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs)->get_Message(&value));
        return winrt::Windows::Web::Http::HttpResponseMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderStatics<D>::CreateFromProcessDiagnosticInfo(winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo const& processDiagnosticInfo) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics)->CreateFromProcessDiagnosticInfo(*(void**)(&processDiagnosticInfo), &value));
        return winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>::SourceUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation)->get_SourceUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>::LineNumber() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation)->get_LineNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>::ColumnNumber() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation)->get_ColumnNumber(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>
    {
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
        int32_t __stdcall add_RequestSent(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RequestSent(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RequestSent(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestSent(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ResponseReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ResponseReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ResponseReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResponseReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RequestResponseCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RequestResponseCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RequestResponseCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestResponseCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs>
    {
        int32_t __stdcall get_ActivityId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timestamps(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps>(this->shim().Timestamps());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().RequestedUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProcessId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ProcessId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThreadId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ThreadId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Initiator(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator>(this->shim().Initiator());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceLocations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>>(this->shim().SourceLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps>
    {
        int32_t __stdcall get_CacheCheckedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().CacheCheckedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionInitiatedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ConnectionInitiatedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NameResolvedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().NameResolvedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SslNegotiatedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().SslNegotiatedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionCompletedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ConnectionCompletedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestSentTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().RequestSentTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestCompletedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().RequestCompletedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseReceivedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ResponseReceivedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseCompletedTimestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().ResponseCompletedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActivityId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpRequestMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProcessId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ProcessId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThreadId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ThreadId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Initiator(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator>(this->shim().Initiator());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceLocations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>>(this->shim().SourceLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActivityId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::HttpResponseMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>
    {
        int32_t __stdcall CreateFromProcessDiagnosticInfo(void* processDiagnosticInfo, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider>(this->shim().CreateFromProcessDiagnosticInfo(*reinterpret_cast<winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo const*>(&processDiagnosticInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation> : produce_base<D, winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation>
    {
        int32_t __stdcall get_SourceUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().SourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineNumber(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().LineNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColumnNumber(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ColumnNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Web::Http::Diagnostics
{
    inline auto HttpDiagnosticProvider::CreateFromProcessDiagnosticInfo(winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo const& processDiagnosticInfo)
    {
        return impl::call_factory<HttpDiagnosticProvider, IHttpDiagnosticProviderStatics>([&](IHttpDiagnosticProviderStatics const& f) { return f.CreateFromProcessDiagnosticInfo(processDiagnosticInfo); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
