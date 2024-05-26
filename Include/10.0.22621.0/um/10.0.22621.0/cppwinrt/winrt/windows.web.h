// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_H
#define WINRT_Windows_Web_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>) consume_Windows_Web_IUriToStreamResolver<D>::UriToStreamAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::IUriToStreamResolver)->UriToStreamAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::WebErrorStatus) consume_Windows_Web_IWebErrorStatics<D>::GetStatus(int32_t hresult) const
    {
        winrt::Windows::Web::WebErrorStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::IWebErrorStatics)->GetStatus(hresult, reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D>
    struct produce<D, winrt::Windows::Web::IUriToStreamResolver> : produce_base<D, winrt::Windows::Web::IUriToStreamResolver>
    {
        int32_t __stdcall UriToStreamAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>>(this->shim().UriToStreamAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::IWebErrorStatics> : produce_base<D, winrt::Windows::Web::IWebErrorStatics>
    {
        int32_t __stdcall GetStatus(int32_t hresult, int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Web::WebErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Web
{
    inline auto WebError::GetStatus(int32_t hresult)
    {
        return impl::call_factory<WebError, IWebErrorStatics>([&](IWebErrorStatics const& f) { return f.GetStatus(hresult); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Web::IUriToStreamResolver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::IWebErrorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::WebError> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
