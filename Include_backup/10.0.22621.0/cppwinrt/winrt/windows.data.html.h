// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Html_H
#define WINRT_Windows_Data_Html_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Data.Html.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Data_Html_IHtmlUtilities<D>::ConvertToText(param::hstring const& html) const
    {
        void* text{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Html::IHtmlUtilities)->ConvertToText(*(void**)(&html), &text));
        return hstring{ text, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Html::IHtmlUtilities> : produce_base<D, winrt::Windows::Data::Html::IHtmlUtilities>
    {
        int32_t __stdcall ConvertToText(void* html, void** text) noexcept final try
        {
            clear_abi(text);
            typename D::abi_guard guard(this->shim());
            *text = detach_from<hstring>(this->shim().ConvertToText(*reinterpret_cast<hstring const*>(&html)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Data::Html
{
    inline auto HtmlUtilities::ConvertToText(param::hstring const& html)
    {
        return impl::call_factory<HtmlUtilities, IHtmlUtilities>([&](IHtmlUtilities const& f) { return f.ConvertToText(html); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Data::Html::IHtmlUtilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Html::HtmlUtilities> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
