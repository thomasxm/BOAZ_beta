// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Resources_2_H
#define WINRT_Windows_UI_Xaml_Resources_2_H
#include "winrt/impl/Windows.UI.Xaml.Resources.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Resources
{
    struct __declspec(empty_bases) CustomXamlResourceLoader : winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoader,
        impl::require<CustomXamlResourceLoader, winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides>
    {
        CustomXamlResourceLoader(std::nullptr_t) noexcept {}
        CustomXamlResourceLoader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoader(ptr, take_ownership_from_abi) {}
        CustomXamlResourceLoader();
        [[nodiscard]] static auto Current();
        static auto Current(winrt::Windows::UI::Xaml::Resources::CustomXamlResourceLoader const& value);
    };
    template <typename D>
    class ICustomXamlResourceLoaderOverridesT
    {
        D& shim() noexcept { return *static_cast<D*>(this); }
        D const& shim() const noexcept { return *static_cast<const D*>(this); }
    public:
        using ICustomXamlResourceLoaderOverrides = winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) GetResource(param::hstring const& resourceId, param::hstring const& objectType, param::hstring const& propertyName, param::hstring const& propertyType) const;
    };
}
#endif
