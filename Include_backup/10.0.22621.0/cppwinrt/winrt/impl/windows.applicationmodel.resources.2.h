// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_2_H
#define WINRT_Windows_ApplicationModel_Resources_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources
{
    struct __declspec(empty_bases) ResourceLoader : winrt::Windows::ApplicationModel::Resources::IResourceLoader,
        impl::require<ResourceLoader, winrt::Windows::ApplicationModel::Resources::IResourceLoader2>
    {
        ResourceLoader(std::nullptr_t) noexcept {}
        ResourceLoader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::IResourceLoader(ptr, take_ownership_from_abi) {}
        ResourceLoader();
        explicit ResourceLoader(param::hstring const& name);
        static auto GetStringForReference(winrt::Windows::Foundation::Uri const& uri);
        static auto GetForCurrentView();
        static auto GetForCurrentView(param::hstring const& name);
        static auto GetForViewIndependentUse();
        static auto GetForViewIndependentUse(param::hstring const& name);
        static auto GetForUIContext(winrt::Windows::UI::UIContext const& context);
        static auto GetDefaultPriPath(param::hstring const& packageFullName);
    };
}
#endif
