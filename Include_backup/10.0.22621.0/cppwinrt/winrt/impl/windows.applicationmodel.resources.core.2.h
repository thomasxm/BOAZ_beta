// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_Core_2_H
#define WINRT_Windows_ApplicationModel_Resources_Core_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Core
{
    struct ResourceLayoutInfo
    {
        uint32_t MajorVersion;
        uint32_t MinorVersion;
        uint32_t ResourceSubtreeCount;
        uint32_t NamedResourceCount;
        int32_t Checksum;
    };
    inline bool operator==(ResourceLayoutInfo const& left, ResourceLayoutInfo const& right) noexcept
    {
        return left.MajorVersion == right.MajorVersion && left.MinorVersion == right.MinorVersion && left.ResourceSubtreeCount == right.ResourceSubtreeCount && left.NamedResourceCount == right.NamedResourceCount && left.Checksum == right.Checksum;
    }
    inline bool operator!=(ResourceLayoutInfo const& left, ResourceLayoutInfo const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) NamedResource : winrt::Windows::ApplicationModel::Resources::Core::INamedResource
    {
        NamedResource(std::nullptr_t) noexcept {}
        NamedResource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Core::INamedResource(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceCandidate : winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate,
        impl::require<ResourceCandidate, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3>
    {
        ResourceCandidate(std::nullptr_t) noexcept {}
        ResourceCandidate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceCandidateVectorView : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>
    {
        ResourceCandidateVectorView(std::nullptr_t) noexcept {}
        ResourceCandidateVectorView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceContext : winrt::Windows::ApplicationModel::Resources::Core::IResourceContext
    {
        ResourceContext(std::nullptr_t) noexcept {}
        ResourceContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Core::IResourceContext(ptr, take_ownership_from_abi) {}
        ResourceContext();
        static auto CreateMatchingContext(param::iterable<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result);
        static auto GetForCurrentView();
        static auto SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value);
        static auto ResetGlobalQualifierValues();
        static auto ResetGlobalQualifierValues(param::iterable<hstring> const& qualifierNames);
        static auto GetForViewIndependentUse();
        static auto SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value, winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const& persistence);
        static auto GetForUIContext(winrt::Windows::UI::UIContext const& context);
    };
    struct __declspec(empty_bases) ResourceContextLanguagesVectorView : winrt::Windows::Foundation::Collections::IVectorView<hstring>
    {
        ResourceContextLanguagesVectorView(std::nullptr_t) noexcept {}
        ResourceContextLanguagesVectorView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IVectorView<hstring>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceManager : winrt::Windows::ApplicationModel::Resources::Core::IResourceManager,
        impl::require<ResourceManager, winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2>
    {
        ResourceManager(std::nullptr_t) noexcept {}
        ResourceManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Core::IResourceManager(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Current();
        static auto IsResourceReference(param::hstring const& resourceReference);
    };
    struct __declspec(empty_bases) ResourceMap : winrt::Windows::ApplicationModel::Resources::Core::IResourceMap
    {
        ResourceMap(std::nullptr_t) noexcept {}
        ResourceMap(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Core::IResourceMap(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceMapIterator : winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::ApplicationModel::Resources::Core::NamedResource>>
    {
        ResourceMapIterator(std::nullptr_t) noexcept {}
        ResourceMapIterator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::ApplicationModel::Resources::Core::NamedResource>>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceMapMapView : winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>
    {
        ResourceMapMapView(std::nullptr_t) noexcept {}
        ResourceMapMapView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceMapMapViewIterator : winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>>
    {
        ResourceMapMapViewIterator(std::nullptr_t) noexcept {}
        ResourceMapMapViewIterator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceQualifier : winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier
    {
        ResourceQualifier(std::nullptr_t) noexcept {}
        ResourceQualifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceQualifierMapView : winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>
    {
        ResourceQualifierMapView(std::nullptr_t) noexcept {}
        ResourceQualifierMapView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceQualifierObservableMap : winrt::Windows::Foundation::Collections::IObservableMap<hstring, hstring>
    {
        ResourceQualifierObservableMap(std::nullptr_t) noexcept {}
        ResourceQualifierObservableMap(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IObservableMap<hstring, hstring>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceQualifierVectorView : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier>
    {
        ResourceQualifierVectorView(std::nullptr_t) noexcept {}
        ResourceQualifierVectorView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier>(ptr, take_ownership_from_abi) {}
    };
}
#endif
