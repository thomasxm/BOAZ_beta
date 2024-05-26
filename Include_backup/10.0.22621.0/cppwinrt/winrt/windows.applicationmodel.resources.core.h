// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_Core_H
#define WINRT_Windows_ApplicationModel_Resources_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Resources.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Uri() const
    {
        void* uri{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::INamedResource)->get_Uri(&uri));
        return winrt::Windows::Foundation::Uri{ uri, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>) consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Candidates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::INamedResource)->get_Candidates(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate) consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Resolve() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::INamedResource)->Resolve(&result));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate) consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::Resolve(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext const& resourceContext) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::INamedResource)->ResolveForContext(*(void**)(&resourceContext), &result));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>) consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::ResolveAll() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::INamedResource)->ResolveAll(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>) consume_Windows_ApplicationModel_Resources_Core_INamedResource<D>::ResolveAll(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext const& resourceContext) const
    {
        void* instances{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::INamedResource)->ResolveAllForContext(*(void**)(&resourceContext), &instances));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>{ instances, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier>) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::Qualifiers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_Qualifiers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::IsMatch() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_IsMatch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::IsMatchAsDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_IsMatchAsDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::IsDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_IsDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::ValueAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->get_ValueAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::GetValueAsFileAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->GetValueAsFileAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate<D>::GetQualifierValue(param::hstring const& qualifierName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate)->GetQualifierValue(*(void**)(&qualifierName), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate2<D>::GetValueAsStreamAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2)->GetValueAsStreamAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidateKind) consume_Windows_ApplicationModel_Resources_Core_IResourceCandidate3<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidateKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableMap<hstring, hstring>) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::QualifierValues() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->get_QualifierValues(&value));
        return winrt::Windows::Foundation::Collections::IObservableMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Reset(param::iterable<hstring> const& qualifierNames) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->ResetQualifierValues(*(void**)(&qualifierNames)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::OverrideToMatch(param::iterable<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->OverrideToMatch(*(void**)(&result)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Clone() const
    {
        void* clone{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->Clone(&clone));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceContext{ clone, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Languages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->get_Languages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContext<D>::Languages(param::async_vector_view<hstring> const& languages) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContext)->put_Languages(*(void**)(&languages)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics<D>::CreateMatchingContext(param::iterable<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics)->CreateMatchingContext(*(void**)(&result), &value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::GetForCurrentView() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->GetForCurrentView(&value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->SetGlobalQualifierValue(*(void**)(&key), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::ResetGlobalQualifierValues() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->ResetGlobalQualifierValues());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::ResetGlobalQualifierValues(param::iterable<hstring> const& qualifierNames) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->ResetGlobalQualifierValuesForSpecifiedQualifiers(*(void**)(&qualifierNames)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics2<D>::GetForViewIndependentUse() const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2)->GetForViewIndependentUse(&loader));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceContext{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics3<D>::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value, winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const& persistence) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics3)->SetGlobalQualifierValueWithPersistence(*(void**)(&key), *(void**)(&value), static_cast<int32_t>(persistence)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext) consume_Windows_ApplicationModel_Resources_Core_IResourceContextStatics4<D>::GetForUIContext(winrt::Windows::UI::UIContext const& context) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics4)->GetForUIContext(*(void**)(&context), &value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceMap) consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::MainResourceMap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager)->get_MainResourceMap(&value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceMap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>) consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::AllResourceMaps() const
    {
        void* maps{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager)->get_AllResourceMaps(&maps));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>{ maps, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceContext) consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::DefaultContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager)->get_DefaultContext(&value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::LoadPriFiles(param::iterable<winrt::Windows::Storage::IStorageFile> const& files) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager)->LoadPriFiles(*(void**)(&files)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Resources_Core_IResourceManager<D>::UnloadPriFiles(param::iterable<winrt::Windows::Storage::IStorageFile> const& files) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager)->UnloadPriFiles(*(void**)(&files)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::NamedResource>) consume_Windows_ApplicationModel_Resources_Core_IResourceManager2<D>::GetAllNamedResourcesForPackage(param::hstring const& packageName, winrt::Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const& resourceLayoutInfo) const
    {
        void* table{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2)->GetAllNamedResourcesForPackage(*(void**)(&packageName), impl::bind_in(resourceLayoutInfo), &table));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::NamedResource>{ table, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>) consume_Windows_ApplicationModel_Resources_Core_IResourceManager2<D>::GetAllSubtreesForPackage(param::hstring const& packageName, winrt::Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const& resourceLayoutInfo) const
    {
        void* table{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2)->GetAllSubtreesForPackage(*(void**)(&packageName), impl::bind_in(resourceLayoutInfo), &table));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>{ table, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceManager) consume_Windows_ApplicationModel_Resources_Core_IResourceManagerStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics)->get_Current(&value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Resources_Core_IResourceManagerStatics<D>::IsResourceReference(param::hstring const& resourceReference) const
    {
        bool isReference{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics)->IsResourceReference(*(void**)(&resourceReference), &isReference));
        return isReference;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::Uri() const
    {
        void* uri{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceMap)->get_Uri(&uri));
        return winrt::Windows::Foundation::Uri{ uri, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate) consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::GetValue(param::hstring const& resource) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceMap)->GetValue(*(void**)(&resource), &value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate) consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::GetValue(param::hstring const& resource, winrt::Windows::ApplicationModel::Resources::Core::ResourceContext const& context) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceMap)->GetValueForContext(*(void**)(&resource), *(void**)(&context), &value));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Core::ResourceMap) consume_Windows_ApplicationModel_Resources_Core_IResourceMap<D>::GetSubtree(param::hstring const& reference) const
    {
        void* map{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceMap)->GetSubtree(*(void**)(&reference), &map));
        return winrt::Windows::ApplicationModel::Resources::Core::ResourceMap{ map, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::QualifierName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_QualifierName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::QualifierValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_QualifierValue(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::IsDefault() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_IsDefault(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::IsMatch() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_IsMatch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_ApplicationModel_Resources_Core_IResourceQualifier<D>::Score() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier)->get_Score(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::INamedResource> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::INamedResource>
    {
        int32_t __stdcall get_Uri(void** uri) noexcept final try
        {
            clear_abi(uri);
            typename D::abi_guard guard(this->shim());
            *uri = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Candidates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>>(this->shim().Candidates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resolve(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().Resolve());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResolveForContext(void* resourceContext, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().Resolve(*reinterpret_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext const*>(&resourceContext)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResolveAll(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>>(this->shim().ResolveAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResolveAllForContext(void* resourceContext, void** instances) noexcept final try
        {
            clear_abi(instances);
            typename D::abi_guard guard(this->shim());
            *instances = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>>(this->shim().ResolveAll(*reinterpret_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext const*>(&resourceContext)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate>
    {
        int32_t __stdcall get_Qualifiers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier>>(this->shim().Qualifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMatch(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMatchAsDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMatchAsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ValueAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().ValueAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValueAsFileAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().GetValueAsFileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetQualifierValue(void* qualifierName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetQualifierValue(*reinterpret_cast<hstring const*>(&qualifierName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2>
    {
        int32_t __stdcall GetValueAsStreamAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetValueAsStreamAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidateKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContext> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContext>
    {
        int32_t __stdcall get_QualifierValues(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableMap<hstring, hstring>>(this->shim().QualifierValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reset() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetQualifierValues(void* qualifierNames) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reset(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&qualifierNames));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OverrideToMatch(void* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OverrideToMatch(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> const*>(&result));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clone(void** clone) noexcept final try
        {
            clear_abi(clone);
            typename D::abi_guard guard(this->shim());
            *clone = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Languages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Languages(void* languages) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Languages(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring> const*>(&languages));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics>
    {
        int32_t __stdcall CreateMatchingContext(void* result, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().CreateMatchingContext(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> const*>(&result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2>
    {
        int32_t __stdcall GetForCurrentView(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetGlobalQualifierValue(void* key, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetGlobalQualifierValue(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetGlobalQualifierValues() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetGlobalQualifierValues();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetGlobalQualifierValuesForSpecifiedQualifiers(void* qualifierNames) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetGlobalQualifierValues(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&qualifierNames));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForViewIndependentUse(void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().GetForViewIndependentUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics3> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics3>
    {
        int32_t __stdcall SetGlobalQualifierValueWithPersistence(void* key, void* value, int32_t persistence) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetGlobalQualifierValue(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const*>(&persistence));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics4> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics4>
    {
        int32_t __stdcall GetForUIContext(void* context, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().GetForUIContext(*reinterpret_cast<winrt::Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceManager> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceManager>
    {
        int32_t __stdcall get_MainResourceMap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>(this->shim().MainResourceMap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllResourceMaps(void** maps) noexcept final try
        {
            clear_abi(maps);
            typename D::abi_guard guard(this->shim());
            *maps = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>>(this->shim().AllResourceMaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext>(this->shim().DefaultContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadPriFiles(void* files) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoadPriFiles(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::IStorageFile> const*>(&files));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnloadPriFiles(void* files) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnloadPriFiles(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::IStorageFile> const*>(&files));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2>
    {
        int32_t __stdcall GetAllNamedResourcesForPackage(void* packageName, struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo resourceLayoutInfo, void** table) noexcept final try
        {
            clear_abi(table);
            typename D::abi_guard guard(this->shim());
            *table = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::NamedResource>>(this->shim().GetAllNamedResourcesForPackage(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const*>(&resourceLayoutInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAllSubtreesForPackage(void* packageName, struct struct_Windows_ApplicationModel_Resources_Core_ResourceLayoutInfo resourceLayoutInfo, void** table) noexcept final try
        {
            clear_abi(table);
            typename D::abi_guard guard(this->shim());
            *table = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>>(this->shim().GetAllSubtreesForPackage(*reinterpret_cast<hstring const*>(&packageName), *reinterpret_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceLayoutInfo const*>(&resourceLayoutInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceManager>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsResourceReference(void* resourceReference, bool* isReference) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isReference = detach_from<bool>(this->shim().IsResourceReference(*reinterpret_cast<hstring const*>(&resourceReference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceMap> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceMap>
    {
        int32_t __stdcall get_Uri(void** uri) noexcept final try
        {
            clear_abi(uri);
            typename D::abi_guard guard(this->shim());
            *uri = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValue(void* resource, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().GetValue(*reinterpret_cast<hstring const*>(&resource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValueForContext(void* resource, void* context, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate>(this->shim().GetValue(*reinterpret_cast<hstring const*>(&resource), *reinterpret_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSubtree(void* reference, void** map) noexcept final try
        {
            clear_abi(map);
            typename D::abi_guard guard(this->shim());
            *map = detach_from<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap>(this->shim().GetSubtree(*reinterpret_cast<hstring const*>(&reference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier> : produce_base<D, winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier>
    {
        int32_t __stdcall get_QualifierName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().QualifierName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QualifierValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().QualifierValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDefault(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMatch(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Score(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Score());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Core
{
    inline ResourceContext::ResourceContext() :
        ResourceContext(impl::call_factory_cast<ResourceContext(*)(winrt::Windows::Foundation::IActivationFactory const&), ResourceContext>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ResourceContext>(); }))
    {
    }
    inline auto ResourceContext::CreateMatchingContext(param::iterable<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> const& result)
    {
        return impl::call_factory<ResourceContext, IResourceContextStatics>([&](IResourceContextStatics const& f) { return f.CreateMatchingContext(result); });
    }
    inline auto ResourceContext::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext(*)(IResourceContextStatics2 const&), ResourceContext, IResourceContextStatics2>([](IResourceContextStatics2 const& f) { return f.GetForCurrentView(); });
    }
    inline auto ResourceContext::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value)
    {
        impl::call_factory<ResourceContext, IResourceContextStatics2>([&](IResourceContextStatics2 const& f) { return f.SetGlobalQualifierValue(key, value); });
    }
    inline auto ResourceContext::ResetGlobalQualifierValues()
    {
        impl::call_factory_cast<void(*)(IResourceContextStatics2 const&), ResourceContext, IResourceContextStatics2>([](IResourceContextStatics2 const& f) { return f.ResetGlobalQualifierValues(); });
    }
    inline auto ResourceContext::ResetGlobalQualifierValues(param::iterable<hstring> const& qualifierNames)
    {
        impl::call_factory<ResourceContext, IResourceContextStatics2>([&](IResourceContextStatics2 const& f) { return f.ResetGlobalQualifierValues(qualifierNames); });
    }
    inline auto ResourceContext::GetForViewIndependentUse()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext(*)(IResourceContextStatics2 const&), ResourceContext, IResourceContextStatics2>([](IResourceContextStatics2 const& f) { return f.GetForViewIndependentUse(); });
    }
    inline auto ResourceContext::SetGlobalQualifierValue(param::hstring const& key, param::hstring const& value, winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierPersistence const& persistence)
    {
        impl::call_factory<ResourceContext, IResourceContextStatics3>([&](IResourceContextStatics3 const& f) { return f.SetGlobalQualifierValue(key, value, persistence); });
    }
    inline auto ResourceContext::GetForUIContext(winrt::Windows::UI::UIContext const& context)
    {
        return impl::call_factory<ResourceContext, IResourceContextStatics4>([&](IResourceContextStatics4 const& f) { return f.GetForUIContext(context); });
    }
    inline auto ResourceManager::Current()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Resources::Core::ResourceManager(*)(IResourceManagerStatics const&), ResourceManager, IResourceManagerStatics>([](IResourceManagerStatics const& f) { return f.Current(); });
    }
    inline auto ResourceManager::IsResourceReference(param::hstring const& resourceReference)
    {
        return impl::call_factory<ResourceManager, IResourceManagerStatics>([&](IResourceManagerStatics const& f) { return f.IsResourceReference(resourceReference); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::INamedResource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceCandidate3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceContextStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceMap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::IResourceQualifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::NamedResource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceCandidateVectorView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceContextLanguagesVectorView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapIterator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapMapView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceMapMapViewIterator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierMapView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierObservableMap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::Core::ResourceQualifierVectorView> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
