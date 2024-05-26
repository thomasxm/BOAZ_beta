// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_H
#define WINRT_Windows_ApplicationModel_Resources_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_IResourceLoader<D>::GetString(param::hstring const& resource) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoader)->GetString(*(void**)(&resource), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_IResourceLoader2<D>::GetStringForUri(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoader2)->GetStringForUri(*(void**)(&uri), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::ResourceLoader) consume_Windows_ApplicationModel_Resources_IResourceLoaderFactory<D>::CreateResourceLoaderByName(param::hstring const& name) const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderFactory)->CreateResourceLoaderByName(*(void**)(&name), &loader));
        return winrt::Windows::ApplicationModel::Resources::ResourceLoader{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics<D>::GetStringForReference(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics)->GetStringForReference(*(void**)(&uri), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::ResourceLoader) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForCurrentView() const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForCurrentView(&loader));
        return winrt::Windows::ApplicationModel::Resources::ResourceLoader{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::ResourceLoader) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForCurrentView(param::hstring const& name) const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForCurrentViewWithName(*(void**)(&name), &loader));
        return winrt::Windows::ApplicationModel::Resources::ResourceLoader{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::ResourceLoader) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForViewIndependentUse() const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForViewIndependentUse(&loader));
        return winrt::Windows::ApplicationModel::Resources::ResourceLoader{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::ResourceLoader) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForViewIndependentUse(param::hstring const& name) const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForViewIndependentUseWithName(*(void**)(&name), &loader));
        return winrt::Windows::ApplicationModel::Resources::ResourceLoader{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::ResourceLoader) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics3<D>::GetForUIContext(winrt::Windows::UI::UIContext const& context) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics3)->GetForUIContext(*(void**)(&context), &result));
        return winrt::Windows::ApplicationModel::Resources::ResourceLoader{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics4<D>::GetDefaultPriPath(param::hstring const& packageFullName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics4)->GetDefaultPriPath(*(void**)(&packageFullName), &value));
        return hstring{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoader> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoader>
    {
        int32_t __stdcall GetString(void* resource, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetString(*reinterpret_cast<hstring const*>(&resource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoader2> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoader2>
    {
        int32_t __stdcall GetStringForUri(void* uri, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetStringForUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderFactory> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderFactory>
    {
        int32_t __stdcall CreateResourceLoaderByName(void* name, void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().CreateResourceLoaderByName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics>
    {
        int32_t __stdcall GetStringForReference(void* uri, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetStringForReference(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2>
    {
        int32_t __stdcall GetForCurrentView(void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForCurrentViewWithName(void* name, void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForCurrentView(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForViewIndependentUse(void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForViewIndependentUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForViewIndependentUseWithName(void* name, void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForViewIndependentUse(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics3> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics3>
    {
        int32_t __stdcall GetForUIContext(void* context, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForUIContext(*reinterpret_cast<winrt::Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics4> : produce_base<D, winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics4>
    {
        int32_t __stdcall GetDefaultPriPath(void* packageFullName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDefaultPriPath(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources
{
    inline ResourceLoader::ResourceLoader() :
        ResourceLoader(impl::call_factory_cast<ResourceLoader(*)(winrt::Windows::Foundation::IActivationFactory const&), ResourceLoader>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ResourceLoader>(); }))
    {
    }
    inline ResourceLoader::ResourceLoader(param::hstring const& name) :
        ResourceLoader(impl::call_factory<ResourceLoader, IResourceLoaderFactory>([&](IResourceLoaderFactory const& f) { return f.CreateResourceLoaderByName(name); }))
    {
    }
    inline auto ResourceLoader::GetStringForReference(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<ResourceLoader, IResourceLoaderStatics>([&](IResourceLoaderStatics const& f) { return f.GetStringForReference(uri); });
    }
    inline auto ResourceLoader::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Resources::ResourceLoader(*)(IResourceLoaderStatics2 const&), ResourceLoader, IResourceLoaderStatics2>([](IResourceLoaderStatics2 const& f) { return f.GetForCurrentView(); });
    }
    inline auto ResourceLoader::GetForCurrentView(param::hstring const& name)
    {
        return impl::call_factory<ResourceLoader, IResourceLoaderStatics2>([&](IResourceLoaderStatics2 const& f) { return f.GetForCurrentView(name); });
    }
    inline auto ResourceLoader::GetForViewIndependentUse()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Resources::ResourceLoader(*)(IResourceLoaderStatics2 const&), ResourceLoader, IResourceLoaderStatics2>([](IResourceLoaderStatics2 const& f) { return f.GetForViewIndependentUse(); });
    }
    inline auto ResourceLoader::GetForViewIndependentUse(param::hstring const& name)
    {
        return impl::call_factory<ResourceLoader, IResourceLoaderStatics2>([&](IResourceLoaderStatics2 const& f) { return f.GetForViewIndependentUse(name); });
    }
    inline auto ResourceLoader::GetForUIContext(winrt::Windows::UI::UIContext const& context)
    {
        return impl::call_factory<ResourceLoader, IResourceLoaderStatics3>([&](IResourceLoaderStatics3 const& f) { return f.GetForUIContext(context); });
    }
    inline auto ResourceLoader::GetDefaultPriPath(param::hstring const& packageFullName)
    {
        return impl::call_factory<ResourceLoader, IResourceLoaderStatics4>([&](IResourceLoaderStatics4 const& f) { return f.GetDefaultPriPath(packageFullName); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Resources::ResourceLoader> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
