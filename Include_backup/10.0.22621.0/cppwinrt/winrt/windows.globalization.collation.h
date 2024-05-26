// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_Collation_H
#define WINRT_Windows_Globalization_Collation_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Globalization.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.Collation.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_Collation_ICharacterGrouping<D>::First() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Collation::ICharacterGrouping)->get_First(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_Collation_ICharacterGrouping<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Collation::ICharacterGrouping)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_Collation_ICharacterGroupings<D>::Lookup(param::hstring const& text) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Collation::ICharacterGroupings)->Lookup(*(void**)(&text), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Collation::CharacterGroupings) consume_Windows_Globalization_Collation_ICharacterGroupingsFactory<D>::Create(param::hstring const& language) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Collation::ICharacterGroupingsFactory)->Create(*(void**)(&language), &result));
        return winrt::Windows::Globalization::Collation::CharacterGroupings{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::Collation::ICharacterGrouping> : produce_base<D, winrt::Windows::Globalization::Collation::ICharacterGrouping>
    {
        int32_t __stdcall get_First(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().First());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Label(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::Collation::ICharacterGroupings> : produce_base<D, winrt::Windows::Globalization::Collation::ICharacterGroupings>
    {
        int32_t __stdcall Lookup(void* text, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Lookup(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::Collation::ICharacterGroupingsFactory> : produce_base<D, winrt::Windows::Globalization::Collation::ICharacterGroupingsFactory>
    {
        int32_t __stdcall Create(void* language, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::Collation::CharacterGroupings>(this->shim().Create(*reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Globalization::Collation
{
    inline CharacterGroupings::CharacterGroupings() :
        CharacterGroupings(impl::call_factory_cast<CharacterGroupings(*)(winrt::Windows::Foundation::IActivationFactory const&), CharacterGroupings>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CharacterGroupings>(); }))
    {
    }
    inline CharacterGroupings::CharacterGroupings(param::hstring const& language) :
        CharacterGroupings(impl::call_factory<CharacterGroupings, ICharacterGroupingsFactory>([&](ICharacterGroupingsFactory const& f) { return f.Create(language); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Globalization::Collation::ICharacterGrouping> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Collation::ICharacterGroupings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Collation::ICharacterGroupingsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Collation::CharacterGrouping> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Collation::CharacterGroupings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
