// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_Fonts_H
#define WINRT_Windows_Globalization_Fonts_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Globalization.h"
#include "winrt/impl/Windows.UI.Text.2.h"
#include "winrt/impl/Windows.Globalization.Fonts.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontFamily() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFont)->get_FontFamily(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontWeight) consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontWeight() const
    {
        winrt::Windows::UI::Text::FontWeight weight{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFont)->get_FontWeight(put_abi(weight)));
        return weight;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontStretch) consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontStretch() const
    {
        winrt::Windows::UI::Text::FontStretch stretch{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFont)->get_FontStretch(reinterpret_cast<int32_t*>(&stretch)));
        return stretch;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontStyle) consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontStyle() const
    {
        winrt::Windows::UI::Text::FontStyle style{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFont)->get_FontStyle(reinterpret_cast<int32_t*>(&style)));
        return style;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Globalization_Fonts_ILanguageFont<D>::ScaleFactor() const
    {
        double scale{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFont)->get_ScaleFactor(&scale));
        return scale;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UITextFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_UITextFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UIHeadingFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_UIHeadingFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UITitleFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_UITitleFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UICaptionFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_UICaptionFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UINotificationHeadingFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_UINotificationHeadingFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::TraditionalDocumentFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_TraditionalDocumentFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::ModernDocumentFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_ModernDocumentFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::DocumentHeadingFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_DocumentHeadingFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::FixedWidthTextFont() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_FixedWidthTextFont(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::DocumentAlternate1Font() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_DocumentAlternate1Font(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFont) consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::DocumentAlternate2Font() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroup)->get_DocumentAlternate2Font(&value));
        return winrt::Windows::Globalization::Fonts::LanguageFont{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Fonts::LanguageFontGroup) consume_Windows_Globalization_Fonts_ILanguageFontGroupFactory<D>::CreateLanguageFontGroup(param::hstring const& languageTag) const
    {
        void* recommendedFonts{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::Fonts::ILanguageFontGroupFactory)->CreateLanguageFontGroup(*(void**)(&languageTag), &recommendedFonts));
        return winrt::Windows::Globalization::Fonts::LanguageFontGroup{ recommendedFonts, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::Fonts::ILanguageFont> : produce_base<D, winrt::Windows::Globalization::Fonts::ILanguageFont>
    {
        int32_t __stdcall get_FontFamily(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontWeight(struct struct_Windows_UI_Text_FontWeight* weight) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Text::FontWeight>(weight);
            typename D::abi_guard guard(this->shim());
            *weight = detach_from<winrt::Windows::UI::Text::FontWeight>(this->shim().FontWeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontStretch(int32_t* stretch) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *stretch = detach_from<winrt::Windows::UI::Text::FontStretch>(this->shim().FontStretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontStyle(int32_t* style) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *style = detach_from<winrt::Windows::UI::Text::FontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleFactor(double* scale) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *scale = detach_from<double>(this->shim().ScaleFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::Fonts::ILanguageFontGroup> : produce_base<D, winrt::Windows::Globalization::Fonts::ILanguageFontGroup>
    {
        int32_t __stdcall get_UITextFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().UITextFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UIHeadingFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().UIHeadingFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UITitleFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().UITitleFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UICaptionFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().UICaptionFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UINotificationHeadingFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().UINotificationHeadingFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TraditionalDocumentFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().TraditionalDocumentFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModernDocumentFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().ModernDocumentFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentHeadingFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().DocumentHeadingFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FixedWidthTextFont(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().FixedWidthTextFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentAlternate1Font(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().DocumentAlternate1Font());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentAlternate2Font(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Fonts::LanguageFont>(this->shim().DocumentAlternate2Font());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::Fonts::ILanguageFontGroupFactory> : produce_base<D, winrt::Windows::Globalization::Fonts::ILanguageFontGroupFactory>
    {
        int32_t __stdcall CreateLanguageFontGroup(void* languageTag, void** recommendedFonts) noexcept final try
        {
            clear_abi(recommendedFonts);
            typename D::abi_guard guard(this->shim());
            *recommendedFonts = detach_from<winrt::Windows::Globalization::Fonts::LanguageFontGroup>(this->shim().CreateLanguageFontGroup(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Globalization::Fonts
{
    inline LanguageFontGroup::LanguageFontGroup(param::hstring const& languageTag) :
        LanguageFontGroup(impl::call_factory<LanguageFontGroup, ILanguageFontGroupFactory>([&](ILanguageFontGroupFactory const& f) { return f.CreateLanguageFontGroup(languageTag); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Globalization::Fonts::ILanguageFont> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Fonts::ILanguageFontGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Fonts::ILanguageFontGroupFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Fonts::LanguageFont> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Fonts::LanguageFontGroup> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
