// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Ocr_H
#define WINRT_Windows_Media_Ocr_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.Ocr.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Ocr::OcrResult>) consume_Windows_Media_Ocr_IOcrEngine<D>::RecognizeAsync(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngine)->RecognizeAsync(*(void**)(&bitmap), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Ocr::OcrResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) consume_Windows_Media_Ocr_IOcrEngine<D>::RecognizerLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngine)->get_RecognizerLanguage(&value));
        return winrt::Windows::Globalization::Language{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Ocr_IOcrEngineStatics<D>::MaxImageDimension() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngineStatics)->get_MaxImageDimension(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>) consume_Windows_Media_Ocr_IOcrEngineStatics<D>::AvailableRecognizerLanguages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngineStatics)->get_AvailableRecognizerLanguages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Ocr_IOcrEngineStatics<D>::IsLanguageSupported(winrt::Windows::Globalization::Language const& language) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngineStatics)->IsLanguageSupported(*(void**)(&language), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Ocr::OcrEngine) consume_Windows_Media_Ocr_IOcrEngineStatics<D>::TryCreateFromLanguage(winrt::Windows::Globalization::Language const& language) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngineStatics)->TryCreateFromLanguage(*(void**)(&language), &result));
        return winrt::Windows::Media::Ocr::OcrEngine{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Ocr::OcrEngine) consume_Windows_Media_Ocr_IOcrEngineStatics<D>::TryCreateFromUserProfileLanguages() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrEngineStatics)->TryCreateFromUserProfileLanguages(&result));
        return winrt::Windows::Media::Ocr::OcrEngine{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Ocr::OcrWord>) consume_Windows_Media_Ocr_IOcrLine<D>::Words() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrLine)->get_Words(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Ocr::OcrWord>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Ocr_IOcrLine<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrLine)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Ocr::OcrLine>) consume_Windows_Media_Ocr_IOcrResult<D>::Lines() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrResult)->get_Lines(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Ocr::OcrLine>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Media_Ocr_IOcrResult<D>::TextAngle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrResult)->get_TextAngle(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Ocr_IOcrResult<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrResult)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Media_Ocr_IOcrWord<D>::BoundingRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrWord)->get_BoundingRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Ocr_IOcrWord<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Ocr::IOcrWord)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Ocr::IOcrEngine> : produce_base<D, winrt::Windows::Media::Ocr::IOcrEngine>
    {
        int32_t __stdcall RecognizeAsync(void* bitmap, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Ocr::OcrResult>>(this->shim().RecognizeAsync(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecognizerLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Language>(this->shim().RecognizerLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Ocr::IOcrEngineStatics> : produce_base<D, winrt::Windows::Media::Ocr::IOcrEngineStatics>
    {
        int32_t __stdcall get_MaxImageDimension(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxImageDimension());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AvailableRecognizerLanguages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>>(this->shim().AvailableRecognizerLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsLanguageSupported(void* language, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsLanguageSupported(*reinterpret_cast<winrt::Windows::Globalization::Language const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFromLanguage(void* language, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Ocr::OcrEngine>(this->shim().TryCreateFromLanguage(*reinterpret_cast<winrt::Windows::Globalization::Language const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFromUserProfileLanguages(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Ocr::OcrEngine>(this->shim().TryCreateFromUserProfileLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Ocr::IOcrLine> : produce_base<D, winrt::Windows::Media::Ocr::IOcrLine>
    {
        int32_t __stdcall get_Words(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Ocr::OcrWord>>(this->shim().Words());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Ocr::IOcrResult> : produce_base<D, winrt::Windows::Media::Ocr::IOcrResult>
    {
        int32_t __stdcall get_Lines(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Ocr::OcrLine>>(this->shim().Lines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextAngle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().TextAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Ocr::IOcrWord> : produce_base<D, winrt::Windows::Media::Ocr::IOcrWord>
    {
        int32_t __stdcall get_BoundingRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Ocr
{
    inline auto OcrEngine::MaxImageDimension()
    {
        return impl::call_factory_cast<uint32_t(*)(IOcrEngineStatics const&), OcrEngine, IOcrEngineStatics>([](IOcrEngineStatics const& f) { return f.MaxImageDimension(); });
    }
    inline auto OcrEngine::AvailableRecognizerLanguages()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>(*)(IOcrEngineStatics const&), OcrEngine, IOcrEngineStatics>([](IOcrEngineStatics const& f) { return f.AvailableRecognizerLanguages(); });
    }
    inline auto OcrEngine::IsLanguageSupported(winrt::Windows::Globalization::Language const& language)
    {
        return impl::call_factory<OcrEngine, IOcrEngineStatics>([&](IOcrEngineStatics const& f) { return f.IsLanguageSupported(language); });
    }
    inline auto OcrEngine::TryCreateFromLanguage(winrt::Windows::Globalization::Language const& language)
    {
        return impl::call_factory<OcrEngine, IOcrEngineStatics>([&](IOcrEngineStatics const& f) { return f.TryCreateFromLanguage(language); });
    }
    inline auto OcrEngine::TryCreateFromUserProfileLanguages()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Ocr::OcrEngine(*)(IOcrEngineStatics const&), OcrEngine, IOcrEngineStatics>([](IOcrEngineStatics const& f) { return f.TryCreateFromUserProfileLanguages(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Ocr::IOcrEngine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::IOcrEngineStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::IOcrLine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::IOcrResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::IOcrWord> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::OcrEngine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::OcrLine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::OcrResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Ocr::OcrWord> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
