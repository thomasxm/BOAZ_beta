// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Pdf_H
#define WINRT_Windows_Data_Pdf_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Data.Pdf.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Pdf::PdfPage) consume_Windows_Data_Pdf_IPdfDocument<D>::GetPage(uint32_t pageIndex) const
    {
        void* pdfPage{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocument)->GetPage(pageIndex, &pdfPage));
        return winrt::Windows::Data::Pdf::PdfPage{ pdfPage, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Data_Pdf_IPdfDocument<D>::PageCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocument)->get_PageCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Pdf_IPdfDocument<D>::IsPasswordProtected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocument)->get_IsPasswordProtected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>) consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromFileAsync(*(void**)(&file), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>) consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& password) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromFileWithPasswordAsync(*(void**)(&file), *(void**)(&password), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>) consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& inputStream) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromStreamAsync(*(void**)(&inputStream), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>) consume_Windows_Data_Pdf_IPdfDocumentStatics<D>::LoadFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& inputStream, param::hstring const& password) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfDocumentStatics)->LoadFromStreamWithPasswordAsync(*(void**)(&inputStream), *(void**)(&password), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Data_Pdf_IPdfPage<D>::RenderToStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& outputStream) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->RenderToStreamAsync(*(void**)(&outputStream), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Data_Pdf_IPdfPage<D>::RenderToStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& outputStream, winrt::Windows::Data::Pdf::PdfPageRenderOptions const& options) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->RenderWithOptionsToStreamAsync(*(void**)(&outputStream), *(void**)(&options), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Data_Pdf_IPdfPage<D>::PreparePageAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->PreparePageAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Data_Pdf_IPdfPage<D>::Index() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->get_Index(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Data_Pdf_IPdfPage<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Pdf::PdfPageDimensions) consume_Windows_Data_Pdf_IPdfPage<D>::Dimensions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->get_Dimensions(&value));
        return winrt::Windows::Data::Pdf::PdfPageDimensions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Pdf::PdfPageRotation) consume_Windows_Data_Pdf_IPdfPage<D>::Rotation() const
    {
        winrt::Windows::Data::Pdf::PdfPageRotation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->get_Rotation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Data_Pdf_IPdfPage<D>::PreferredZoom() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPage)->get_PreferredZoom(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Data_Pdf_IPdfPageDimensions<D>::MediaBox() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageDimensions)->get_MediaBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Data_Pdf_IPdfPageDimensions<D>::CropBox() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageDimensions)->get_CropBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Data_Pdf_IPdfPageDimensions<D>::BleedBox() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageDimensions)->get_BleedBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Data_Pdf_IPdfPageDimensions<D>::TrimBox() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageDimensions)->get_TrimBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Data_Pdf_IPdfPageDimensions<D>::ArtBox() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageDimensions)->get_ArtBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::SourceRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->get_SourceRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::SourceRect(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->put_SourceRect(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->get_DestinationWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationWidth(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->put_DestinationWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->get_DestinationHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::DestinationHeight(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->put_DestinationHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->get_BackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->put_BackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::IsIgnoringHighContrast() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->get_IsIgnoringHighContrast(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::IsIgnoringHighContrast(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->put_IsIgnoringHighContrast(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BitmapEncoderId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->get_BitmapEncoderId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Pdf_IPdfPageRenderOptions<D>::BitmapEncoderId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Pdf::IPdfPageRenderOptions)->put_BitmapEncoderId(impl::bind_in(value)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Pdf::IPdfDocument> : produce_base<D, winrt::Windows::Data::Pdf::IPdfDocument>
    {
        int32_t __stdcall GetPage(uint32_t pageIndex, void** pdfPage) noexcept final try
        {
            clear_abi(pdfPage);
            typename D::abi_guard guard(this->shim());
            *pdfPage = detach_from<winrt::Windows::Data::Pdf::PdfPage>(this->shim().GetPage(pageIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPasswordProtected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPasswordProtected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Pdf::IPdfDocumentStatics> : produce_base<D, winrt::Windows::Data::Pdf::IPdfDocumentStatics>
    {
        int32_t __stdcall LoadFromFileAsync(void* file, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadFromFileWithPasswordAsync(void* file, void* password, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&password)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadFromStreamAsync(void* inputStream, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&inputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadFromStreamWithPasswordAsync(void* inputStream, void* password, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Pdf::PdfDocument>>(this->shim().LoadFromStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&inputStream), *reinterpret_cast<hstring const*>(&password)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Pdf::IPdfPage> : produce_base<D, winrt::Windows::Data::Pdf::IPdfPage>
    {
        int32_t __stdcall RenderToStreamAsync(void* outputStream, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenderToStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RenderWithOptionsToStreamAsync(void* outputStream, void* options, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenderToStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&outputStream), *reinterpret_cast<winrt::Windows::Data::Pdf::PdfPageRenderOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PreparePageAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().PreparePageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Index(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Index());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Size(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Dimensions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Pdf::PdfPageDimensions>(this->shim().Dimensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rotation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Pdf::PdfPageRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredZoom(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().PreferredZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Pdf::IPdfPageDimensions> : produce_base<D, winrt::Windows::Data::Pdf::IPdfPageDimensions>
    {
        int32_t __stdcall get_MediaBox(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().MediaBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CropBox(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().CropBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BleedBox(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BleedBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrimBox(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().TrimBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ArtBox(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ArtBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Pdf::IPdfPageRenderOptions> : produce_base<D, winrt::Windows::Data::Pdf::IPdfPageRenderOptions>
    {
        int32_t __stdcall get_SourceRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().SourceRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourceRect(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceRect(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DestinationWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DestinationWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DestinationWidth(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DestinationWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DestinationHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DestinationHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DestinationHeight(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DestinationHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIgnoringHighContrast(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIgnoringHighContrast());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsIgnoringHighContrast(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsIgnoringHighContrast(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BitmapEncoderId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().BitmapEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BitmapEncoderId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BitmapEncoderId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Data::Pdf
{
    inline auto PdfDocument::LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<PdfDocument, IPdfDocumentStatics>([&](IPdfDocumentStatics const& f) { return f.LoadFromFileAsync(file); });
    }
    inline auto PdfDocument::LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& password)
    {
        return impl::call_factory<PdfDocument, IPdfDocumentStatics>([&](IPdfDocumentStatics const& f) { return f.LoadFromFileAsync(file, password); });
    }
    inline auto PdfDocument::LoadFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& inputStream)
    {
        return impl::call_factory<PdfDocument, IPdfDocumentStatics>([&](IPdfDocumentStatics const& f) { return f.LoadFromStreamAsync(inputStream); });
    }
    inline auto PdfDocument::LoadFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& inputStream, param::hstring const& password)
    {
        return impl::call_factory<PdfDocument, IPdfDocumentStatics>([&](IPdfDocumentStatics const& f) { return f.LoadFromStreamAsync(inputStream, password); });
    }
    inline PdfPageRenderOptions::PdfPageRenderOptions() :
        PdfPageRenderOptions(impl::call_factory_cast<PdfPageRenderOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), PdfPageRenderOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PdfPageRenderOptions>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Data::Pdf::IPdfDocument> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::IPdfDocumentStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::IPdfPage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::IPdfPageDimensions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::IPdfPageRenderOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::PdfDocument> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::PdfPage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::PdfPageDimensions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Pdf::PdfPageRenderOptions> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
