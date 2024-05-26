// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_H
#define WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.DataTransfer.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.ShareTarget.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Thumbnail(winrt::Windows::Storage::Streams::RandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::SupportedDataFormats() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_SupportedDataFormats(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>::SupportedFileTypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink)->get_SupportedFileTypes(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->get_Data(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::QuickLinkId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->get_QuickLinkId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::RemoveThisQuickLink() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->RemoveThisQuickLink());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportStarted() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportStarted());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportDataRetrieved() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportDataRetrieved());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportSubmittedBackgroundTask() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportSubmittedBackgroundTask());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportCompleted(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const& quicklink) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportCompletedWithQuickLink(*(void**)(&quicklink)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportCompleted() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportCompleted());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>::ReportError(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation)->ReportError(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation2<D>::DismissUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2)->DismissUI());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation3<D>::Contacts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3)->get_Contacts(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Thumbnail(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Thumbnail(*reinterpret_cast<winrt::Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedDataFormats(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedDataFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedFileTypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedFileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QuickLinkId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().QuickLinkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveThisQuickLink() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveThisQuickLink();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportStarted() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportStarted();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportDataRetrieved() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportDataRetrieved();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportSubmittedBackgroundTask() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportSubmittedBackgroundTask();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompletedWithQuickLink(void* quicklink) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const*>(&quicklink));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompleted() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportError(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>
    {
        int32_t __stdcall DismissUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>
    {
        int32_t __stdcall get_Contacts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().Contacts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget
{
    inline QuickLink::QuickLink() :
        QuickLink(impl::call_factory_cast<QuickLink(*)(winrt::Windows::Foundation::IActivationFactory const&), QuickLink>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<QuickLink>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
