// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Preview_H
#define WINRT_Windows_System_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.Devices.Sensors.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::GetCurrentPostureAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview)->GetCurrentPostureAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview, winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview)->add_PostureChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged_revoker consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview, winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PostureChanged_revoker>(this, PostureChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreview<D>::PostureChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview)->remove_PostureChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Preview::HingeState) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::HingeState() const
    {
        winrt::Windows::System::Preview::HingeState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_HingeState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientation) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel1Orientation() const
    {
        winrt::Windows::Devices::Sensors::SimpleOrientation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel1Orientation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel1Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel1Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientation) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel2Orientation() const
    {
        winrt::Windows::Devices::Sensors::SimpleOrientation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel2Orientation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReading<D>::Panel2Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading)->get_Panel2Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview>) consume_Windows_System_Preview_ITwoPanelHingedDevicePosturePreviewStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview> : produce_base<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview>
    {
        int32_t __stdcall GetCurrentPostureAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>>(this->shim().GetCurrentPostureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PostureChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PostureChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview, winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PostureChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PostureChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading> : produce_base<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HingeState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Preview::HingeState>(this->shim().HingeState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Panel1Orientation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SimpleOrientation>(this->shim().Panel1Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Panel1Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Panel1Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Panel2Orientation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SimpleOrientation>(this->shim().Panel2Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Panel2Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Panel2Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> : produce_base<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics> : produce_base<D, winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Preview
{
    inline auto TwoPanelHingedDevicePosturePreview::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview>(*)(ITwoPanelHingedDevicePosturePreviewStatics const&), TwoPanelHingedDevicePosturePreview, ITwoPanelHingedDevicePosturePreviewStatics>([](ITwoPanelHingedDevicePosturePreviewStatics const& f) { return f.GetDefaultAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Preview::TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
