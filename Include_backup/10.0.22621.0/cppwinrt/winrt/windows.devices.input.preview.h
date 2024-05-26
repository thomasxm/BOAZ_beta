// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Input_Preview_H
#define WINRT_Windows_Devices_Input_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Input.h"
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Input.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::CanTrackEyes() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->get_CanTrackEyes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::CanTrackHead() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->get_CanTrackHead(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::ConfigurationState() const
    {
        winrt::Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->get_ConfigurationState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::RequestCalibrationAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->RequestCalibrationAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::GetNumericControlDescriptions(uint16_t usagePage, uint16_t usageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->GetNumericControlDescriptions(usagePage, usageId, &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>) consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::GetBooleanControlDescriptions(uint16_t usagePage, uint16_t usageId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDevicePreview)->GetBooleanControlDescriptions(usagePage, usageId, &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeDevicePreview) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherAddedPreviewEventArgs<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs)->get_Device(&value));
        return winrt::Windows::Devices::Input::Preview::GazeDevicePreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeDevicePreview) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherRemovedPreviewEventArgs<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs)->get_Device(&value));
        return winrt::Windows::Devices::Input::Preview::GazeDevicePreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeDevicePreview) consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherUpdatedPreviewEventArgs<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs)->get_Device(&value));
        return winrt::Windows::Devices::Input::Preview::GazeDevicePreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazePointPreview) consume_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs<D>::CurrentPoint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs)->get_CurrentPoint(&value));
        return winrt::Windows::Devices::Input::Preview::GazePointPreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazePointPreview) consume_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs<D>::CurrentPoint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs)->get_CurrentPoint(&value));
        return winrt::Windows::Devices::Input::Preview::GazePointPreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview)->add_GazeMoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved_revoker consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GazeMoved_revoker>(this, GazeMoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview)->remove_GazeMoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview)->add_GazeEntered(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered_revoker consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GazeEntered_revoker>(this, GazeEntered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview)->remove_GazeEntered(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview)->add_GazeExited(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited_revoker consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GazeExited_revoker>(this, GazeExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview)->remove_GazeExited(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreviewStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics)->GetForCurrentView(&result));
        return winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview) consume_Windows_Devices_Input_Preview_IGazeInputSourcePreviewStatics<D>::CreateWatcher() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics)->CreateWatcher(&result));
        return winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazePointPreview) consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::CurrentPoint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->get_CurrentPoint(&value));
        return winrt::Windows::Devices::Input::Preview::GazePointPreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Input::Preview::GazePointPreview>) consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::GetIntermediatePoints() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->GetIntermediatePoints(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Input::Preview::GazePointPreview>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::Preview::GazeDevicePreview) consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::SourceDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazePointPreview)->get_SourceDevice(&value));
        return winrt::Windows::Devices::Input::Preview::GazeDevicePreview{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::EyeGazePosition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazePointPreview)->get_EyeGazePosition(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::HeadGazePosition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazePointPreview)->get_HeadGazePosition(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::Timestamp() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazePointPreview)->get_Timestamp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::HumanInterfaceDevice::HidInputReport) consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::HidInputReport() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Input::Preview::IGazePointPreview)->get_HidInputReport(&value));
        return winrt::Windows::Devices::HumanInterfaceDevice::HidInputReport{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeDevicePreview> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeDevicePreview>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanTrackEyes(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanTrackEyes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanTrackHead(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanTrackHead());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConfigurationState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview>(this->shim().ConfigurationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestCalibrationAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestCalibrationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNumericControlDescriptions(uint16_t usagePage, uint16_t usageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>>(this->shim().GetNumericControlDescriptions(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBooleanControlDescriptions(uint16_t usagePage, uint16_t usageId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>>(this->shim().GetBooleanControlDescriptions(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentPoint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazePointPreview>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentPoint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazePointPreview>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview>
    {
        int32_t __stdcall add_GazeMoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GazeMoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GazeMoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GazeMoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GazeEntered(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GazeEntered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GazeEntered(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GazeEntered(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GazeExited(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GazeExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview, winrt::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GazeExited(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GazeExited(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics>
    {
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWatcher(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentPoint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazePointPreview>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIntermediatePoints(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Input::Preview::GazePointPreview>>(this->shim().GetIntermediatePoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Input::Preview::IGazePointPreview> : produce_base<D, winrt::Windows::Devices::Input::Preview::IGazePointPreview>
    {
        int32_t __stdcall get_SourceDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().SourceDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EyeGazePosition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().EyeGazePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeadGazePosition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().HeadGazePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timestamp(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HidInputReport(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::HumanInterfaceDevice::HidInputReport>(this->shim().HidInputReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Input::Preview
{
    inline auto GazeInputSourcePreview::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview(*)(IGazeInputSourcePreviewStatics const&), GazeInputSourcePreview, IGazeInputSourcePreviewStatics>([](IGazeInputSourcePreviewStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto GazeInputSourcePreview::CreateWatcher()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview(*)(IGazeInputSourcePreviewStatics const&), GazeInputSourcePreview, IGazeInputSourcePreviewStatics>([](IGazeInputSourcePreviewStatics const& f) { return f.CreateWatcher(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDevicePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazePointPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDevicePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Input::Preview::GazePointPreview> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
