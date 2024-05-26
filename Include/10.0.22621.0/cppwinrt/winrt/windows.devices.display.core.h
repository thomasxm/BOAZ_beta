// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Display_Core_H
#define WINRT_Windows_Devices_Display_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Display.h"
#include "winrt/impl/Windows.Devices.Display.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Display.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DisplayAdapterId) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::Id() const
    {
        winrt::Windows::Graphics::DisplayAdapterId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::DeviceInterfacePath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_DeviceInterfacePath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::SourceCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_SourceCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciVendorId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_PciVendorId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciDeviceId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_PciDeviceId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciSubSystemId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_PciSubSystemId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciRevision() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_PciRevision(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapter)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayAdapter) consume_Windows_Devices_Display_Core_IDisplayAdapterStatics<D>::FromId(winrt::Windows::Graphics::DisplayAdapterId const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayAdapterStatics)->FromId(impl::bind_in(id), &result));
        return winrt::Windows::Devices::Display::Core::DisplayAdapter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplaySource) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreateScanoutSource(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->CreateScanoutSource(*(void**)(&target), &result));
        return winrt::Windows::Devices::Display::Core::DisplaySource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplaySurface) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreatePrimary(winrt::Windows::Devices::Display::Core::DisplayTarget const& target, winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription const& desc) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->CreatePrimary(*(void**)(&target), *(void**)(&desc), &result));
        return winrt::Windows::Devices::Display::Core::DisplaySurface{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayTaskPool) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreateTaskPool() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->CreateTaskPool(&result));
        return winrt::Windows::Devices::Display::Core::DisplayTaskPool{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayFence) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreatePeriodicFence(winrt::Windows::Devices::Display::Core::DisplayTarget const& target, winrt::Windows::Foundation::TimeSpan const& offsetFromVBlank) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->CreatePeriodicFence(*(void**)(&target), impl::bind_in(offsetFromVBlank), &result));
        return winrt::Windows::Devices::Display::Core::DisplayFence{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::WaitForVBlank(winrt::Windows::Devices::Display::Core::DisplaySource const& source) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->WaitForVBlank(*(void**)(&source)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayScanout) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreateSimpleScanout(winrt::Windows::Devices::Display::Core::DisplaySource const& pSource, winrt::Windows::Devices::Display::Core::DisplaySurface const& pSurface, uint32_t SubResourceIndex, uint32_t SyncInterval) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->CreateSimpleScanout(*(void**)(&pSource), *(void**)(&pSurface), SubResourceIndex, SyncInterval, &result));
        return winrt::Windows::Devices::Display::Core::DisplayScanout{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayDevice<D>::IsCapabilitySupported(winrt::Windows::Devices::Display::Core::DisplayDeviceCapability const& capability) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice)->IsCapabilitySupported(static_cast<int32_t>(capability), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayScanout) consume_Windows_Devices_Display_Core_IDisplayDevice2<D>::CreateSimpleScanoutWithDirtyRectsAndOptions(winrt::Windows::Devices::Display::Core::DisplaySource const& source, winrt::Windows::Devices::Display::Core::DisplaySurface const& surface, uint32_t subresourceIndex, uint32_t syncInterval, param::iterable<winrt::Windows::Graphics::RectInt32> const& dirtyRects, winrt::Windows::Devices::Display::Core::DisplayScanoutOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayDevice2)->CreateSimpleScanoutWithDirtyRectsAndOptions(*(void**)(&source), *(void**)(&surface), subresourceIndex, syncInterval, *(void**)(&dirtyRects), static_cast<uint32_t>(options), &result));
        return winrt::Windows::Devices::Display::Core::DisplayScanout{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayTarget>) consume_Windows_Devices_Display_Core_IDisplayManager<D>::GetCurrentTargets() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->GetCurrentTargets(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayTarget>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayAdapter>) consume_Windows_Devices_Display_Core_IDisplayManager<D>::GetCurrentAdapters() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->GetCurrentAdapters(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayAdapter>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManagerResult) consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        winrt::Windows::Devices::Display::Core::DisplayManagerResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTarget(*(void**)(&target), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::ReleaseTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->ReleaseTarget(*(void**)(&target)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState) consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryReadCurrentStateForAllTargets() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->TryReadCurrentStateForAllTargets(&result));
        return winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState) consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTargetsAndReadCurrentState(param::iterable<winrt::Windows::Devices::Display::Core::DisplayTarget> const& targets) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTargetsAndReadCurrentState(*(void**)(&targets), &result));
        return winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState) consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTargetsAndCreateEmptyState(param::iterable<winrt::Windows::Devices::Display::Core::DisplayTarget> const& targets) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTargetsAndCreateEmptyState(*(void**)(&targets), &result));
        return winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState) consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTargetsAndCreateSubstate(winrt::Windows::Devices::Display::Core::DisplayState const& existingState, param::iterable<winrt::Windows::Devices::Display::Core::DisplayTarget> const& targets) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTargetsAndCreateSubstate(*(void**)(&existingState), *(void**)(&targets), &result));
        return winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayDevice) consume_Windows_Devices_Display_Core_IDisplayManager<D>::CreateDisplayDevice(winrt::Windows::Devices::Display::Core::DisplayAdapter const& adapter) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->CreateDisplayDevice(*(void**)(&adapter), &result));
        return winrt::Windows::Devices::Display::Core::DisplayDevice{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->add_Enabled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Enabled_revoker>(this, Enabled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->remove_Enabled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->add_Disabled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Disabled_revoker>(this, Disabled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->remove_Disabled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->add_Changed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->remove_Changed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->add_PathsFailedOrInvalidated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PathsFailedOrInvalidated_revoker>(this, PathsFailedOrInvalidated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->remove_PathsFailedOrInvalidated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManager<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManager)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManagerResult) consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>::ErrorCode() const
    {
        winrt::Windows::Devices::Display::Core::DisplayManagerResult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState)->get_ErrorCode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>::ExtendedErrorCode() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState)->get_ExtendedErrorCode(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayState) consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>::State() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState)->get_State(&value));
        return winrt::Windows::Devices::Display::Core::DisplayState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayManager) consume_Windows_Devices_Display_Core_IDisplayManagerStatics<D>::Create(winrt::Windows::Devices::Display::Core::DisplayManagerOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayManagerStatics)->Create(static_cast<uint32_t>(options), &result));
        return winrt::Windows::Devices::Display::Core::DisplayManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::SourceResolution() const
    {
        winrt::Windows::Graphics::SizeInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_SourceResolution(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::IsStereo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_IsStereo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::DirectXPixelFormat) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::SourcePixelFormat() const
    {
        winrt::Windows::Graphics::DirectX::DirectXPixelFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_SourcePixelFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::TargetResolution() const
    {
        winrt::Windows::Graphics::SizeInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_TargetResolution(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPresentationRate) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::PresentationRate() const
    {
        winrt::Windows::Devices::Display::Core::DisplayPresentationRate value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_PresentationRate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::IsInterlaced() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_IsInterlaced(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayBitsPerChannel) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::GetWireFormatSupportedBitsPerChannel(winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& encoding) const
    {
        winrt::Windows::Devices::Display::Core::DisplayBitsPerChannel result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->GetWireFormatSupportedBitsPerChannel(static_cast<int32_t>(encoding), reinterpret_cast<uint32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::IsWireFormatSupported(winrt::Windows::Devices::Display::Core::DisplayWireFormat const& wireFormat) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->IsWireFormatSupported(*(void**)(&wireFormat), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPresentationRate) consume_Windows_Devices_Display_Core_IDisplayModeInfo2<D>::PhysicalPresentationRate() const
    {
        winrt::Windows::Devices::Display::Core::DisplayPresentationRate value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayModeInfo2)->get_PhysicalPresentationRate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayView) consume_Windows_Devices_Display_Core_IDisplayPath<D>::View() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_View(&value));
        return winrt::Windows::Devices::Display::Core::DisplayView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayTarget) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Target() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_Target(&value));
        return winrt::Windows::Devices::Display::Core::DisplayTarget{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPathStatus) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Status() const
    {
        winrt::Windows::Devices::Display::Core::DisplayPathStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>) consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourceResolution() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_SourceResolution(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourceResolution(winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_SourceResolution(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::DirectXPixelFormat) consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourcePixelFormat() const
    {
        winrt::Windows::Graphics::DirectX::DirectXPixelFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_SourcePixelFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourcePixelFormat(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_SourcePixelFormat(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsStereo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_IsStereo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsStereo(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_IsStereo(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>) consume_Windows_Devices_Display_Core_IDisplayPath<D>::TargetResolution() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_TargetResolution(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::TargetResolution(winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_TargetResolution(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>) consume_Windows_Devices_Display_Core_IDisplayPath<D>::PresentationRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_PresentationRate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::PresentationRate(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_PresentationRate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsInterlaced() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_IsInterlaced(&value));
        return winrt::Windows::Foundation::IReference<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsInterlaced(winrt::Windows::Foundation::IReference<bool> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_IsInterlaced(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormat) consume_Windows_Devices_Display_Core_IDisplayPath<D>::WireFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_WireFormat(&value));
        return winrt::Windows::Devices::Display::Core::DisplayWireFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::WireFormat(winrt::Windows::Devices::Display::Core::DisplayWireFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_WireFormat(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayRotation) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Rotation() const
    {
        winrt::Windows::Devices::Display::Core::DisplayRotation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_Rotation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Rotation(winrt::Windows::Devices::Display::Core::DisplayRotation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_Rotation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPathScaling) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Scaling() const
    {
        winrt::Windows::Devices::Display::Core::DisplayPathScaling value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_Scaling(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Scaling(winrt::Windows::Devices::Display::Core::DisplayPathScaling const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->put_Scaling(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayModeInfo>) consume_Windows_Devices_Display_Core_IDisplayPath<D>::FindModes(winrt::Windows::Devices::Display::Core::DisplayModeQueryOptions const& flags) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->FindModes(static_cast<uint32_t>(flags), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayModeInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath<D>::ApplyPropertiesFromMode(winrt::Windows::Devices::Display::Core::DisplayModeInfo const& modeResult) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->ApplyPropertiesFromMode(*(void**)(&modeResult)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayPath<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>) consume_Windows_Devices_Display_Core_IDisplayPath2<D>::PhysicalPresentationRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath2)->get_PhysicalPresentationRate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayPath2<D>::PhysicalPresentationRate(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPath2)->put_PhysicalPresentationRate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::DirectXPixelFormat) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Format() const
    {
        winrt::Windows::Graphics::DirectX::DirectXPixelFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Format(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::DirectXColorSpace) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::ColorSpace() const
    {
        winrt::Windows::Graphics::DirectX::DirectXColorSpace value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_ColorSpace(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::IsStereo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_IsStereo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::MultisampleDescription() const
    {
        winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_MultisampleDescription(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionFactory<D>::CreateInstance(uint32_t width, uint32_t height, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, winrt::Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory)->CreateInstance(width, height, static_cast<int32_t>(pixelFormat), static_cast<int32_t>(colorSpace), isStereo, impl::bind_in(multisampleDescription), &value));
        return winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription) consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionStatics<D>::CreateWithProperties(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::guid, winrt::Windows::Foundation::IInspectable>> const& extraProperties, uint32_t width, uint32_t height, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, winrt::Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics)->CreateWithProperties(*(void**)(&extraProperties), width, height, static_cast<int32_t>(pixelFormat), static_cast<int32_t>(colorSpace), isStereo, impl::bind_in(multisampleDescription), &result));
        return winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DisplayAdapterId) consume_Windows_Devices_Display_Core_IDisplaySource<D>::AdapterId() const
    {
        winrt::Windows::Graphics::DisplayAdapterId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplaySource)->get_AdapterId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplaySource<D>::SourceId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplaySource)->get_SourceId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_Display_Core_IDisplaySource<D>::GetMetadata(winrt::guid const& Key) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplaySource)->GetMetadata(impl::bind_in(Key), &result));
        return winrt::Windows::Storage::Streams::IBuffer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplaySourceStatus) consume_Windows_Devices_Display_Core_IDisplaySource2<D>::Status() const
    {
        winrt::Windows::Devices::Display::Core::DisplaySourceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplaySource2)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Display_Core_IDisplaySource2<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplaySource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplaySource2)->add_StatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Display_Core_IDisplaySource2<D>::StatusChanged_revoker consume_Windows_Devices_Display_Core_IDisplaySource2<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplaySource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplaySource2<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplaySource2)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayState<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayState<D>::IsStale() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->get_IsStale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayTarget>) consume_Windows_Devices_Display_Core_IDisplayState<D>::Targets() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->get_Targets(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayTarget>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayView>) consume_Windows_Devices_Display_Core_IDisplayState<D>::Views() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->get_Views(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayView>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayState<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPath) consume_Windows_Devices_Display_Core_IDisplayState<D>::ConnectTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->ConnectTarget(*(void**)(&target), &result));
        return winrt::Windows::Devices::Display::Core::DisplayPath{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPath) consume_Windows_Devices_Display_Core_IDisplayState<D>::ConnectTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target, winrt::Windows::Devices::Display::Core::DisplayView const& view) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->ConnectTargetToView(*(void**)(&target), *(void**)(&view), &result));
        return winrt::Windows::Devices::Display::Core::DisplayPath{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayState<D>::CanConnectTargetToView(winrt::Windows::Devices::Display::Core::DisplayTarget const& target, winrt::Windows::Devices::Display::Core::DisplayView const& view) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->CanConnectTargetToView(*(void**)(&target), *(void**)(&view), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayView) consume_Windows_Devices_Display_Core_IDisplayState<D>::GetViewForTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->GetViewForTarget(*(void**)(&target), &result));
        return winrt::Windows::Devices::Display::Core::DisplayView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPath) consume_Windows_Devices_Display_Core_IDisplayState<D>::GetPathForTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->GetPathForTarget(*(void**)(&target), &result));
        return winrt::Windows::Devices::Display::Core::DisplayPath{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayState<D>::DisconnectTarget(winrt::Windows::Devices::Display::Core::DisplayTarget const& target) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->DisconnectTarget(*(void**)(&target)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayStateOperationResult) consume_Windows_Devices_Display_Core_IDisplayState<D>::TryFunctionalize(winrt::Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->TryFunctionalize(static_cast<uint32_t>(options), &result));
        return winrt::Windows::Devices::Display::Core::DisplayStateOperationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayStateOperationResult) consume_Windows_Devices_Display_Core_IDisplayState<D>::TryApply(winrt::Windows::Devices::Display::Core::DisplayStateApplyOptions const& options) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->TryApply(static_cast<uint32_t>(options), &result));
        return winrt::Windows::Devices::Display::Core::DisplayStateOperationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayState) consume_Windows_Devices_Display_Core_IDisplayState<D>::Clone() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayState)->Clone(&result));
        return winrt::Windows::Devices::Display::Core::DisplayState{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayStateOperationStatus) consume_Windows_Devices_Display_Core_IDisplayStateOperationResult<D>::Status() const
    {
        winrt::Windows::Devices::Display::Core::DisplayStateOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Devices_Display_Core_IDisplayStateOperationResult<D>::ExtendedErrorCode() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult)->get_ExtendedErrorCode(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayAdapter) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::Adapter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_Adapter(&value));
        return winrt::Windows::Devices::Display::Core::DisplayAdapter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::DeviceInterfacePath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_DeviceInterfacePath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::AdapterRelativeId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_AdapterRelativeId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsConnected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_IsConnected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsVirtualModeEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_IsVirtualModeEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsVirtualTopologyEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_IsVirtualTopologyEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::DisplayMonitorUsageKind) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::UsageKind() const
    {
        winrt::Windows::Devices::Display::DisplayMonitorUsageKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_UsageKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayTargetPersistence) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::MonitorPersistence() const
    {
        winrt::Windows::Devices::Display::Core::DisplayTargetPersistence value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_MonitorPersistence(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::StableMonitorId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_StableMonitorId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::DisplayMonitor) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::TryGetMonitor() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->TryGetMonitor(&result));
        return winrt::Windows::Devices::Display::DisplayMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsStale() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->get_IsStale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsSame(winrt::Windows::Devices::Display::Core::DisplayTarget const& otherTarget) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->IsSame(*(void**)(&otherTarget), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsEqual(winrt::Windows::Devices::Display::Core::DisplayTarget const& otherTarget) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTarget)->IsEqual(*(void**)(&otherTarget), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayTask<D>::SetScanout(winrt::Windows::Devices::Display::Core::DisplayScanout const& scanout) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTask)->SetScanout(*(void**)(&scanout)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayTask<D>::SetWait(winrt::Windows::Devices::Display::Core::DisplayFence const& readyFence, uint64_t readyFenceValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTask)->SetWait(*(void**)(&readyFence), readyFenceValue));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayTask2<D>::SetSignal(winrt::Windows::Devices::Display::Core::DisplayTaskSignalKind const& signalKind, winrt::Windows::Devices::Display::Core::DisplayFence const& fence) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTask2)->SetSignal(static_cast<int32_t>(signalKind), *(void**)(&fence)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayTask) consume_Windows_Devices_Display_Core_IDisplayTaskPool<D>::CreateTask() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTaskPool)->CreateTask(&result));
        return winrt::Windows::Devices::Display::Core::DisplayTask{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayTaskPool<D>::ExecuteTask(winrt::Windows::Devices::Display::Core::DisplayTask const& task) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTaskPool)->ExecuteTask(*(void**)(&task)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayTaskResult) consume_Windows_Devices_Display_Core_IDisplayTaskPool2<D>::TryExecuteTask(winrt::Windows::Devices::Display::Core::DisplayTask const& task) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTaskPool2)->TryExecuteTask(*(void**)(&task), &result));
        return winrt::Windows::Devices::Display::Core::DisplayTaskResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayPresentStatus) consume_Windows_Devices_Display_Core_IDisplayTaskResult<D>::PresentStatus() const
    {
        winrt::Windows::Devices::Display::Core::DisplayPresentStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTaskResult)->get_PresentStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Display_Core_IDisplayTaskResult<D>::PresentId() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTaskResult)->get_PresentId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplaySourceStatus) consume_Windows_Devices_Display_Core_IDisplayTaskResult<D>::SourceStatus() const
    {
        winrt::Windows::Devices::Display::Core::DisplaySourceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayTaskResult)->get_SourceStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayPath>) consume_Windows_Devices_Display_Core_IDisplayView<D>::Paths() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayView)->get_Paths(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayPath>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>) consume_Windows_Devices_Display_Core_IDisplayView<D>::ContentResolution() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayView)->get_ContentResolution(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayView<D>::ContentResolution(winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayView)->put_ContentResolution(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Display_Core_IDisplayView<D>::SetPrimaryPath(winrt::Windows::Devices::Display::Core::DisplayPath const& path) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayView)->SetPrimaryPath(*(void**)(&path)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayView<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayView)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding) consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::PixelEncoding() const
    {
        winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormat)->get_PixelEncoding(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::BitsPerChannel() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormat)->get_BitsPerChannel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace) consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::ColorSpace() const
    {
        winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormat)->get_ColorSpace(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf) consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::Eotf() const
    {
        winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormat)->get_Eotf(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata) consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::HdrMetadata() const
    {
        winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormat)->get_HdrMetadata(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormat)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormat) consume_Windows_Devices_Display_Core_IDisplayWireFormatFactory<D>::CreateInstance(winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormatFactory)->CreateInstance(static_cast<int32_t>(pixelEncoding), bitsPerChannel, static_cast<int32_t>(colorSpace), static_cast<int32_t>(eotf), static_cast<int32_t>(hdrMetadata), &value));
        return winrt::Windows::Devices::Display::Core::DisplayWireFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::Core::DisplayWireFormat) consume_Windows_Devices_Display_Core_IDisplayWireFormatStatics<D>::CreateWithProperties(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::guid, winrt::Windows::Foundation::IInspectable>> const& extraProperties, winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::Core::IDisplayWireFormatStatics)->CreateWithProperties(*(void**)(&extraProperties), static_cast<int32_t>(pixelEncoding), bitsPerChannel, static_cast<int32_t>(colorSpace), static_cast<int32_t>(eotf), static_cast<int32_t>(hdrMetadata), &result));
        return winrt::Windows::Devices::Display::Core::DisplayWireFormat{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayAdapter> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayAdapter>
    {
        int32_t __stdcall get_Id(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::DisplayAdapterId>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DisplayAdapterId>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceInterfacePath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceInterfacePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SourceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PciVendorId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PciVendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PciDeviceId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PciDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PciSubSystemId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PciSubSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PciRevision(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PciRevision());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayAdapterStatics> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayAdapterStatics>
    {
        int32_t __stdcall FromId(struct struct_Windows_Graphics_DisplayAdapterId id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayAdapter>(this->shim().FromId(*reinterpret_cast<winrt::Windows::Graphics::DisplayAdapterId const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayDevice> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayDevice>
    {
        int32_t __stdcall CreateScanoutSource(void* target, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplaySource>(this->shim().CreateScanoutSource(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePrimary(void* target, void* desc, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplaySurface>(this->shim().CreatePrimary(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription const*>(&desc)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTaskPool(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayTaskPool>(this->shim().CreateTaskPool());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePeriodicFence(void* target, int64_t offsetFromVBlank, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayFence>(this->shim().CreatePeriodicFence(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&offsetFromVBlank)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForVBlank(void* source) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WaitForVBlank(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplaySource const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSimpleScanout(void* pSource, void* pSurface, uint32_t SubResourceIndex, uint32_t SyncInterval, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayScanout>(this->shim().CreateSimpleScanout(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplaySource const*>(&pSource), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplaySurface const*>(&pSurface), SubResourceIndex, SyncInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsCapabilitySupported(int32_t capability, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsCapabilitySupported(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayDeviceCapability const*>(&capability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayDevice2> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayDevice2>
    {
        int32_t __stdcall CreateSimpleScanoutWithDirtyRectsAndOptions(void* source, void* surface, uint32_t subresourceIndex, uint32_t syncInterval, void* dirtyRects, uint32_t options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayScanout>(this->shim().CreateSimpleScanoutWithDirtyRectsAndOptions(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplaySource const*>(&source), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplaySurface const*>(&surface), subresourceIndex, syncInterval, *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Graphics::RectInt32> const*>(&dirtyRects), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayScanoutOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayFence> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayFence>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManager> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManager>
    {
        int32_t __stdcall GetCurrentTargets(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayTarget>>(this->shim().GetCurrentTargets());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentAdapters(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayAdapter>>(this->shim().GetCurrentAdapters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryAcquireTarget(void* target, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayManagerResult>(this->shim().TryAcquireTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleaseTarget(void* target) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryReadCurrentStateForAllTargets(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryReadCurrentStateForAllTargets());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryAcquireTargetsAndReadCurrentState(void* targets, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryAcquireTargetsAndReadCurrentState(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Display::Core::DisplayTarget> const*>(&targets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryAcquireTargetsAndCreateEmptyState(void* targets, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryAcquireTargetsAndCreateEmptyState(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Display::Core::DisplayTarget> const*>(&targets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryAcquireTargetsAndCreateSubstate(void* existingState, void* targets, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryAcquireTargetsAndCreateSubstate(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayState const*>(&existingState), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Display::Core::DisplayTarget> const*>(&targets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDisplayDevice(void* adapter, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayDevice>(this->shim().CreateDisplayDevice(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Enabled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Enabled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Enabled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Disabled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Disabled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Disabled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disabled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Changed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Changed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PathsFailedOrInvalidated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PathsFailedOrInvalidated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplayManager, winrt::Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PathsFailedOrInvalidated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PathsFailedOrInvalidated(*reinterpret_cast<winrt::event_token const*>(&token));
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
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs>
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
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs>
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
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs>
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
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs>
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
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState>
    {
        int32_t __stdcall get_ErrorCode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayManagerResult>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedErrorCode(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayManagerStatics> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayManagerStatics>
    {
        int32_t __stdcall Create(uint32_t options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayManager>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayManagerOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayModeInfo> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayModeInfo>
    {
        int32_t __stdcall get_SourceResolution(struct struct_Windows_Graphics_SizeInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::SizeInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::SizeInt32>(this->shim().SourceResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStereo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourcePixelFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().SourcePixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetResolution(struct struct_Windows_Graphics_SizeInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::SizeInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::SizeInt32>(this->shim().TargetResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PresentationRate(struct struct_Windows_Devices_Display_Core_DisplayPresentationRate* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>(this->shim().PresentationRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInterlaced(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInterlaced());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetWireFormatSupportedBitsPerChannel(int32_t encoding, uint32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayBitsPerChannel>(this->shim().GetWireFormatSupportedBitsPerChannel(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsWireFormatSupported(void* wireFormat, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsWireFormatSupported(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormat const*>(&wireFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayModeInfo2> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayModeInfo2>
    {
        int32_t __stdcall get_PhysicalPresentationRate(struct struct_Windows_Devices_Display_Core_DisplayPresentationRate* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>(this->shim().PhysicalPresentationRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayPath> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayPath>
    {
        int32_t __stdcall get_View(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayView>(this->shim().View());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Target(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayTarget>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayPathStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceResolution(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>>(this->shim().SourceResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourceResolution(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceResolution(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourcePixelFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().SourcePixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourcePixelFormat(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourcePixelFormat(*reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXPixelFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStereo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsStereo(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsStereo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetResolution(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>>(this->shim().TargetResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetResolution(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetResolution(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PresentationRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>>(this->shim().PresentationRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PresentationRate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PresentationRate(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInterlaced(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<bool>>(this->shim().IsInterlaced());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInterlaced(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInterlaced(*reinterpret_cast<winrt::Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WireFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormat>(this->shim().WireFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WireFormat(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WireFormat(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rotation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Rotation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rotation(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scaling(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayPathScaling>(this->shim().Scaling());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Scaling(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Scaling(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayPathScaling const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindModes(uint32_t flags, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayModeInfo>>(this->shim().FindModes(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayModeQueryOptions const*>(&flags)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ApplyPropertiesFromMode(void* modeResult) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplyPropertiesFromMode(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayModeInfo const*>(&modeResult));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayPath2> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayPath2>
    {
        int32_t __stdcall get_PhysicalPresentationRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate>>(this->shim().PhysicalPresentationRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PhysicalPresentationRate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PhysicalPresentationRate(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Display::Core::DisplayPresentationRate> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription>
    {
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Format(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColorSpace(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::DirectXColorSpace>(this->shim().ColorSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStereo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MultisampleDescription(struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription>(this->shim().MultisampleDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>
    {
        int32_t __stdcall CreateInstance(uint32_t width, uint32_t height, int32_t pixelFormat, int32_t colorSpace, bool isStereo, struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription multisampleDescription, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription>(this->shim().CreateInstance(width, height, *reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXColorSpace const*>(&colorSpace), isStereo, *reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const*>(&multisampleDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>
    {
        int32_t __stdcall CreateWithProperties(void* extraProperties, uint32_t width, uint32_t height, int32_t pixelFormat, int32_t colorSpace, bool isStereo, struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription multisampleDescription, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription>(this->shim().CreateWithProperties(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::guid, winrt::Windows::Foundation::IInspectable>> const*>(&extraProperties), width, height, *reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXColorSpace const*>(&colorSpace), isStereo, *reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const*>(&multisampleDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayScanout> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayScanout>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplaySource> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplaySource>
    {
        int32_t __stdcall get_AdapterId(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::DisplayAdapterId>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DisplayAdapterId>(this->shim().AdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SourceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMetadata(winrt::guid Key, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().GetMetadata(*reinterpret_cast<winrt::guid const*>(&Key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplaySource2> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplaySource2>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplaySourceStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Display::Core::DisplaySource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayState> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayState>
    {
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStale(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Targets(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayTarget>>(this->shim().Targets());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Views(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayView>>(this->shim().Views());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectTarget(void* target, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayPath>(this->shim().ConnectTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectTargetToView(void* target, void* view, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayPath>(this->shim().ConnectTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CanConnectTargetToView(void* target, void* view, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CanConnectTargetToView(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetViewForTarget(void* target, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayView>(this->shim().GetViewForTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPathForTarget(void* target, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayPath>(this->shim().GetPathForTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisconnectTarget(void* target) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisconnectTarget(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryFunctionalize(uint32_t options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayStateOperationResult>(this->shim().TryFunctionalize(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryApply(uint32_t options, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayStateOperationResult>(this->shim().TryApply(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayStateApplyOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clone(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayState>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayStateOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedErrorCode(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplaySurface> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplaySurface>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayTarget> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayTarget>
    {
        int32_t __stdcall get_Adapter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayAdapter>(this->shim().Adapter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceInterfacePath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceInterfacePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AdapterRelativeId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AdapterRelativeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConnected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVirtualModeEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVirtualModeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVirtualTopologyEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVirtualTopologyEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsageKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::DisplayMonitorUsageKind>(this->shim().UsageKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MonitorPersistence(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayTargetPersistence>(this->shim().MonitorPersistence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StableMonitorId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StableMonitorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetMonitor(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::DisplayMonitor>(this->shim().TryGetMonitor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStale(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSame(void* otherTarget, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSame(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&otherTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEqual(void* otherTarget, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTarget const*>(&otherTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayTask> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayTask>
    {
        int32_t __stdcall SetScanout(void* scanout) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetScanout(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayScanout const*>(&scanout));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetWait(void* readyFence, uint64_t readyFenceValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetWait(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayFence const*>(&readyFence), readyFenceValue);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayTask2> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayTask2>
    {
        int32_t __stdcall SetSignal(int32_t signalKind, void* fence) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSignal(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTaskSignalKind const*>(&signalKind), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayFence const*>(&fence));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayTaskPool> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayTaskPool>
    {
        int32_t __stdcall CreateTask(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayTask>(this->shim().CreateTask());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ExecuteTask(void* task) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExecuteTask(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTask const*>(&task));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayTaskPool2> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayTaskPool2>
    {
        int32_t __stdcall TryExecuteTask(void* task, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayTaskResult>(this->shim().TryExecuteTask(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayTask const*>(&task)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayTaskResult> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayTaskResult>
    {
        int32_t __stdcall get_PresentStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayPresentStatus>(this->shim().PresentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PresentId(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().PresentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplaySourceStatus>(this->shim().SourceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayView> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayView>
    {
        int32_t __stdcall get_Paths(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Display::Core::DisplayPath>>(this->shim().Paths());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentResolution(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32>>(this->shim().ContentResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentResolution(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentResolution(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::SizeInt32> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrimaryPath(void* path) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPrimaryPath(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayPath const*>(&path));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayWireFormat> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayWireFormat>
    {
        int32_t __stdcall get_PixelEncoding(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding>(this->shim().PixelEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BitsPerChannel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().BitsPerChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColorSpace(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace>(this->shim().ColorSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Eotf(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf>(this->shim().Eotf());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HdrMetadata(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata>(this->shim().HdrMetadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayWireFormatFactory> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayWireFormatFactory>
    {
        int32_t __stdcall CreateInstance(int32_t pixelEncoding, int32_t bitsPerChannel, int32_t colorSpace, int32_t eotf, int32_t hdrMetadata, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormat>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const*>(&pixelEncoding), bitsPerChannel, *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace const*>(&colorSpace), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf const*>(&eotf), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const*>(&hdrMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::Core::IDisplayWireFormatStatics> : produce_base<D, winrt::Windows::Devices::Display::Core::IDisplayWireFormatStatics>
    {
        int32_t __stdcall CreateWithProperties(void* extraProperties, int32_t pixelEncoding, int32_t bitsPerChannel, int32_t colorSpace, int32_t eotf, int32_t hdrMetadata, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Display::Core::DisplayWireFormat>(this->shim().CreateWithProperties(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::guid, winrt::Windows::Foundation::IInspectable>> const*>(&extraProperties), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const*>(&pixelEncoding), bitsPerChannel, *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace const*>(&colorSpace), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf const*>(&eotf), *reinterpret_cast<winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const*>(&hdrMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Display::Core
{
    constexpr auto operator|(DisplayBitsPerChannel const left, DisplayBitsPerChannel const right) noexcept
    {
        return static_cast<DisplayBitsPerChannel>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayBitsPerChannel& left, DisplayBitsPerChannel const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayBitsPerChannel const left, DisplayBitsPerChannel const right) noexcept
    {
        return static_cast<DisplayBitsPerChannel>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayBitsPerChannel& left, DisplayBitsPerChannel const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayBitsPerChannel const value) noexcept
    {
        return static_cast<DisplayBitsPerChannel>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayBitsPerChannel const left, DisplayBitsPerChannel const right) noexcept
    {
        return static_cast<DisplayBitsPerChannel>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayBitsPerChannel& left, DisplayBitsPerChannel const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DisplayManagerOptions const left, DisplayManagerOptions const right) noexcept
    {
        return static_cast<DisplayManagerOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayManagerOptions& left, DisplayManagerOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayManagerOptions const left, DisplayManagerOptions const right) noexcept
    {
        return static_cast<DisplayManagerOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayManagerOptions& left, DisplayManagerOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayManagerOptions const value) noexcept
    {
        return static_cast<DisplayManagerOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayManagerOptions const left, DisplayManagerOptions const right) noexcept
    {
        return static_cast<DisplayManagerOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayManagerOptions& left, DisplayManagerOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DisplayModeQueryOptions const left, DisplayModeQueryOptions const right) noexcept
    {
        return static_cast<DisplayModeQueryOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayModeQueryOptions& left, DisplayModeQueryOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayModeQueryOptions const left, DisplayModeQueryOptions const right) noexcept
    {
        return static_cast<DisplayModeQueryOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayModeQueryOptions& left, DisplayModeQueryOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayModeQueryOptions const value) noexcept
    {
        return static_cast<DisplayModeQueryOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayModeQueryOptions const left, DisplayModeQueryOptions const right) noexcept
    {
        return static_cast<DisplayModeQueryOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayModeQueryOptions& left, DisplayModeQueryOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DisplayScanoutOptions const left, DisplayScanoutOptions const right) noexcept
    {
        return static_cast<DisplayScanoutOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayScanoutOptions& left, DisplayScanoutOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayScanoutOptions const left, DisplayScanoutOptions const right) noexcept
    {
        return static_cast<DisplayScanoutOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayScanoutOptions& left, DisplayScanoutOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayScanoutOptions const value) noexcept
    {
        return static_cast<DisplayScanoutOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayScanoutOptions const left, DisplayScanoutOptions const right) noexcept
    {
        return static_cast<DisplayScanoutOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayScanoutOptions& left, DisplayScanoutOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DisplayStateApplyOptions const left, DisplayStateApplyOptions const right) noexcept
    {
        return static_cast<DisplayStateApplyOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayStateApplyOptions& left, DisplayStateApplyOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayStateApplyOptions const left, DisplayStateApplyOptions const right) noexcept
    {
        return static_cast<DisplayStateApplyOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayStateApplyOptions& left, DisplayStateApplyOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayStateApplyOptions const value) noexcept
    {
        return static_cast<DisplayStateApplyOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayStateApplyOptions const left, DisplayStateApplyOptions const right) noexcept
    {
        return static_cast<DisplayStateApplyOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayStateApplyOptions& left, DisplayStateApplyOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DisplayStateFunctionalizeOptions const left, DisplayStateFunctionalizeOptions const right) noexcept
    {
        return static_cast<DisplayStateFunctionalizeOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayStateFunctionalizeOptions& left, DisplayStateFunctionalizeOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayStateFunctionalizeOptions const left, DisplayStateFunctionalizeOptions const right) noexcept
    {
        return static_cast<DisplayStateFunctionalizeOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayStateFunctionalizeOptions& left, DisplayStateFunctionalizeOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayStateFunctionalizeOptions const value) noexcept
    {
        return static_cast<DisplayStateFunctionalizeOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayStateFunctionalizeOptions const left, DisplayStateFunctionalizeOptions const right) noexcept
    {
        return static_cast<DisplayStateFunctionalizeOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayStateFunctionalizeOptions& left, DisplayStateFunctionalizeOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto DisplayAdapter::FromId(winrt::Windows::Graphics::DisplayAdapterId const& id)
    {
        return impl::call_factory<DisplayAdapter, IDisplayAdapterStatics>([&](IDisplayAdapterStatics const& f) { return f.FromId(id); });
    }
    inline auto DisplayManager::Create(winrt::Windows::Devices::Display::Core::DisplayManagerOptions const& options)
    {
        return impl::call_factory<DisplayManager, IDisplayManagerStatics>([&](IDisplayManagerStatics const& f) { return f.Create(options); });
    }
    inline DisplayPrimaryDescription::DisplayPrimaryDescription(uint32_t width, uint32_t height, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, winrt::Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) :
        DisplayPrimaryDescription(impl::call_factory<DisplayPrimaryDescription, IDisplayPrimaryDescriptionFactory>([&](IDisplayPrimaryDescriptionFactory const& f) { return f.CreateInstance(width, height, pixelFormat, colorSpace, isStereo, multisampleDescription); }))
    {
    }
    inline auto DisplayPrimaryDescription::CreateWithProperties(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::guid, winrt::Windows::Foundation::IInspectable>> const& extraProperties, uint32_t width, uint32_t height, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, winrt::Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, winrt::Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription)
    {
        return impl::call_factory<DisplayPrimaryDescription, IDisplayPrimaryDescriptionStatics>([&](IDisplayPrimaryDescriptionStatics const& f) { return f.CreateWithProperties(extraProperties, width, height, pixelFormat, colorSpace, isStereo, multisampleDescription); });
    }
    inline DisplayWireFormat::DisplayWireFormat(winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) :
        DisplayWireFormat(impl::call_factory<DisplayWireFormat, IDisplayWireFormatFactory>([&](IDisplayWireFormatFactory const& f) { return f.CreateInstance(pixelEncoding, bitsPerChannel, colorSpace, eotf, hdrMetadata); }))
    {
    }
    inline auto DisplayWireFormat::CreateWithProperties(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<winrt::guid, winrt::Windows::Foundation::IInspectable>> const& extraProperties, winrt::Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, winrt::Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, winrt::Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, winrt::Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata)
    {
        return impl::call_factory<DisplayWireFormat, IDisplayWireFormatStatics>([&](IDisplayWireFormatStatics const& f) { return f.CreateWithProperties(extraProperties, pixelEncoding, bitsPerChannel, colorSpace, eotf, hdrMetadata); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayAdapter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayAdapterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayDevice2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayFence> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayModeInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayModeInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPath2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayScanout> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplaySource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplaySource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplaySurface> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTarget> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTask> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTask2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTaskPool> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTaskPool2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTaskResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayWireFormat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayWireFormatFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayWireFormatStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayAdapter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayFence> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayModeInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayPath> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayScanout> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplaySource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayStateOperationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplaySurface> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTarget> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTask> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTaskPool> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTaskResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayWireFormat> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
