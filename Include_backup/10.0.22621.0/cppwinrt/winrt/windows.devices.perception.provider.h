// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Perception_Provider_H
#define WINRT_Windows_Devices_Perception_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Perception.h"
#include "winrt/impl/Windows.Devices.Perception.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Devices.Perception.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>::Color() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics)->get_Color(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>::Depth() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics)->get_Depth(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>::Infrared() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics)->get_Infrared(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Devices_Perception_Provider_IPerceptionControlGroup<D>::FrameProviderIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup)->get_FrameProviderIds(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup) consume_Windows_Devices_Perception_Provider_IPerceptionControlGroupFactory<D>::Create(param::iterable<hstring> const& ids) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory)->Create(*(void**)(&ids), &result));
        return winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>::TargetId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation)->get_TargetId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>::Orientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation)->get_Orientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation) consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationFactory<D>::Create(param::hstring const& targetId, winrt::Windows::Foundation::Numerics::float3 const& position, winrt::Windows::Foundation::Numerics::quaternion const& orientation) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory)->Create(*(void**)(&targetId), impl::bind_in(position), impl::bind_in(orientation), &result));
        return winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>) consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroup<D>::RelativeLocations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup)->get_RelativeLocations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup) consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroupFactory<D>::Create(param::iterable<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> const& relativeLocations) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory)->Create(*(void**)(&relativeLocations), &result));
        return winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroup<D>::FrameProviderIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup)->get_FrameProviderIds(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup) consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroupFactory<D>::Create(param::iterable<hstring> const& ids, winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const& startHandler, winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const& stopHandler) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory)->Create(*(void**)(&ids), *(void**)(&startHandler), *(void**)(&stopHandler), &result));
        return winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::RelativeTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrame)->get_RelativeTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::RelativeTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrame)->put_RelativeTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrame)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IMemoryBuffer) consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::FrameData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrame)->get_FrameData(&value));
        return winrt::Windows::Foundation::IMemoryBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::FrameProviderInfo() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->get_FrameProviderInfo(&result));
        return winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Available() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->get_Available(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::SetProperty(winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->SetProperty(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DeviceKind() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_DeviceKind(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DeviceKind(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_DeviceKind(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::FrameKind() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_FrameKind(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::FrameKind(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_FrameKind(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Hidden() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_Hidden(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Hidden(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_Hidden(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManager<D>::GetFrameProvider(winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager)->GetFrameProvider(*(void**)(&frameProviderInfo), &result));
        return winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterFrameProviderInfo(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterFrameProviderInfo(*(void**)(&manager), *(void**)(&frameProviderInfo)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterFrameProviderInfo(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterFrameProviderInfo(*(void**)(&manager), *(void**)(&frameProviderInfo)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterFaceAuthenticationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterFaceAuthenticationGroup(*(void**)(&manager), *(void**)(&faceAuthenticationGroup)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterFaceAuthenticationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterFaceAuthenticationGroup(*(void**)(&manager), *(void**)(&faceAuthenticationGroup)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterControlGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterControlGroup(*(void**)(&manager), *(void**)(&controlGroup)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterControlGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterControlGroup(*(void**)(&manager), *(void**)(&controlGroup)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterCorrelationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterCorrelationGroup(*(void**)(&manager), *(void**)(&correlationGroup)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterCorrelationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterCorrelationGroup(*(void**)(&manager), *(void**)(&correlationGroup)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UpdateAvailabilityForProvider(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, bool available) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UpdateAvailabilityForProvider(*(void**)(&provider), available));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::PublishFrameForProvider(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, winrt::Windows::Devices::Perception::Provider::PerceptionFrame const& frame) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->PublishFrameForProvider(*(void**)(&provider), *(void**)(&frame)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->get_Value(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus) consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Status() const
    {
        winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Status(winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFrame) consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocator<D>::AllocateFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator)->AllocateFrame(&value));
        return winrt::Windows::Devices::Perception::Provider::PerceptionFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionFrame) consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocator<D>::CopyFromVideoFrame(winrt::Windows::Media::VideoFrame const& frame) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator)->CopyFromVideoFrame(*(void**)(&frame), &value));
        return winrt::Windows::Devices::Perception::Provider::PerceptionFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator) consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocatorFactory<D>::Create(uint32_t maxOutstandingFrameCountForWrite, winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, winrt::Windows::Foundation::Size const& resolution, winrt::Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory)->Create(maxOutstandingFrameCountForWrite, static_cast<int32_t>(format), impl::bind_in(resolution), static_cast<int32_t>(alpha), &result));
        return winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator{ result, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler, H> final : implements_delegate<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, bool* result) noexcept final try
        {
            *result = detach_from<bool>((*this)(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&sender)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler, H> final : implements_delegate<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&sender));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>
    {
        int32_t __stdcall get_Color(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Depth(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Depth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Infrared(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Infrared());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup>
    {
        int32_t __stdcall get_FrameProviderIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FrameProviderIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>
    {
        int32_t __stdcall Create(void* ids, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&ids)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation>
    {
        int32_t __stdcall get_TargetId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>
    {
        int32_t __stdcall Create(void* targetId, winrt::Windows::Foundation::Numerics::float3 position, winrt::Windows::Foundation::Numerics::quaternion orientation, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>(this->shim().Create(*reinterpret_cast<hstring const*>(&targetId), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&orientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup>
    {
        int32_t __stdcall get_RelativeLocations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation>>(this->shim().RelativeLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>
    {
        int32_t __stdcall Create(void* relativeLocations, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> const*>(&relativeLocations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup>
    {
        int32_t __stdcall get_FrameProviderIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FrameProviderIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>
    {
        int32_t __stdcall Create(void* ids, void* startHandler, void* stopHandler, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&ids), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const*>(&startHandler), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const*>(&stopHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrame> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrame>
    {
        int32_t __stdcall get_RelativeTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelativeTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelativeTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IMemoryBuffer>(this->shim().FrameData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider>
    {
        int32_t __stdcall get_FrameProviderInfo(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo>(this->shim().FrameProviderInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Available(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Available());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
        int32_t __stdcall SetProperty(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetProperty(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo>
    {
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
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceKind(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeviceKind(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeviceKind(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameKind(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FrameKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FrameKind(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameKind(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hidden(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Hidden());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Hidden(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hidden(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager>
    {
        int32_t __stdcall GetFrameProvider(void* frameProviderInfo, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider>(this->shim().GetFrameProvider(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const*>(&frameProviderInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>
    {
        int32_t __stdcall RegisterFrameProviderInfo(void* manager, void* frameProviderInfo) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterFrameProviderInfo(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const*>(&frameProviderInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterFrameProviderInfo(void* manager, void* frameProviderInfo) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterFrameProviderInfo(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const*>(&frameProviderInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterFaceAuthenticationGroup(void* manager, void* faceAuthenticationGroup) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterFaceAuthenticationGroup(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&faceAuthenticationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterFaceAuthenticationGroup(void* manager, void* faceAuthenticationGroup) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterFaceAuthenticationGroup(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&faceAuthenticationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterControlGroup(void* manager, void* controlGroup) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterControlGroup(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const*>(&controlGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterControlGroup(void* manager, void* controlGroup) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterControlGroup(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const*>(&controlGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterCorrelationGroup(void* manager, void* correlationGroup) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterCorrelationGroup(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const*>(&correlationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterCorrelationGroup(void* manager, void* correlationGroup) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterCorrelationGroup(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const*>(&correlationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateAvailabilityForProvider(void* provider, bool available) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateAvailabilityForProvider(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const*>(&provider), available);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PublishFrameForProvider(void* provider, void* frame) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PublishFrameForProvider(*reinterpret_cast<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const*>(&provider), *reinterpret_cast<winrt::Windows::Devices::Perception::Provider::PerceptionFrame const*>(&frame));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus const*>(&value));
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
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator>
    {
        int32_t __stdcall AllocateFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionFrame>(this->shim().AllocateFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyFromVideoFrame(void* frame, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionFrame>(this->shim().CopyFromVideoFrame(*reinterpret_cast<winrt::Windows::Media::VideoFrame const*>(&frame)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory> : produce_base<D, winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>
    {
        int32_t __stdcall Create(uint32_t maxOutstandingFrameCountForWrite, int32_t format, winrt::Windows::Foundation::Size resolution, int32_t alpha, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator>(this->shim().Create(maxOutstandingFrameCountForWrite, *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&resolution), *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider
{
    inline auto KnownPerceptionFrameKind::Color()
    {
        return impl::call_factory_cast<hstring(*)(IKnownPerceptionFrameKindStatics const&), KnownPerceptionFrameKind, IKnownPerceptionFrameKindStatics>([](IKnownPerceptionFrameKindStatics const& f) { return f.Color(); });
    }
    inline auto KnownPerceptionFrameKind::Depth()
    {
        return impl::call_factory_cast<hstring(*)(IKnownPerceptionFrameKindStatics const&), KnownPerceptionFrameKind, IKnownPerceptionFrameKindStatics>([](IKnownPerceptionFrameKindStatics const& f) { return f.Depth(); });
    }
    inline auto KnownPerceptionFrameKind::Infrared()
    {
        return impl::call_factory_cast<hstring(*)(IKnownPerceptionFrameKindStatics const&), KnownPerceptionFrameKind, IKnownPerceptionFrameKindStatics>([](IKnownPerceptionFrameKindStatics const& f) { return f.Infrared(); });
    }
    inline PerceptionControlGroup::PerceptionControlGroup(param::iterable<hstring> const& ids) :
        PerceptionControlGroup(impl::call_factory<PerceptionControlGroup, IPerceptionControlGroupFactory>([&](IPerceptionControlGroupFactory const& f) { return f.Create(ids); }))
    {
    }
    inline PerceptionCorrelation::PerceptionCorrelation(param::hstring const& targetId, winrt::Windows::Foundation::Numerics::float3 const& position, winrt::Windows::Foundation::Numerics::quaternion const& orientation) :
        PerceptionCorrelation(impl::call_factory<PerceptionCorrelation, IPerceptionCorrelationFactory>([&](IPerceptionCorrelationFactory const& f) { return f.Create(targetId, position, orientation); }))
    {
    }
    inline PerceptionCorrelationGroup::PerceptionCorrelationGroup(param::iterable<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> const& relativeLocations) :
        PerceptionCorrelationGroup(impl::call_factory<PerceptionCorrelationGroup, IPerceptionCorrelationGroupFactory>([&](IPerceptionCorrelationGroupFactory const& f) { return f.Create(relativeLocations); }))
    {
    }
    inline PerceptionFaceAuthenticationGroup::PerceptionFaceAuthenticationGroup(param::iterable<hstring> const& ids, winrt::Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const& startHandler, winrt::Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const& stopHandler) :
        PerceptionFaceAuthenticationGroup(impl::call_factory<PerceptionFaceAuthenticationGroup, IPerceptionFaceAuthenticationGroupFactory>([&](IPerceptionFaceAuthenticationGroupFactory const& f) { return f.Create(ids, startHandler, stopHandler); }))
    {
    }
    inline PerceptionFrameProviderInfo::PerceptionFrameProviderInfo() :
        PerceptionFrameProviderInfo(impl::call_factory_cast<PerceptionFrameProviderInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), PerceptionFrameProviderInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PerceptionFrameProviderInfo>(); }))
    {
    }
    inline auto PerceptionFrameProviderManagerService::RegisterFrameProviderInfo(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.RegisterFrameProviderInfo(manager, frameProviderInfo); });
    }
    inline auto PerceptionFrameProviderManagerService::UnregisterFrameProviderInfo(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.UnregisterFrameProviderInfo(manager, frameProviderInfo); });
    }
    inline auto PerceptionFrameProviderManagerService::RegisterFaceAuthenticationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.RegisterFaceAuthenticationGroup(manager, faceAuthenticationGroup); });
    }
    inline auto PerceptionFrameProviderManagerService::UnregisterFaceAuthenticationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.UnregisterFaceAuthenticationGroup(manager, faceAuthenticationGroup); });
    }
    inline auto PerceptionFrameProviderManagerService::RegisterControlGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.RegisterControlGroup(manager, controlGroup); });
    }
    inline auto PerceptionFrameProviderManagerService::UnregisterControlGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.UnregisterControlGroup(manager, controlGroup); });
    }
    inline auto PerceptionFrameProviderManagerService::RegisterCorrelationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.RegisterCorrelationGroup(manager, correlationGroup); });
    }
    inline auto PerceptionFrameProviderManagerService::UnregisterCorrelationGroup(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.UnregisterCorrelationGroup(manager, correlationGroup); });
    }
    inline auto PerceptionFrameProviderManagerService::UpdateAvailabilityForProvider(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, bool available)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.UpdateAvailabilityForProvider(provider, available); });
    }
    inline auto PerceptionFrameProviderManagerService::PublishFrameForProvider(winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, winrt::Windows::Devices::Perception::Provider::PerceptionFrame const& frame)
    {
        impl::call_factory<PerceptionFrameProviderManagerService, IPerceptionFrameProviderManagerServiceStatics>([&](IPerceptionFrameProviderManagerServiceStatics const& f) { return f.PublishFrameForProvider(provider, frame); });
    }
    inline PerceptionVideoFrameAllocator::PerceptionVideoFrameAllocator(uint32_t maxOutstandingFrameCountForWrite, winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, winrt::Windows::Foundation::Size const& resolution, winrt::Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) :
        PerceptionVideoFrameAllocator(impl::call_factory<PerceptionVideoFrameAllocator, IPerceptionVideoFrameAllocatorFactory>([&](IPerceptionVideoFrameAllocatorFactory const& f) { return f.Create(maxOutstandingFrameCountForWrite, format, resolution, alpha); }))
    {
    }
    template <typename L> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(L handler) :
        PerceptionStartFaceAuthenticationHandler(impl::make_delegate<PerceptionStartFaceAuthenticationHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(F* handler) :
        PerceptionStartFaceAuthenticationHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(O* object, M method) :
        PerceptionStartFaceAuthenticationHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(com_ptr<O>&& object, M method) :
        PerceptionStartFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(weak_ref<O>&& object, M method) :
        PerceptionStartFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto PerceptionStartFaceAuthenticationHandler::operator()(winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& sender) const
    {
        bool result{};
        check_hresult((*(impl::abi_t<PerceptionStartFaceAuthenticationHandler>**)this)->Invoke(*(void**)(&sender), &result));
        return result;
    }
    template <typename L> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(L handler) :
        PerceptionStopFaceAuthenticationHandler(impl::make_delegate<PerceptionStopFaceAuthenticationHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(F* handler) :
        PerceptionStopFaceAuthenticationHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(O* object, M method) :
        PerceptionStopFaceAuthenticationHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(com_ptr<O>&& object, M method) :
        PerceptionStopFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(weak_ref<O>&& object, M method) :
        PerceptionStopFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto PerceptionStopFaceAuthenticationHandler::operator()(winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& sender) const
    {
        check_hresult((*(impl::abi_t<PerceptionStopFaceAuthenticationHandler>**)this)->Invoke(*(void**)(&sender)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::KnownPerceptionFrameKind> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderManagerService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
