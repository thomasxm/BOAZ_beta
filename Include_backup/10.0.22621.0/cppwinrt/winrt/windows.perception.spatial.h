// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Perception_Spatial_H
#define WINRT_Windows_Perception_Spatial_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Perception.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Perception.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_ISpatialAnchor<D>::CoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchor)->get_CoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchor)->get_RawCoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialAnchor, winrt::Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchor)->add_RawCoordinateSystemAdjusted(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted_revoker consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialAnchor, winrt::Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RawCoordinateSystemAdjusted_revoker>(this, RawCoordinateSystemAdjusted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchor)->remove_RawCoordinateSystemAdjusted(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Perception_Spatial_ISpatialAnchor2<D>::RemovedByUser() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchor2)->get_RemovedByUser(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>::IsMinimallySufficient() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency)->get_IsMinimallySufficient(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>::SufficiencyLevel() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency)->get_SufficiencyLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>::RecommendedSufficiencyLevel() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency)->get_RecommendedSufficiencyLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorExportSufficiency>) consume_Windows_Perception_Spatial_ISpatialAnchorExporter<D>::GetAnchorExportSufficiencyAsync(winrt::Windows::Perception::Spatial::SpatialAnchor const& anchor, winrt::Windows::Perception::Spatial::SpatialAnchorExportPurpose const& purpose) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExporter)->GetAnchorExportSufficiencyAsync(*(void**)(&anchor), static_cast<int32_t>(purpose), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorExportSufficiency>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Perception_Spatial_ISpatialAnchorExporter<D>::TryExportAnchorAsync(winrt::Windows::Perception::Spatial::SpatialAnchor const& anchor, winrt::Windows::Perception::Spatial::SpatialAnchorExportPurpose const& purpose, winrt::Windows::Storage::Streams::IOutputStream const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExporter)->TryExportAnchorAsync(*(void**)(&anchor), static_cast<int32_t>(purpose), *(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialAnchorExporter) consume_Windows_Perception_Spatial_ISpatialAnchorExporterStatics<D>::GetDefault() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics)->GetDefault(&value));
        return winrt::Windows::Perception::Spatial::SpatialAnchorExporter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>) consume_Windows_Perception_Spatial_ISpatialAnchorExporterStatics<D>::RequestAccessAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics)->RequestAccessAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorStore>) consume_Windows_Perception_Spatial_ISpatialAnchorManagerStatics<D>::RequestStoreAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorManagerStatics)->RequestStoreAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorStore>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float4x4) consume_Windows_Perception_Spatial_ISpatialAnchorRawCoordinateSystemAdjustedEventArgs<D>::OldRawCoordinateSystemToNewRawCoordinateSystemTransform() const
    {
        winrt::Windows::Foundation::Numerics::float4x4 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs)->get_OldRawCoordinateSystemToNewRawCoordinateSystemTransform(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialAnchor) consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>::TryCreateRelativeTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStatics)->TryCreateRelativeTo(*(void**)(&coordinateSystem), &value));
        return winrt::Windows::Perception::Spatial::SpatialAnchor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialAnchor) consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>::TryCreateRelativeTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& position) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStatics)->TryCreateWithPositionRelativeTo(*(void**)(&coordinateSystem), impl::bind_in(position), &value));
        return winrt::Windows::Perception::Spatial::SpatialAnchor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialAnchor) consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>::TryCreateRelativeTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& position, winrt::Windows::Foundation::Numerics::quaternion const& orientation) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStatics)->TryCreateWithPositionAndOrientationRelativeTo(*(void**)(&coordinateSystem), impl::bind_in(position), impl::bind_in(orientation), &value));
        return winrt::Windows::Perception::Spatial::SpatialAnchor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>) consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::GetAllSavedAnchors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStore)->GetAllSavedAnchors(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::TrySave(param::hstring const& id, winrt::Windows::Perception::Spatial::SpatialAnchor const& anchor) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStore)->TrySave(*(void**)(&id), *(void**)(&anchor), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::Remove(param::hstring const& id) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStore)->Remove(*(void**)(&id)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorStore)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>>) consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>::TryImportAnchorsAsync(winrt::Windows::Storage::Streams::IInputStream const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics)->TryImportAnchorsAsync(*(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>::TryExportAnchorsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>> const& anchors, winrt::Windows::Storage::Streams::IOutputStream const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics)->TryExportAnchorsAsync(*(void**)(&anchors), *(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>) consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>::RequestAccessAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics)->RequestAccessAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialBoundingVolume) consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromBox(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingBox const& box) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromBox(*(void**)(&coordinateSystem), impl::bind_in(box), &value));
        return winrt::Windows::Perception::Spatial::SpatialBoundingVolume{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialBoundingVolume) consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromOrientedBox(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingOrientedBox const& box) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromOrientedBox(*(void**)(&coordinateSystem), impl::bind_in(box), &value));
        return winrt::Windows::Perception::Spatial::SpatialBoundingVolume{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialBoundingVolume) consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromSphere(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingSphere const& sphere) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromSphere(*(void**)(&coordinateSystem), impl::bind_in(sphere), &value));
        return winrt::Windows::Perception::Spatial::SpatialBoundingVolume{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialBoundingVolume) consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromFrustum(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingFrustum const& frustum) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromFrustum(*(void**)(&coordinateSystem), impl::bind_in(frustum), &value));
        return winrt::Windows::Perception::Spatial::SpatialBoundingVolume{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float4x4>) consume_Windows_Perception_Spatial_ISpatialCoordinateSystem<D>::TryGetTransformTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& target) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialCoordinateSystem)->TryGetTransformTo(*(void**)(&target), &value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float4x4>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Perception_Spatial_ISpatialEntity<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntity)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialAnchor) consume_Windows_Perception_Spatial_ISpatialEntity<D>::Anchor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntity)->get_Anchor(&value));
        return winrt::Windows::Perception::Spatial::SpatialAnchor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Perception_Spatial_ISpatialEntity<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntity)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntity) consume_Windows_Perception_Spatial_ISpatialEntityAddedEventArgs<D>::Entity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityAddedEventArgs)->get_Entity(&value));
        return winrt::Windows::Perception::Spatial::SpatialEntity{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntity) consume_Windows_Perception_Spatial_ISpatialEntityFactory<D>::CreateWithSpatialAnchor(winrt::Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityFactory)->CreateWithSpatialAnchor(*(void**)(&spatialAnchor), &value));
        return winrt::Windows::Perception::Spatial::SpatialEntity{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntity) consume_Windows_Perception_Spatial_ISpatialEntityFactory<D>::CreateWithSpatialAnchorAndProperties(winrt::Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor, winrt::Windows::Foundation::Collections::ValueSet const& propertySet) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityFactory)->CreateWithSpatialAnchorAndProperties(*(void**)(&spatialAnchor), *(void**)(&propertySet), &value));
        return winrt::Windows::Perception::Spatial::SpatialEntity{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntity) consume_Windows_Perception_Spatial_ISpatialEntityRemovedEventArgs<D>::Entity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs)->get_Entity(&value));
        return winrt::Windows::Perception::Spatial::SpatialEntity{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Perception_Spatial_ISpatialEntityStore<D>::SaveAsync(winrt::Windows::Perception::Spatial::SpatialEntity const& entity) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityStore)->SaveAsync(*(void**)(&entity), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Perception_Spatial_ISpatialEntityStore<D>::RemoveAsync(winrt::Windows::Perception::Spatial::SpatialEntity const& entity) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityStore)->RemoveAsync(*(void**)(&entity), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntityWatcher) consume_Windows_Perception_Spatial_ISpatialEntityStore<D>::CreateEntityWatcher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityStore)->CreateEntityWatcher(&value));
        return winrt::Windows::Perception::Spatial::SpatialEntityWatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Perception_Spatial_ISpatialEntityStoreStatics<D>::IsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics)->get_IsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntityStore) consume_Windows_Perception_Spatial_ISpatialEntityStoreStatics<D>::TryGet(winrt::Windows::System::RemoteSystems::RemoteSystemSession const& session) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics)->TryGetForRemoteSystemSession(*(void**)(&session), &value));
        return winrt::Windows::Perception::Spatial::SpatialEntityStore{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntity) consume_Windows_Perception_Spatial_ISpatialEntityUpdatedEventArgs<D>::Entity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs)->get_Entity(&value));
        return winrt::Windows::Perception::Spatial::SpatialEntity{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialEntityWatcherStatus) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Status() const
    {
        winrt::Windows::Perception::Spatial::SpatialEntityWatcherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialEntityWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Perception_Spatial_ISpatialLocation<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Perception_Spatial_ISpatialLocation<D>::Orientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation)->get_Orientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteLinearVelocity() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteLinearVelocity(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteLinearAcceleration() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteLinearAcceleration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteAngularVelocity() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteAngularVelocity(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteAngularAcceleration() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteAngularAcceleration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Perception_Spatial_ISpatialLocation2<D>::AbsoluteAngularVelocityAxisAngle() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation2)->get_AbsoluteAngularVelocityAxisAngle(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Perception_Spatial_ISpatialLocation2<D>::AbsoluteAngularAccelerationAxisAngle() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocation2)->get_AbsoluteAngularAccelerationAxisAngle(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocatability) consume_Windows_Perception_Spatial_ISpatialLocator<D>::Locatability() const
    {
        winrt::Windows::Perception::Spatial::SpatialLocatability value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->get_Locatability(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialLocator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->add_LocatabilityChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged_revoker consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialLocator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, LocatabilityChanged_revoker>(this, LocatabilityChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->remove_LocatabilityChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialLocator, winrt::Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->add_PositionalTrackingDeactivating(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating_revoker consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialLocator, winrt::Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PositionalTrackingDeactivating_revoker>(this, PositionalTrackingDeactivating(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->remove_PositionalTrackingDeactivating(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocation) consume_Windows_Perception_Spatial_ISpatialLocator<D>::TryLocateAtTimestamp(winrt::Windows::Perception::PerceptionTimestamp const& timestamp, winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->TryLocateAtTimestamp(*(void**)(&timestamp), *(void**)(&coordinateSystem), &value));
        return winrt::Windows::Perception::Spatial::SpatialLocation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeading(&value));
        return winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading(winrt::Windows::Foundation::Numerics::float3 const& relativePosition) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeadingWithPosition(impl::bind_in(relativePosition), &value));
        return winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading(winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientation(impl::bind_in(relativePosition), impl::bind_in(relativeOrientation), &value));
        return winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading(winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation, double relativeHeadingInRadians) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientationAndRelativeHeading(impl::bind_in(relativePosition), impl::bind_in(relativeOrientation), relativeHeadingInRadians, &value));
        return winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocation(&value));
        return winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation(winrt::Windows::Foundation::Numerics::float3 const& relativePosition) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocationWithPosition(impl::bind_in(relativePosition), &value));
        return winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation(winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientation(impl::bind_in(relativePosition), impl::bind_in(relativeOrientation), &value));
        return winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference) consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation(winrt::Windows::Foundation::Numerics::float3 const& relativePosition, winrt::Windows::Foundation::Numerics::quaternion const& relativeOrientation, double relativeHeadingInRadians) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientationAndRelativeHeading(impl::bind_in(relativePosition), impl::bind_in(relativeOrientation), relativeHeadingInRadians, &value));
        return winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativePosition() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->get_RelativePosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativePosition(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->put_RelativePosition(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativeOrientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->get_RelativeOrientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativeOrientation(winrt::Windows::Foundation::Numerics::quaternion const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->put_RelativeOrientation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::AdjustHeading(double headingOffsetInRadians) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->AdjustHeading(headingOffsetInRadians));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::GetStationaryCoordinateSystemAtTimestamp(winrt::Windows::Perception::PerceptionTimestamp const& timestamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->GetStationaryCoordinateSystemAtTimestamp(*(void**)(&timestamp), &value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::TryGetRelativeHeadingAtTimestamp(winrt::Windows::Perception::PerceptionTimestamp const& timestamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->TryGetRelativeHeadingAtTimestamp(*(void**)(&timestamp), &value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Perception_Spatial_ISpatialLocatorPositionalTrackingDeactivatingEventArgs<D>::Canceled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs)->get_Canceled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialLocatorPositionalTrackingDeactivatingEventArgs<D>::Canceled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs)->put_Canceled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLocator) consume_Windows_Perception_Spatial_ISpatialLocatorStatics<D>::GetDefault() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialLocatorStatics)->GetDefault(&value));
        return winrt::Windows::Perception::Spatial::SpatialLocator{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::CoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference)->get_CoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialMovementRange) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::MovementRange() const
    {
        winrt::Windows::Perception::Spatial::SpatialMovementRange value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference)->get_MovementRange(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialLookDirectionRange) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::LookDirectionRange() const
    {
        winrt::Windows::Perception::Spatial::SpatialLookDirectionRange value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference)->get_LookDirectionRange(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::GetCoordinateSystemAtCurrentLocation(winrt::Windows::Perception::Spatial::SpatialLocator const& locator) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference)->GetCoordinateSystemAtCurrentLocation(*(void**)(&locator), &result));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::TryGetMovementBounds(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        uint32_t value_impl_size{};
        winrt::Windows::Foundation::Numerics::float3* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference)->TryGetMovementBounds(*(void**)(&coordinateSystem), &value_impl_size, &value));
        return com_array<winrt::Windows::Foundation::Numerics::float3>{ value, value_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->get_Current(&value));
        return winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->add_CurrentChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged_revoker consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CurrentChanged_revoker>(this, CurrentChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->remove_CurrentChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference>) consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::RequestNewStageAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->RequestNewStageAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Perception_Spatial_ISpatialStationaryFrameOfReference<D>::CoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Perception::Spatial::ISpatialStationaryFrameOfReference)->get_CoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchor> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchor>
    {
        int32_t __stdcall get_CoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawCoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().RawCoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RawCoordinateSystemAdjusted(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().RawCoordinateSystemAdjusted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialAnchor, winrt::Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RawCoordinateSystemAdjusted(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RawCoordinateSystemAdjusted(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchor2> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchor2>
    {
        int32_t __stdcall get_RemovedByUser(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().RemovedByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency>
    {
        int32_t __stdcall get_IsMinimallySufficient(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMinimallySufficient());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SufficiencyLevel(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SufficiencyLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecommendedSufficiencyLevel(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RecommendedSufficiencyLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorExporter> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorExporter>
    {
        int32_t __stdcall GetAnchorExportSufficiencyAsync(void* anchor, int32_t purpose, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorExportSufficiency>>(this->shim().GetAnchorExportSufficiencyAsync(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchor const*>(&anchor), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchorExportPurpose const*>(&purpose)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryExportAnchorAsync(void* anchor, int32_t purpose, void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryExportAnchorAsync(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchor const*>(&anchor), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchorExportPurpose const*>(&purpose), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics>
    {
        int32_t __stdcall GetDefault(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialAnchorExporter>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorManagerStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorManagerStatics>
    {
        int32_t __stdcall RequestStoreAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>
    {
        int32_t __stdcall get_OldRawCoordinateSystemToNewRawCoordinateSystemTransform(winrt::Windows::Foundation::Numerics::float4x4* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float4x4>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float4x4>(this->shim().OldRawCoordinateSystemToNewRawCoordinateSystemTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorStatics>
    {
        int32_t __stdcall TryCreateRelativeTo(void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialAnchor>(this->shim().TryCreateRelativeTo(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateWithPositionRelativeTo(void* coordinateSystem, winrt::Windows::Foundation::Numerics::float3 position, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialAnchor>(this->shim().TryCreateRelativeTo(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateWithPositionAndOrientationRelativeTo(void* coordinateSystem, winrt::Windows::Foundation::Numerics::float3 position, winrt::Windows::Foundation::Numerics::quaternion orientation, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialAnchor>(this->shim().TryCreateRelativeTo(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&orientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorStore> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorStore>
    {
        int32_t __stdcall GetAllSavedAnchors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>>(this->shim().GetAllSavedAnchors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySave(void* id, void* anchor, bool* succeeded) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TrySave(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchor const*>(&anchor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Remove(void* id) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clear() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>
    {
        int32_t __stdcall TryImportAnchorsAsync(void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>>>(this->shim().TryImportAnchorsAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryExportAnchorsAsync(void* anchors, void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryExportAnchorsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>> const*>(&anchors), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialBoundingVolume> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialBoundingVolume>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>
    {
        int32_t __stdcall FromBox(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingBox box, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromBox(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialBoundingBox const*>(&box)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromOrientedBox(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingOrientedBox box, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromOrientedBox(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialBoundingOrientedBox const*>(&box)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromSphere(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingSphere sphere, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromSphere(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialBoundingSphere const*>(&sphere)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromFrustum(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingFrustum frustum, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromFrustum(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialBoundingFrustum const*>(&frustum)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialCoordinateSystem> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialCoordinateSystem>
    {
        int32_t __stdcall TryGetTransformTo(void* target, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float4x4>>(this->shim().TryGetTransformTo(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntity> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntity>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Anchor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialAnchor>(this->shim().Anchor());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityAddedEventArgs> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityAddedEventArgs>
    {
        int32_t __stdcall get_Entity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntity>(this->shim().Entity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityFactory> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityFactory>
    {
        int32_t __stdcall CreateWithSpatialAnchor(void* spatialAnchor, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntity>(this->shim().CreateWithSpatialAnchor(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchor const*>(&spatialAnchor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithSpatialAnchorAndProperties(void* spatialAnchor, void* propertySet, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntity>(this->shim().CreateWithSpatialAnchorAndProperties(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialAnchor const*>(&spatialAnchor), *reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&propertySet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs>
    {
        int32_t __stdcall get_Entity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntity>(this->shim().Entity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityStore> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityStore>
    {
        int32_t __stdcall SaveAsync(void* entity, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveAsync(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialEntity const*>(&entity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveAsync(void* entity, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RemoveAsync(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialEntity const*>(&entity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateEntityWatcher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntityWatcher>(this->shim().CreateEntityWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics>
    {
        int32_t __stdcall get_IsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetForRemoteSystemSession(void* session, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntityStore>(this->shim().TryGet(*reinterpret_cast<winrt::Windows::System::RemoteSystems::RemoteSystemSession const*>(&session)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs>
    {
        int32_t __stdcall get_Entity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntity>(this->shim().Entity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialEntityWatcher> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialEntityWatcher>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialEntityWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialEntityWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
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
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialLocation> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialLocation>
    {
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
        int32_t __stdcall get_AbsoluteLinearVelocity(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().AbsoluteLinearVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AbsoluteLinearAcceleration(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().AbsoluteLinearAcceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AbsoluteAngularVelocity(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().AbsoluteAngularVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AbsoluteAngularAcceleration(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().AbsoluteAngularAcceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialLocation2> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialLocation2>
    {
        int32_t __stdcall get_AbsoluteAngularVelocityAxisAngle(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().AbsoluteAngularVelocityAxisAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AbsoluteAngularAccelerationAxisAngle(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().AbsoluteAngularAccelerationAxisAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialLocator> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialLocator>
    {
        int32_t __stdcall get_Locatability(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocatability>(this->shim().Locatability());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_LocatabilityChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().LocatabilityChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialLocator, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LocatabilityChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LocatabilityChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PositionalTrackingDeactivating(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PositionalTrackingDeactivating(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Perception::Spatial::SpatialLocator, winrt::Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PositionalTrackingDeactivating(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionalTrackingDeactivating(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall TryLocateAtTimestamp(void* timestamp, void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocation>(this->shim().TryLocateAtTimestamp(*reinterpret_cast<winrt::Windows::Perception::PerceptionTimestamp const*>(&timestamp), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAttachedFrameOfReferenceAtCurrentHeading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAttachedFrameOfReferenceAtCurrentHeadingWithPosition(winrt::Windows::Foundation::Numerics::float3 relativePosition, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientation(winrt::Windows::Foundation::Numerics::float3 relativePosition, winrt::Windows::Foundation::Numerics::quaternion relativeOrientation, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientationAndRelativeHeading(winrt::Windows::Foundation::Numerics::float3 relativePosition, winrt::Windows::Foundation::Numerics::quaternion relativeOrientation, double relativeHeadingInRadians, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation), relativeHeadingInRadians));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStationaryFrameOfReferenceAtCurrentLocation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStationaryFrameOfReferenceAtCurrentLocationWithPosition(winrt::Windows::Foundation::Numerics::float3 relativePosition, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientation(winrt::Windows::Foundation::Numerics::float3 relativePosition, winrt::Windows::Foundation::Numerics::quaternion relativeOrientation, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientationAndRelativeHeading(winrt::Windows::Foundation::Numerics::float3 relativePosition, winrt::Windows::Foundation::Numerics::quaternion relativeOrientation, double relativeHeadingInRadians, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation), relativeHeadingInRadians));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference>
    {
        int32_t __stdcall get_RelativePosition(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().RelativePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelativePosition(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelativePosition(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelativeOrientation(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().RelativeOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelativeOrientation(winrt::Windows::Foundation::Numerics::quaternion value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelativeOrientation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AdjustHeading(double headingOffsetInRadians) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AdjustHeading(headingOffsetInRadians);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStationaryCoordinateSystemAtTimestamp(void* timestamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().GetStationaryCoordinateSystemAtTimestamp(*reinterpret_cast<winrt::Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetRelativeHeadingAtTimestamp(void* timestamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().TryGetRelativeHeadingAtTimestamp(*reinterpret_cast<winrt::Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs>
    {
        int32_t __stdcall get_Canceled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Canceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Canceled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Canceled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialLocatorStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialLocatorStatics>
    {
        int32_t __stdcall GetDefault(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLocator>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference>
    {
        int32_t __stdcall get_CoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MovementRange(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialMovementRange>(this->shim().MovementRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LookDirectionRange(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialLookDirectionRange>(this->shim().LookDirectionRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCoordinateSystemAtCurrentLocation(void* locator, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().GetCoordinateSystemAtCurrentLocation(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialLocator const*>(&locator)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetMovementBounds(void* coordinateSystem, uint32_t* __valueSize, winrt::Windows::Foundation::Numerics::float3** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            std::tie(*__valueSize, *value) = detach_abi(this->shim().TryGetMovementBounds(*reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CurrentChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().CurrentChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall RequestNewStageAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference>>(this->shim().RequestNewStageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Perception::Spatial::ISpatialStationaryFrameOfReference> : produce_base<D, winrt::Windows::Perception::Spatial::ISpatialStationaryFrameOfReference>
    {
        int32_t __stdcall get_CoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Perception::Spatial
{
    inline auto SpatialAnchor::TryCreateRelativeTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem)
    {
        return impl::call_factory<SpatialAnchor, ISpatialAnchorStatics>([&](ISpatialAnchorStatics const& f) { return f.TryCreateRelativeTo(coordinateSystem); });
    }
    inline auto SpatialAnchor::TryCreateRelativeTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& position)
    {
        return impl::call_factory<SpatialAnchor, ISpatialAnchorStatics>([&](ISpatialAnchorStatics const& f) { return f.TryCreateRelativeTo(coordinateSystem, position); });
    }
    inline auto SpatialAnchor::TryCreateRelativeTo(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Foundation::Numerics::float3 const& position, winrt::Windows::Foundation::Numerics::quaternion const& orientation)
    {
        return impl::call_factory<SpatialAnchor, ISpatialAnchorStatics>([&](ISpatialAnchorStatics const& f) { return f.TryCreateRelativeTo(coordinateSystem, position, orientation); });
    }
    inline auto SpatialAnchorExporter::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Perception::Spatial::SpatialAnchorExporter(*)(ISpatialAnchorExporterStatics const&), SpatialAnchorExporter, ISpatialAnchorExporterStatics>([](ISpatialAnchorExporterStatics const& f) { return f.GetDefault(); });
    }
    inline auto SpatialAnchorExporter::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>(*)(ISpatialAnchorExporterStatics const&), SpatialAnchorExporter, ISpatialAnchorExporterStatics>([](ISpatialAnchorExporterStatics const& f) { return f.RequestAccessAsync(); });
    }
    inline auto SpatialAnchorManager::RequestStoreAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialAnchorStore>(*)(ISpatialAnchorManagerStatics const&), SpatialAnchorManager, ISpatialAnchorManagerStatics>([](ISpatialAnchorManagerStatics const& f) { return f.RequestStoreAsync(); });
    }
    inline auto SpatialAnchorTransferManager::TryImportAnchorsAsync(winrt::Windows::Storage::Streams::IInputStream const& stream)
    {
        return impl::call_factory<SpatialAnchorTransferManager, ISpatialAnchorTransferManagerStatics>([&](ISpatialAnchorTransferManagerStatics const& f) { return f.TryImportAnchorsAsync(stream); });
    }
    inline auto SpatialAnchorTransferManager::TryExportAnchorsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Perception::Spatial::SpatialAnchor>> const& anchors, winrt::Windows::Storage::Streams::IOutputStream const& stream)
    {
        return impl::call_factory<SpatialAnchorTransferManager, ISpatialAnchorTransferManagerStatics>([&](ISpatialAnchorTransferManagerStatics const& f) { return f.TryExportAnchorsAsync(anchors, stream); });
    }
    inline auto SpatialAnchorTransferManager::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialPerceptionAccessStatus>(*)(ISpatialAnchorTransferManagerStatics const&), SpatialAnchorTransferManager, ISpatialAnchorTransferManagerStatics>([](ISpatialAnchorTransferManagerStatics const& f) { return f.RequestAccessAsync(); });
    }
    inline auto SpatialBoundingVolume::FromBox(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingBox const& box)
    {
        return impl::call_factory<SpatialBoundingVolume, ISpatialBoundingVolumeStatics>([&](ISpatialBoundingVolumeStatics const& f) { return f.FromBox(coordinateSystem, box); });
    }
    inline auto SpatialBoundingVolume::FromOrientedBox(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingOrientedBox const& box)
    {
        return impl::call_factory<SpatialBoundingVolume, ISpatialBoundingVolumeStatics>([&](ISpatialBoundingVolumeStatics const& f) { return f.FromOrientedBox(coordinateSystem, box); });
    }
    inline auto SpatialBoundingVolume::FromSphere(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingSphere const& sphere)
    {
        return impl::call_factory<SpatialBoundingVolume, ISpatialBoundingVolumeStatics>([&](ISpatialBoundingVolumeStatics const& f) { return f.FromSphere(coordinateSystem, sphere); });
    }
    inline auto SpatialBoundingVolume::FromFrustum(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::Spatial::SpatialBoundingFrustum const& frustum)
    {
        return impl::call_factory<SpatialBoundingVolume, ISpatialBoundingVolumeStatics>([&](ISpatialBoundingVolumeStatics const& f) { return f.FromFrustum(coordinateSystem, frustum); });
    }
    inline SpatialEntity::SpatialEntity(winrt::Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor) :
        SpatialEntity(impl::call_factory<SpatialEntity, ISpatialEntityFactory>([&](ISpatialEntityFactory const& f) { return f.CreateWithSpatialAnchor(spatialAnchor); }))
    {
    }
    inline SpatialEntity::SpatialEntity(winrt::Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor, winrt::Windows::Foundation::Collections::ValueSet const& propertySet) :
        SpatialEntity(impl::call_factory<SpatialEntity, ISpatialEntityFactory>([&](ISpatialEntityFactory const& f) { return f.CreateWithSpatialAnchorAndProperties(spatialAnchor, propertySet); }))
    {
    }
    inline auto SpatialEntityStore::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(ISpatialEntityStoreStatics const&), SpatialEntityStore, ISpatialEntityStoreStatics>([](ISpatialEntityStoreStatics const& f) { return f.IsSupported(); });
    }
    inline auto SpatialEntityStore::TryGet(winrt::Windows::System::RemoteSystems::RemoteSystemSession const& session)
    {
        return impl::call_factory<SpatialEntityStore, ISpatialEntityStoreStatics>([&](ISpatialEntityStoreStatics const& f) { return f.TryGet(session); });
    }
    inline auto SpatialLocator::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Perception::Spatial::SpatialLocator(*)(ISpatialLocatorStatics const&), SpatialLocator, ISpatialLocatorStatics>([](ISpatialLocatorStatics const& f) { return f.GetDefault(); });
    }
    inline auto SpatialStageFrameOfReference::Current()
    {
        return impl::call_factory_cast<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference(*)(ISpatialStageFrameOfReferenceStatics const&), SpatialStageFrameOfReference, ISpatialStageFrameOfReferenceStatics>([](ISpatialStageFrameOfReferenceStatics const& f) { return f.Current(); });
    }
    inline auto SpatialStageFrameOfReference::CurrentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<SpatialStageFrameOfReference, ISpatialStageFrameOfReferenceStatics>([&](ISpatialStageFrameOfReferenceStatics const& f) { return f.CurrentChanged(handler); });
    }
    inline SpatialStageFrameOfReference::CurrentChanged_revoker SpatialStageFrameOfReference::CurrentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<SpatialStageFrameOfReference, winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>();
        return { f, f.CurrentChanged(handler) };
    }
    inline auto SpatialStageFrameOfReference::CurrentChanged(winrt::event_token const& cookie)
    {
        impl::call_factory<SpatialStageFrameOfReference, ISpatialStageFrameOfReferenceStatics>([&](ISpatialStageFrameOfReferenceStatics const& f) { return f.CurrentChanged(cookie); });
    }
    inline auto SpatialStageFrameOfReference::RequestNewStageAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference>(*)(ISpatialStageFrameOfReferenceStatics const&), SpatialStageFrameOfReference, ISpatialStageFrameOfReferenceStatics>([](ISpatialStageFrameOfReferenceStatics const& f) { return f.RequestNewStageAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorExporter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialBoundingVolume> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialCoordinateSystem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntity> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocatorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialStationaryFrameOfReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorExportSufficiency> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorExporter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorTransferManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialBoundingVolume> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntity> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityAddedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
