// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Maps_Guidance_H
#define WINRT_Windows_Services_Maps_Guidance_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Services.Maps.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Services.Maps.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Services.Maps.Guidance.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind) consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>::AudioNotification() const
    {
        winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs)->get_AudioNotification(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>::AudioFilePaths() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs)->get_AudioFilePaths(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>::AudioText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs)->get_AudioText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceLaneMarkers) consume_Windows_Services_Maps_Guidance_IGuidanceLaneInfo<D>::LaneMarkers() const
    {
        winrt::Windows::Services::Maps::Guidance::GuidanceLaneMarkers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo)->get_LaneMarkers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceLaneInfo<D>::IsOnRoute() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo)->get_IsOnRoute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopoint) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::StartLocation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_StartLocation(&value));
        return winrt::Windows::Devices::Geolocation::Geopoint{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DistanceFromRouteStart() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DistanceFromRouteStart(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DistanceFromPreviousManeuver() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DistanceFromPreviousManeuver(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DepartureRoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DepartureRoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::NextRoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_NextRoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DepartureShortRoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DepartureShortRoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::NextShortRoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_NextShortRoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceManeuverKind) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::Kind() const
    {
        winrt::Windows::Services::Maps::Guidance::GuidanceManeuverKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::StartAngle() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_StartAngle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::EndAngle() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_EndAngle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::RoadSignpost() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_RoadSignpost(&value));
        return winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::InstructionText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_InstructionText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopoint) consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::Location() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_Location(&value));
        return winrt::Windows::Devices::Geolocation::Geopoint{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::CurrentHeading() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_CurrentHeading(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::CurrentSpeed() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_CurrentSpeed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::IsOnStreet() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_IsOnStreet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment) consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::Road() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_Road(&value));
        return winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::StartNavigating(winrt::Windows::Services::Maps::Guidance::GuidanceRoute const& route) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->StartNavigating(*(void**)(&route)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::StartSimulating(winrt::Windows::Services::Maps::Guidance::GuidanceRoute const& route, int32_t speedInMetersPerSecond) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->StartSimulating(*(void**)(&route), speedInMetersPerSecond));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::StartTracking() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->StartTracking());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RepeatLastAudioNotification() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->RepeatLastAudioNotification());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioMeasurementSystem() const
    {
        winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->get_AudioMeasurementSystem(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioMeasurementSystem(winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->put_AudioMeasurementSystem(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioNotifications() const
    {
        winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->get_AudioNotifications(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioNotifications(winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->put_AudioNotifications(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_GuidanceUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GuidanceUpdated_revoker>(this, GuidanceUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_GuidanceUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_DestinationReached(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DestinationReached_revoker>(this, DestinationReached(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_DestinationReached(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_Rerouting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Rerouting_revoker>(this, Rerouting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_Rerouting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_Rerouted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Rerouted_revoker>(this, Rerouted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_Rerouted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_RerouteFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RerouteFailed_revoker>(this, RerouteFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_RerouteFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_UserLocationLost(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UserLocationLost_revoker>(this, UserLocationLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_UserLocationLost(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_UserLocationRestored(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UserLocationRestored_revoker>(this, UserLocationRestored(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_UserLocationRestored(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::SetGuidanceVoice(int32_t voiceId, param::hstring const& voiceFolder) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->SetGuidanceVoice(voiceId, *(void**)(&voiceFolder)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UpdateUserLocation(winrt::Windows::Devices::Geolocation::Geocoordinate const& userLocation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->UpdateUserLocation(*(void**)(&userLocation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UpdateUserLocation(winrt::Windows::Devices::Geolocation::Geocoordinate const& userLocation, winrt::Windows::Devices::Geolocation::BasicGeoposition const& positionOverride) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator)->UpdateUserLocationWithPositionOverride(*(void**)(&userLocation), impl::bind_in(positionOverride)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2)->add_AudioNotificationRequested(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, AudioNotificationRequested_revoker>(this, AudioNotificationRequested(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2)->remove_AudioNotificationRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::IsGuidanceAudioMuted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2)->get_IsGuidanceAudioMuted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::IsGuidanceAudioMuted(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2)->put_IsGuidanceAudioMuted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceNavigator) consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics<D>::GetCurrent() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics)->GetCurrent(&result));
        return winrt::Windows::Services::Maps::Guidance::GuidanceNavigator{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics2<D>::UseAppProvidedVoice() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2)->get_UseAppProvidedVoice(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoute) consume_Windows_Services_Maps_Guidance_IGuidanceReroutedEventArgs<D>::Route() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs)->get_Route(&result));
        return winrt::Windows::Services::Maps::Guidance::GuidanceRoute{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::RoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_RoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::ShortRoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_ShortRoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::SpeedLimit() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_SpeedLimit(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::TravelTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_TravelTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopath) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_Path(&value));
        return winrt::Windows::Devices::Geolocation::Geopath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::IsHighway() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_IsHighway(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::IsTunnel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_IsTunnel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::IsTollRoad() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_IsTollRoad(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment2<D>::IsScenic() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2)->get_IsScenic(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::ExitNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_ExitNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::Exit() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_Exit(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::BackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_BackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::ForegroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_ForegroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::ExitDirections() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_ExitDirections(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Distance() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Distance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Maneuvers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Maneuvers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::GeoboundingBox) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::BoundingBox() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->get_BoundingBox(&value));
        return winrt::Windows::Devices::Geolocation::GeoboundingBox{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Geopath) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Path(&value));
        return winrt::Windows::Devices::Geolocation::Geopath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::RoadSegments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->get_RoadSegments(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::MapRoute) consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::ConvertToMapRoute() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRoute)->ConvertToMapRoute(&result));
        return winrt::Windows::Services::Maps::MapRoute{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceRouteStatics<D>::CanCreateFromMapRoute(winrt::Windows::Services::Maps::MapRoute const& mapRoute) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics)->CanCreateFromMapRoute(*(void**)(&mapRoute), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoute) consume_Windows_Services_Maps_Guidance_IGuidanceRouteStatics<D>::TryCreateFromMapRoute(winrt::Windows::Services::Maps::MapRoute const& mapRoute) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics)->TryCreateFromMapRoute(*(void**)(&mapRoute), &result));
        return winrt::Windows::Services::Maps::Guidance::GuidanceRoute{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::Enabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->get_Enabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::Enabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->put_Enabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::ClearLocalData() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->ClearLocalData());
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::SpeedTrigger() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->get_SpeedTrigger(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::SpeedTrigger(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->put_SpeedTrigger(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::UploadFrequency() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->get_UploadFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::UploadFrequency(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->put_UploadFrequency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector) consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollectorStatics<D>::GetCurrent() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics)->GetCurrent(&result));
        return winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceMode) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::Mode() const
    {
        winrt::Windows::Services::Maps::Guidance::GuidanceMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceManeuver) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::NextManeuver() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_NextManeuver(&value));
        return winrt::Windows::Services::Maps::Guidance::GuidanceManeuver{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::NextManeuverDistance() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_NextManeuverDistance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceManeuver) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::AfterNextManeuver() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_AfterNextManeuver(&value));
        return winrt::Windows::Services::Maps::Guidance::GuidanceManeuver{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::AfterNextManeuverDistance() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_AfterNextManeuverDistance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::DistanceToDestination() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_DistanceToDestination(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::ElapsedDistance() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_ElapsedDistance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::ElapsedTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_ElapsedTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::TimeToDestination() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_TimeToDestination(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::RoadName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_RoadName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceRoute) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::Route() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_Route(&result));
        return winrt::Windows::Services::Maps::Guidance::GuidanceRoute{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::CurrentLocation() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_CurrentLocation(&result));
        return winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::IsNewManeuver() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_IsNewManeuver(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo>) consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::LaneInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_LaneInfo(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo>{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs>
    {
        int32_t __stdcall get_AudioNotification(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind>(this->shim().AudioNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFilePaths(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AudioFilePaths());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo>
    {
        int32_t __stdcall get_LaneMarkers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceLaneMarkers>(this->shim().LaneMarkers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOnRoute(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOnRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver>
    {
        int32_t __stdcall get_StartLocation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Geolocation::Geopoint>(this->shim().StartLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceFromRouteStart(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DistanceFromRouteStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceFromPreviousManeuver(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DistanceFromPreviousManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DepartureRoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DepartureRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NextRoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NextRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DepartureShortRoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DepartureShortRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NextShortRoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NextShortRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceManeuverKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartAngle(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().StartAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndAngle(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().EndAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoadSignpost(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost>(this->shim().RoadSignpost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstructionText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InstructionText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate>
    {
        int32_t __stdcall get_Location(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentHeading(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurrentHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentSpeed(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CurrentSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOnStreet(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOnStreet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Road(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>(this->shim().Road());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator>
    {
        int32_t __stdcall StartNavigating(void* route) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartNavigating(*reinterpret_cast<winrt::Windows::Services::Maps::Guidance::GuidanceRoute const*>(&route));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartSimulating(void* route, int32_t speedInMetersPerSecond) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartSimulating(*reinterpret_cast<winrt::Windows::Services::Maps::Guidance::GuidanceRoute const*>(&route), speedInMetersPerSecond);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartTracking() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTracking();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Pause() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resume() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resume();
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
        int32_t __stdcall RepeatLastAudioNotification() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RepeatLastAudioNotification();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioMeasurementSystem(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem>(this->shim().AudioMeasurementSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioMeasurementSystem(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioMeasurementSystem(*reinterpret_cast<winrt::Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioNotifications(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications>(this->shim().AudioNotifications());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioNotifications(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioNotifications(*reinterpret_cast<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotifications const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_GuidanceUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GuidanceUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GuidanceUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GuidanceUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DestinationReached(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DestinationReached(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DestinationReached(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DestinationReached(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Rerouting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Rerouting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Rerouting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rerouting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Rerouted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Rerouted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Rerouted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rerouted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RerouteFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RerouteFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RerouteFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RerouteFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UserLocationLost(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UserLocationLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UserLocationLost(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserLocationLost(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UserLocationRestored(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UserLocationRestored(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UserLocationRestored(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserLocationRestored(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall SetGuidanceVoice(int32_t voiceId, void* voiceFolder) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetGuidanceVoice(voiceId, *reinterpret_cast<hstring const*>(&voiceFolder));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateUserLocation(void* userLocation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateUserLocation(*reinterpret_cast<winrt::Windows::Devices::Geolocation::Geocoordinate const*>(&userLocation));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateUserLocationWithPositionOverride(void* userLocation, struct struct_Windows_Devices_Geolocation_BasicGeoposition positionOverride) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateUserLocation(*reinterpret_cast<winrt::Windows::Devices::Geolocation::Geocoordinate const*>(&userLocation), *reinterpret_cast<winrt::Windows::Devices::Geolocation::BasicGeoposition const*>(&positionOverride));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2>
    {
        int32_t __stdcall add_AudioNotificationRequested(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AudioNotificationRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator, winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AudioNotificationRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioNotificationRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_IsGuidanceAudioMuted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGuidanceAudioMuted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsGuidanceAudioMuted(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsGuidanceAudioMuted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>
    {
        int32_t __stdcall GetCurrent(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator>(this->shim().GetCurrent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>
    {
        int32_t __stdcall get_UseAppProvidedVoice(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UseAppProvidedVoice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs>
    {
        int32_t __stdcall get_Route(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceRoute>(this->shim().Route());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment>
    {
        int32_t __stdcall get_RoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShortRoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ShortRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeedLimit(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SpeedLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TravelTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().TravelTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Geolocation::Geopath>(this->shim().Path());
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
        int32_t __stdcall get_IsHighway(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHighway());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTunnel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTunnel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTollRoad(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTollRoad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2>
    {
        int32_t __stdcall get_IsScenic(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScenic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost>
    {
        int32_t __stdcall get_ExitNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExitNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Exit(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Exit());
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
        int32_t __stdcall get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitDirections(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().ExitDirections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoute> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRoute>
    {
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Distance(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Distance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Maneuvers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>>(this->shim().Maneuvers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BoundingBox(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Geolocation::GeoboundingBox>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Geolocation::Geopath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoadSegments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment>>(this->shim().RoadSegments());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertToMapRoute(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::MapRoute>(this->shim().ConvertToMapRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics>
    {
        int32_t __stdcall CanCreateFromMapRoute(void* mapRoute, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().CanCreateFromMapRoute(*reinterpret_cast<winrt::Windows::Services::Maps::MapRoute const*>(&mapRoute)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFromMapRoute(void* mapRoute, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceRoute>(this->shim().TryCreateFromMapRoute(*reinterpret_cast<winrt::Windows::Services::Maps::MapRoute const*>(&mapRoute)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector>
    {
        int32_t __stdcall get_Enabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Enabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearLocalData() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearLocalData();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeedTrigger(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SpeedTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpeedTrigger(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpeedTrigger(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UploadFrequency(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().UploadFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UploadFrequency(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UploadFrequency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>
    {
        int32_t __stdcall GetCurrent(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector>(this->shim().GetCurrent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs> : produce_base<D, winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs>
    {
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NextManeuver(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>(this->shim().NextManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NextManeuverDistance(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NextManeuverDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AfterNextManeuver(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver>(this->shim().AfterNextManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AfterNextManeuverDistance(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().AfterNextManeuverDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceToDestination(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DistanceToDestination());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElapsedDistance(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ElapsedDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElapsedTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().ElapsedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimeToDestination(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().TimeToDestination());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoadName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Route(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceRoute>(this->shim().Route());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentLocation(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate>(this->shim().CurrentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsNewManeuver(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsNewManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LaneInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo>>(this->shim().LaneInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Services::Maps::Guidance
{
    constexpr auto operator|(GuidanceAudioNotifications const left, GuidanceAudioNotifications const right) noexcept
    {
        return static_cast<GuidanceAudioNotifications>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(GuidanceAudioNotifications& left, GuidanceAudioNotifications const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(GuidanceAudioNotifications const left, GuidanceAudioNotifications const right) noexcept
    {
        return static_cast<GuidanceAudioNotifications>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(GuidanceAudioNotifications& left, GuidanceAudioNotifications const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(GuidanceAudioNotifications const value) noexcept
    {
        return static_cast<GuidanceAudioNotifications>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(GuidanceAudioNotifications const left, GuidanceAudioNotifications const right) noexcept
    {
        return static_cast<GuidanceAudioNotifications>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(GuidanceAudioNotifications& left, GuidanceAudioNotifications const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(GuidanceLaneMarkers const left, GuidanceLaneMarkers const right) noexcept
    {
        return static_cast<GuidanceLaneMarkers>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(GuidanceLaneMarkers& left, GuidanceLaneMarkers const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(GuidanceLaneMarkers const left, GuidanceLaneMarkers const right) noexcept
    {
        return static_cast<GuidanceLaneMarkers>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(GuidanceLaneMarkers& left, GuidanceLaneMarkers const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(GuidanceLaneMarkers const value) noexcept
    {
        return static_cast<GuidanceLaneMarkers>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(GuidanceLaneMarkers const left, GuidanceLaneMarkers const right) noexcept
    {
        return static_cast<GuidanceLaneMarkers>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(GuidanceLaneMarkers& left, GuidanceLaneMarkers const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto GuidanceNavigator::GetCurrent()
    {
        return impl::call_factory_cast<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator(*)(IGuidanceNavigatorStatics const&), GuidanceNavigator, IGuidanceNavigatorStatics>([](IGuidanceNavigatorStatics const& f) { return f.GetCurrent(); });
    }
    inline auto GuidanceNavigator::UseAppProvidedVoice()
    {
        return impl::call_factory_cast<bool(*)(IGuidanceNavigatorStatics2 const&), GuidanceNavigator, IGuidanceNavigatorStatics2>([](IGuidanceNavigatorStatics2 const& f) { return f.UseAppProvidedVoice(); });
    }
    inline auto GuidanceRoute::CanCreateFromMapRoute(winrt::Windows::Services::Maps::MapRoute const& mapRoute)
    {
        return impl::call_factory<GuidanceRoute, IGuidanceRouteStatics>([&](IGuidanceRouteStatics const& f) { return f.CanCreateFromMapRoute(mapRoute); });
    }
    inline auto GuidanceRoute::TryCreateFromMapRoute(winrt::Windows::Services::Maps::MapRoute const& mapRoute)
    {
        return impl::call_factory<GuidanceRoute, IGuidanceRouteStatics>([&](IGuidanceRouteStatics const& f) { return f.TryCreateFromMapRoute(mapRoute); });
    }
    inline auto GuidanceTelemetryCollector::GetCurrent()
    {
        return impl::call_factory_cast<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector(*)(IGuidanceTelemetryCollectorStatics const&), GuidanceTelemetryCollector, IGuidanceTelemetryCollectorStatics>([](IGuidanceTelemetryCollectorStatics const& f) { return f.GetCurrent(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceRoute> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
