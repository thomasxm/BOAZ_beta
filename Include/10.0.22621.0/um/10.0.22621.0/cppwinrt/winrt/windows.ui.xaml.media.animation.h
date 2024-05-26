// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Media_Animation_H
#define WINRT_Windows_UI_Xaml_Media_Animation_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IBackEase<D>::Amplitude() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBackEase)->get_Amplitude(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IBackEase<D>::Amplitude(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBackEase)->put_Amplitude(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IBackEaseStatics<D>::AmplitudeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBackEaseStatics)->get_AmplitudeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration) consume_Windows_UI_Xaml_Media_Animation_IBasicConnectedAnimationConfigurationFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::Storyboard) consume_Windows_UI_Xaml_Media_Animation_IBeginStoryboard<D>::Storyboard() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard)->get_Storyboard(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::Storyboard{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IBeginStoryboard<D>::Storyboard(winrt::Windows::UI::Xaml::Media::Animation::Storyboard const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard)->put_Storyboard(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IBeginStoryboardStatics<D>::StoryboardProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics)->get_StoryboardProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounces() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBounceEase)->get_Bounces(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounces(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBounceEase)->put_Bounces(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounciness() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBounceEase)->get_Bounciness(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounciness(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBounceEase)->put_Bounciness(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IBounceEaseStatics<D>::BouncesProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics)->get_BouncesProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IBounceEaseStatics<D>::BouncinessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics)->get_BouncinessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::From() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_From(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::From(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_From(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::To() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_To(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::To(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_To(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::By() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_By(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::By(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_By(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_EasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_EasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::FromProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_FromProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::ToProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_ToProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::ByProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_ByProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::EasingFunctionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_EasingFunctionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFrames<D>::KeyFrames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames)->get_KeyFrames(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::Value() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->get_Value(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::Value(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->put_Value(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeyTime) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::KeyTime() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::KeyTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->get_KeyTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::KeyTime(winrt::Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->put_KeyTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrame) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrameFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrameStatics<D>::ValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics)->get_ValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrameStatics<D>::KeyTimeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics)->get_KeyTimeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfo<D>::IsStaggeringEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo)->get_IsStaggeringEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfo<D>::IsStaggeringEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo)->put_IsStaggeringEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::IsStaggeringEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->get_IsStaggeringEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::IsStaggerElementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->get_IsStaggerElementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::GetIsStaggerElement(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->GetIsStaggerElement(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::SetIsStaggerElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->SetIsStaggerElement(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->add_Completed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed_revoker consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->remove_Completed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::TryStart(winrt::Windows::UI::Xaml::UIElement const& destination) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->TryStart(*(void**)(&destination), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Cancel() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->Cancel());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::IsScaleAnimationEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->get_IsScaleAnimationEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::IsScaleAnimationEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->put_IsScaleAnimationEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::TryStart(winrt::Windows::UI::Xaml::UIElement const& destination, param::iterable<winrt::Windows::UI::Xaml::UIElement> const& coordinatedElements) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->TryStartWithCoordinatedElements(*(void**)(&destination), *(void**)(&coordinatedElements), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::SetAnimationComponent(winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationComponent const& component, winrt::Windows::UI::Composition::ICompositionAnimationBase const& animation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->SetAnimationComponent(static_cast<int32_t>(component), *(void**)(&animation)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation3<D>::Configuration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3)->get_Configuration(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation3<D>::Configuration(winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3)->put_Configuration(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->get_DefaultDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultDuration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->put_DefaultDuration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::CompositionEasingFunction) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultEasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->get_DefaultEasingFunction(&value));
        return winrt::Windows::UI::Composition::CompositionEasingFunction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultEasingFunction(winrt::Windows::UI::Composition::CompositionEasingFunction const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->put_DefaultEasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::PrepareToAnimate(param::hstring const& key, winrt::Windows::UI::Xaml::UIElement const& source) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->PrepareToAnimate(*(void**)(&key), *(void**)(&source), &result));
        return winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::GetAnimation(param::hstring const& key) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->GetAnimation(*(void**)(&key), &result));
        return winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService) consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationServiceStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics)->GetForCurrentView(&result));
        return winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::HorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->get_HorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::HorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->put_HorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::VerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->get_VerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::VerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->put_VerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransitionStatics<D>::HorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics)->get_HorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransitionStatics<D>::VerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics)->get_VerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfo<D>::ExitElement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo)->get_ExitElement(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfo<D>::ExitElement(winrt::Windows::UI::Xaml::UIElement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo)->put_ExitElement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::ExitElementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_ExitElementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::IsEntranceElementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_IsEntranceElementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::GetIsEntranceElement(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->GetIsEntranceElement(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::SetIsEntranceElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->SetIsEntranceElement(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::IsExitElementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_IsExitElementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::GetIsExitElement(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->GetIsExitElement(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::SetIsExitElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->SetIsExitElement(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::ExitElementContainerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_ExitElementContainerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::GetExitElementContainer(winrt::Windows::UI::Xaml::Controls::ListViewBase const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->GetExitElementContainer(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::SetExitElementContainer(winrt::Windows::UI::Xaml::Controls::ListViewBase const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->SetExitElementContainer(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration) consume_Windows_UI_Xaml_Media_Animation_IDirectConnectedAnimationConfigurationFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::From() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_From(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::From(winrt::Windows::Foundation::IReference<double> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_From(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::To() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_To(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::To(winrt::Windows::Foundation::IReference<double> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_To(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::By() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_By(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::By(winrt::Windows::Foundation::IReference<double> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_By(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_EasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_EasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::FromProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_FromProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::ToProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_ToProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::ByProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_ByProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::EasingFunctionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_EasingFunctionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFrames<D>::KeyFrames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames)->get_KeyFrames(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::Value() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->get_Value(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::Value(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->put_Value(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeyTime) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::KeyTime() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::KeyTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->get_KeyTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::KeyTime(winrt::Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->put_KeyTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrame) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrameFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrameStatics<D>::ValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics)->get_ValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrameStatics<D>::KeyTimeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics)->get_KeyTimeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDragItemThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDragItemThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDragItemThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::ToOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->get_ToOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::ToOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->put_ToOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::Direction() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->get_Direction(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::Direction(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->put_Direction(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimationStatics<D>::ToOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics)->get_ToOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimationStatics<D>::DirectionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics)->get_DirectionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_EntranceTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_EntranceTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_EntranceTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_EntranceTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_ExitTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_ExitTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_ExitTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_ExitTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::EntranceTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_EntranceTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::EntranceTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_EntranceTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::ExitTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_ExitTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::ExitTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_ExitTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_EntranceTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_EntranceTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_EntranceTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_EntranceTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_ExitTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_ExitTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_ExitTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_ExitTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::EntranceTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_EntranceTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::EntranceTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_EntranceTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::ExitTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_ExitTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::ExitTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_ExitTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IDropTargetItemThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IDropTargetItemThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IDropTargetItemThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_Media_Animation_IEasingColorKeyFrame<D>::EasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame)->get_EasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEasingColorKeyFrame<D>::EasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame)->put_EasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEasingColorKeyFrameStatics<D>::EasingFunctionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics)->get_EasingFunctionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_Media_Animation_IEasingDoubleKeyFrame<D>::EasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame)->get_EasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEasingDoubleKeyFrame<D>::EasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame)->put_EasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEasingDoubleKeyFrameStatics<D>::EasingFunctionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics)->get_EasingFunctionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingMode) consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBase<D>::EasingMode() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::EasingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase)->get_EasingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBase<D>::EasingMode(winrt::Windows::UI::Xaml::Media::Animation::EasingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase)->put_EasingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBase<D>::Ease(double normalizedTime) const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase)->Ease(normalizedTime, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBaseStatics<D>::EasingModeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics)->get_EasingModeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_Media_Animation_IEasingPointKeyFrame<D>::EasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame)->get_EasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEasingPointKeyFrame<D>::EasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame)->put_EasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEasingPointKeyFrameStatics<D>::EasingFunctionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics)->get_EasingFunctionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation) consume_Windows_UI_Xaml_Media_Animation_IEdgeUIThemeTransition<D>::Edge() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition)->get_Edge(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEdgeUIThemeTransition<D>::Edge(winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition)->put_Edge(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEdgeUIThemeTransitionStatics<D>::EdgeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics)->get_EdgeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Oscillations() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IElasticEase)->get_Oscillations(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Oscillations(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IElasticEase)->put_Oscillations(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Springiness() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IElasticEase)->get_Springiness(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Springiness(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IElasticEase)->put_Springiness(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IElasticEaseStatics<D>::OscillationsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics)->get_OscillationsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IElasticEaseStatics<D>::SpringinessProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics)->get_SpringinessProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEntranceNavigationTransitionInfoStatics<D>::IsTargetElementProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics)->get_IsTargetElementProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IEntranceNavigationTransitionInfoStatics<D>::GetIsTargetElement(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics)->GetIsTargetElement(*(void**)(&element), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEntranceNavigationTransitionInfoStatics<D>::SetIsTargetElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics)->SetIsTargetElement(*(void**)(&element), value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->get_FromHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->put_FromHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->get_FromVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->put_FromVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::IsStaggeringEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->get_IsStaggeringEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::IsStaggeringEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->put_IsStaggeringEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransitionStatics<D>::FromHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics)->get_FromHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransitionStatics<D>::FromVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics)->get_FromVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransitionStatics<D>::IsStaggeringEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics)->get_IsStaggeringEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IExponentialEase<D>::Exponent() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase)->get_Exponent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IExponentialEase<D>::Exponent(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase)->put_Exponent(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IExponentialEaseStatics<D>::ExponentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics)->get_ExponentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IFadeInThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IFadeInThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IFadeInThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IFadeOutThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IFadeOutThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IFadeOutThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IGravityConnectedAnimationConfiguration2<D>::IsShadowEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2)->get_IsShadowEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IGravityConnectedAnimationConfiguration2<D>::IsShadowEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2)->put_IsShadowEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration) consume_Windows_UI_Xaml_Media_Animation_IGravityConnectedAnimationConfigurationFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint1() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IKeySpline)->get_ControlPoint1(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint1(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IKeySpline)->put_ControlPoint1(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint2() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IKeySpline)->get_ControlPoint2(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint2(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IKeySpline)->put_ControlPoint2(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeyTime) consume_Windows_UI_Xaml_Media_Animation_IKeyTimeHelperStatics<D>::FromTimeSpan(winrt::Windows::Foundation::TimeSpan const& timeSpan) const
    {
        winrt::Windows::UI::Xaml::Media::Animation::KeyTime result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics)->FromTimeSpan(impl::bind_in(timeSpan), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo) consume_Windows_UI_Xaml_Media_Animation_INavigationThemeTransition<D>::DefaultNavigationTransitionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition)->get_DefaultNavigationTransitionInfo(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_INavigationThemeTransition<D>::DefaultNavigationTransitionInfo(winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition)->put_DefaultNavigationTransitionInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_INavigationThemeTransitionStatics<D>::DefaultNavigationTransitionInfoProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics)->get_DefaultNavigationTransitionInfoProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo) consume_Windows_UI_Xaml_Media_Animation_INavigationTransitionInfoFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_INavigationTransitionInfoOverrides<D>::GetNavigationStateCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides)->GetNavigationStateCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_INavigationTransitionInfoOverrides<D>::SetNavigationStateCore(param::hstring const& navigationState) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides)->SetNavigationStateCore(*(void**)(&navigationState)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection) consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFrames<D>::KeyFrames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames)->get_KeyFrames(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->get_Value(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::Value(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeyTime) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::KeyTime() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::KeyTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->get_KeyTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::KeyTime(winrt::Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->put_KeyTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrame) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrameFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrameStatics<D>::ValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics)->get_ValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrameStatics<D>::KeyTimeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics)->get_KeyTimeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation) consume_Windows_UI_Xaml_Media_Animation_IPaneThemeTransition<D>::Edge() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition)->get_Edge(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPaneThemeTransition<D>::Edge(winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition)->put_Edge(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPaneThemeTransitionStatics<D>::EdgeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics)->get_EdgeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::From() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_From(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::From(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_From(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::To() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_To(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::To(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_To(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::By() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_By(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::By(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_By(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EasingFunction() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_EasingFunction(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EasingFunction(winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_EasingFunction(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::FromProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_FromProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::ToProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_ToProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::ByProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_ByProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::EasingFunctionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_EasingFunctionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFrames<D>::KeyFrames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames)->get_KeyFrames(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::Value() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->get_Value(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::Value(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->put_Value(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeyTime) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::KeyTime() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::KeyTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->get_KeyTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::KeyTime(winrt::Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->put_KeyTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrame) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrameFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrameStatics<D>::ValueProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics)->get_ValueProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrameStatics<D>::KeyTimeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics)->get_KeyTimeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IPointerDownThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointerDownThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointerDownThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IPointerUpThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPointerUpThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPointerUpThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->get_FromHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->put_FromHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->get_FromVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->put_FromVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimationStatics<D>::FromHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics)->get_FromHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimationStatics<D>::FromVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics)->get_FromVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IPopOutThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPopOutThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPopOutThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->get_FromHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->put_FromHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->get_FromVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->put_FromVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransitionStatics<D>::FromHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics)->get_FromHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransitionStatics<D>::FromVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics)->get_FromVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IPowerEase<D>::Power() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPowerEase)->get_Power(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IPowerEase<D>::Power(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPowerEase)->put_Power(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IPowerEaseStatics<D>::PowerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IPowerEaseStatics)->get_PowerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior) consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::Forever() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->get_Forever(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior) consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::FromCount(double count) const
    {
        winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->FromCount(count, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior) consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::FromDuration(winrt::Windows::Foundation::TimeSpan const& duration) const
    {
        winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->FromDuration(impl::bind_in(duration), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::GetHasCount(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->GetHasCount(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::GetHasDuration(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->GetHasDuration(impl::bind_in(target), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::Equals(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target, winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& value) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->Equals(impl::bind_in(target), impl::bind_in(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->get_FromHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->put_FromHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->get_FromVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->put_FromVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimationStatics<D>::FromHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics)->get_FromHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimationStatics<D>::FromVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics)->get_FromVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeTransition2<D>::IsStaggeringEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2)->get_IsStaggeringEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeTransition2<D>::IsStaggeringEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2)->put_IsStaggeringEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeTransitionStatics2<D>::IsStaggeringEnabledProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2)->get_IsStaggeringEnabledProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect) consume_Windows_UI_Xaml_Media_Animation_ISlideNavigationTransitionInfo2<D>::Effect() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2)->get_Effect(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISlideNavigationTransitionInfo2<D>::Effect(winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2)->put_Effect(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISlideNavigationTransitionInfoStatics2<D>::EffectProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2)->get_EffectProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeySpline) consume_Windows_UI_Xaml_Media_Animation_ISplineColorKeyFrame<D>::KeySpline() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame)->get_KeySpline(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::KeySpline{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplineColorKeyFrame<D>::KeySpline(winrt::Windows::UI::Xaml::Media::Animation::KeySpline const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame)->put_KeySpline(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplineColorKeyFrameStatics<D>::KeySplineProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics)->get_KeySplineProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeySpline) consume_Windows_UI_Xaml_Media_Animation_ISplineDoubleKeyFrame<D>::KeySpline() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame)->get_KeySpline(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::KeySpline{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplineDoubleKeyFrame<D>::KeySpline(winrt::Windows::UI::Xaml::Media::Animation::KeySpline const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame)->put_KeySpline(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplineDoubleKeyFrameStatics<D>::KeySplineProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics)->get_KeySplineProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::KeySpline) consume_Windows_UI_Xaml_Media_Animation_ISplinePointKeyFrame<D>::KeySpline() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame)->get_KeySpline(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::KeySpline{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplinePointKeyFrame<D>::KeySpline(winrt::Windows::UI::Xaml::Media::Animation::KeySpline const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame)->put_KeySpline(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplinePointKeyFrameStatics<D>::KeySplineProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics)->get_KeySplineProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OpenedTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OpenedTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OpenedTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OpenedTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ClosedTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ClosedTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ClosedTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ClosedTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OpenedLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedLength(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OpenedLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ClosedLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedLength(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ClosedLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OffsetFromCenter() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OffsetFromCenter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OffsetFromCenter(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OffsetFromCenter(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationDirection() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTranslationDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationDirection(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTranslationDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTranslationOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTranslationOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OpenedTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OpenedTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OpenedTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OpenedTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ClosedTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ClosedTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ClosedTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ClosedTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OpenedLengthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OpenedLengthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ClosedLengthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ClosedLengthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OffsetFromCenterProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OffsetFromCenterProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTranslationDirectionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTranslationDirectionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTranslationOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTranslationOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OpenedTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OpenedTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OpenedTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OpenedTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ClosedTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ClosedTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ClosedTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ClosedTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTarget(&value));
        return winrt::Windows::UI::Xaml::DependencyObject{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTarget(winrt::Windows::UI::Xaml::DependencyObject const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTarget(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OpenedLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedLength(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OpenedLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedLength() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ClosedLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedLength(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ClosedLength(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OffsetFromCenter() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OffsetFromCenter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OffsetFromCenter(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OffsetFromCenter(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationDirection() const
    {
        winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTranslationDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationDirection(winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTranslationDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTranslationOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTranslationOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OpenedTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OpenedTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OpenedTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OpenedTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ClosedTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ClosedTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ClosedTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ClosedTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTargetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTargetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OpenedLengthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OpenedLengthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ClosedLengthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ClosedLengthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OffsetFromCenterProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OffsetFromCenterProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTranslationDirectionProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTranslationDirectionProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTranslationOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTranslationOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::TimelineCollection) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Children() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->get_Children(&value));
        return winrt::Windows::UI::Xaml::Media::Animation::TimelineCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Seek(winrt::Windows::Foundation::TimeSpan const& offset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->Seek(impl::bind_in(offset)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Begin() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->Begin());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::ClockState) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::GetCurrentState() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::ClockState result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->GetCurrentState(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::GetCurrentTime() const
    {
        winrt::Windows::Foundation::TimeSpan result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->GetCurrentTime(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::SeekAlignedToLastTick(winrt::Windows::Foundation::TimeSpan const& offset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->SeekAlignedToLastTick(impl::bind_in(offset)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::SkipToFill() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboard)->SkipToFill());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::TargetPropertyProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->get_TargetPropertyProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::GetTargetProperty(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->GetTargetProperty(*(void**)(&element), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::SetTargetProperty(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& path) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->SetTargetProperty(*(void**)(&element), *(void**)(&path)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::GetTargetName(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->GetTargetName(*(void**)(&element), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::SetTargetName(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& name) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->SetTargetName(*(void**)(&element), *(void**)(&name)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::SetTarget(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& timeline, winrt::Windows::UI::Xaml::DependencyObject const& target) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->SetTarget(*(void**)(&timeline), *(void**)(&target)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->get_FromHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->put_FromHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->get_FromVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->put_FromVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimationStatics<D>::FromHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics)->get_FromHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimationStatics<D>::FromVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics)->get_FromVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToHorizontalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->get_ToHorizontalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToHorizontalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->put_ToHorizontalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToVerticalOffset() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->get_ToVerticalOffset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToVerticalOffset(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->put_ToVerticalOffset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimationStatics<D>::TargetNameProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics)->get_TargetNameProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimationStatics<D>::ToHorizontalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics)->get_ToHorizontalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimationStatics<D>::ToVerticalOffsetProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics)->get_ToVerticalOffsetProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::AutoReverse() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->get_AutoReverse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::AutoReverse(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->put_AutoReverse(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::BeginTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->get_BeginTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::BeginTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->put_BeginTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Duration) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Duration() const
    {
        winrt::Windows::UI::Xaml::Duration value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Duration(winrt::Windows::UI::Xaml::Duration const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::SpeedRatio() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->get_SpeedRatio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::SpeedRatio(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->put_SpeedRatio(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::FillBehavior) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::FillBehavior() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::FillBehavior value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->get_FillBehavior(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::FillBehavior(winrt::Windows::UI::Xaml::Media::Animation::FillBehavior const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->put_FillBehavior(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::RepeatBehavior() const
    {
        winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->get_RepeatBehavior(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::RepeatBehavior(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->put_RepeatBehavior(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->add_Completed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed_revoker consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimeline)->remove_Completed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Animation::Timeline) consume_Windows_UI_Xaml_Media_Animation_ITimelineFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Animation::Timeline{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::AllowDependentAnimations() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_AllowDependentAnimations(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::AllowDependentAnimations(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->put_AllowDependentAnimations(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::AutoReverseProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_AutoReverseProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::BeginTimeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_BeginTimeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::DurationProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_DurationProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::SpeedRatioProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_SpeedRatioProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::FillBehaviorProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_FillBehaviorProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::RepeatBehaviorProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_RepeatBehaviorProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBackEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBackEase>
    {
        int32_t __stdcall get_Amplitude(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Amplitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Amplitude(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Amplitude(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBackEaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBackEaseStatics>
    {
        int32_t __stdcall get_AmplitudeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AmplitudeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard>
    {
        int32_t __stdcall get_Storyboard(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::Storyboard>(this->shim().Storyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Storyboard(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Storyboard(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Storyboard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics>
    {
        int32_t __stdcall get_StoryboardProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().StoryboardProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBounceEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBounceEase>
    {
        int32_t __stdcall get_Bounces(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Bounces());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Bounces(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bounces(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bounciness(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Bounciness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Bounciness(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bounciness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics>
    {
        int32_t __stdcall get_BouncesProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().BouncesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BouncinessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().BouncinessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ICircleEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ICircleEase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation>
    {
        int32_t __stdcall get_From(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_From(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().From(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_To(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_To(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().To(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_By(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().By());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_By(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().By(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>
    {
        int32_t __stdcall get_FromProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ByProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EasingFunctionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames>
    {
        int32_t __stdcall get_KeyFrames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics>
    {
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame>
    {
        int32_t __stdcall get_Value(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTime(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics>
    {
        int32_t __stdcall get_ValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTimeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo>
    {
        int32_t __stdcall get_IsStaggeringEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStaggeringEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsStaggeringEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsStaggeringEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics>
    {
        int32_t __stdcall get_IsStaggeringEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggeringEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStaggerElementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggerElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsStaggerElement(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsStaggerElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetIsStaggerElement(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetIsStaggerElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation>
    {
        int32_t __stdcall add_Completed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Completed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall TryStart(void* destination, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryStart(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Cancel() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2>
    {
        int32_t __stdcall get_IsScaleAnimationEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScaleAnimationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsScaleAnimationEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsScaleAnimationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStartWithCoordinatedElements(void* destination, void* coordinatedElements, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TryStart(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&destination), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::UIElement> const*>(&coordinatedElements)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAnimationComponent(int32_t component, void* animation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAnimationComponent(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationComponent const*>(&component), *reinterpret_cast<winrt::Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3>
    {
        int32_t __stdcall get_Configuration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Configuration(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Configuration(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService>
    {
        int32_t __stdcall get_DefaultDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DefaultDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultDuration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultDuration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultEasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::CompositionEasingFunction>(this->shim().DefaultEasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultEasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultEasingFunction(*reinterpret_cast<winrt::Windows::UI::Composition::CompositionEasingFunction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrepareToAnimate(void* key, void* source, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation>(this->shim().PrepareToAnimate(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnimation(void* key, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation>(this->shim().GetAnimation(*reinterpret_cast<hstring const*>(&key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics>
    {
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition>
    {
        int32_t __stdcall get_HorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics>
    {
        int32_t __stdcall get_HorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().VerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo>
    {
        int32_t __stdcall get_ExitElement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().ExitElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitElement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>
    {
        int32_t __stdcall get_ExitElementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEntranceElementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsEntranceElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsEntranceElement(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsEntranceElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetIsEntranceElement(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetIsEntranceElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsExitElementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsExitElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsExitElement(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsExitElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetIsExitElement(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetIsExitElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitElementContainerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitElementContainerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetExitElementContainer(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetExitElementContainer(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListViewBase const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetExitElementContainer(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetExitElementContainer(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListViewBase const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ICubicEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ICubicEase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation>
    {
        int32_t __stdcall get_From(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_From(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().From(*reinterpret_cast<winrt::Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_To(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_To(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().To(*reinterpret_cast<winrt::Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_By(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().By());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_By(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().By(*reinterpret_cast<winrt::Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>
    {
        int32_t __stdcall get_FromProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ByProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EasingFunctionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames>
    {
        int32_t __stdcall get_KeyFrames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics>
    {
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame>
    {
        int32_t __stdcall get_Value(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTime(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics>
    {
        int32_t __stdcall get_ValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTimeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ToOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direction(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Direction(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Direction(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ToOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DirectionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation>
    {
        int32_t __stdcall get_EntranceTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EntranceTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EntranceTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EntranceTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EntranceTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().EntranceTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EntranceTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EntranceTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExitTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ExitTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics>
    {
        int32_t __stdcall get_EntranceTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EntranceTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation>
    {
        int32_t __stdcall get_EntranceTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EntranceTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EntranceTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EntranceTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EntranceTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().EntranceTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EntranceTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EntranceTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExitTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ExitTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExitTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExitTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics>
    {
        int32_t __stdcall get_EntranceTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EntranceTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExitTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame>
    {
        int32_t __stdcall get_EasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics>
    {
        int32_t __stdcall get_EasingFunctionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame>
    {
        int32_t __stdcall get_EasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics>
    {
        int32_t __stdcall get_EasingFunctionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase>
    {
        int32_t __stdcall get_EasingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingMode>(this->shim().EasingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingMode(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Ease(double normalizedTime, double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().Ease(normalizedTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics>
    {
        int32_t __stdcall get_EasingModeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame>
    {
        int32_t __stdcall get_EasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics>
    {
        int32_t __stdcall get_EasingFunctionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition>
    {
        int32_t __stdcall get_Edge(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Edge(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Edge(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics>
    {
        int32_t __stdcall get_EdgeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EdgeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IElasticEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IElasticEase>
    {
        int32_t __stdcall get_Oscillations(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Oscillations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Oscillations(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Oscillations(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Springiness(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Springiness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Springiness(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Springiness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics>
    {
        int32_t __stdcall get_OscillationsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OscillationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpringinessProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SpringinessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics>
    {
        int32_t __stdcall get_IsTargetElementProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsTargetElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIsTargetElement(void* element, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetIsTargetElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetIsTargetElement(void* element, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetIsTargetElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition>
    {
        int32_t __stdcall get_FromHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStaggeringEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStaggeringEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsStaggeringEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsStaggeringEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics>
    {
        int32_t __stdcall get_FromHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStaggeringEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggeringEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase>
    {
        int32_t __stdcall get_Exponent(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Exponent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Exponent(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Exponent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics>
    {
        int32_t __stdcall get_ExponentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ExponentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2>
    {
        int32_t __stdcall get_IsShadowEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsShadowEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsShadowEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsShadowEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IKeySpline> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IKeySpline>
    {
        int32_t __stdcall get_ControlPoint1(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().ControlPoint1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ControlPoint1(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ControlPoint1(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ControlPoint2(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().ControlPoint2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ControlPoint2(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ControlPoint2(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelper> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics>
    {
        int32_t __stdcall FromTimeSpan(int64_t timeSpan, struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().FromTimeSpan(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timeSpan)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition>
    {
        int32_t __stdcall get_DefaultNavigationTransitionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().DefaultNavigationTransitionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultNavigationTransitionInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultNavigationTransitionInfo(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics>
    {
        int32_t __stdcall get_DefaultNavigationTransitionInfoProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DefaultNavigationTransitionInfoProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides>
    {
        int32_t __stdcall GetNavigationStateCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetNavigationStateCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetNavigationStateCore(void* navigationState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetNavigationStateCore(*reinterpret_cast<hstring const*>(&navigationState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames>
    {
        int32_t __stdcall get_KeyFrames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics>
    {
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame>
    {
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTime(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics>
    {
        int32_t __stdcall get_ValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTimeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition>
    {
        int32_t __stdcall get_Edge(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Edge(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Edge(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics>
    {
        int32_t __stdcall get_EdgeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EdgeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation>
    {
        int32_t __stdcall get_From(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_From(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().From(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_To(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_To(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().To(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_By(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point>>(this->shim().By());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_By(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().By(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EasingFunction(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EasingFunction(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EasingFunction(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>
    {
        int32_t __stdcall get_FromProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ByProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EasingFunctionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames>
    {
        int32_t __stdcall get_KeyFrames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EnableDependentAnimation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnableDependentAnimation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics>
    {
        int32_t __stdcall get_EnableDependentAnimationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame>
    {
        int32_t __stdcall get_Value(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyTime(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics>
    {
        int32_t __stdcall get_ValueProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyTimeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition>
    {
        int32_t __stdcall get_FromHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics>
    {
        int32_t __stdcall get_FromHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPowerEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPowerEase>
    {
        int32_t __stdcall get_Power(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Power());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Power(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Power(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IPowerEaseStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IPowerEaseStatics>
    {
        int32_t __stdcall get_PowerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PowerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IQuadraticEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IQuadraticEase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IQuarticEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IQuarticEase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IQuinticEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IQuinticEase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IReorderThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IReorderThemeTransition>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>
    {
        int32_t __stdcall get_Forever(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().Forever());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromCount(double count, struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().FromCount(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromDuration(int64_t duration, struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().FromDuration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHasCount(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetHasCount(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHasDuration(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior target, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().GetHasDuration(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Equals(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior target, struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior value, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&target), *reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2>
    {
        int32_t __stdcall get_IsStaggeringEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStaggeringEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsStaggeringEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsStaggeringEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2>
    {
        int32_t __stdcall get_IsStaggeringEnabledProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggeringEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISineEase> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISineEase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2>
    {
        int32_t __stdcall get_Effect(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect>(this->shim().Effect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Effect(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Effect(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2>
    {
        int32_t __stdcall get_EffectProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().EffectProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame>
    {
        int32_t __stdcall get_KeySpline(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeySpline>(this->shim().KeySpline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeySpline(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeySpline(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeySpline const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics>
    {
        int32_t __stdcall get_KeySplineProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeySplineProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame>
    {
        int32_t __stdcall get_KeySpline(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeySpline>(this->shim().KeySpline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeySpline(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeySpline(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeySpline const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics>
    {
        int32_t __stdcall get_KeySplineProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeySplineProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame>
    {
        int32_t __stdcall get_KeySpline(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::KeySpline>(this->shim().KeySpline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeySpline(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeySpline(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::KeySpline const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics>
    {
        int32_t __stdcall get_KeySplineProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().KeySplineProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation>
    {
        int32_t __stdcall get_OpenedTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OpenedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpenedTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().OpenedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpenedTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenedTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ClosedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ClosedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ContentTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OpenedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpenedLength(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ClosedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedLength(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetFromCenter(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OffsetFromCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OffsetFromCenter(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OffsetFromCenter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().ContentTranslationDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTranslationDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTranslationDirection(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ContentTranslationOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTranslationOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTranslationOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>
    {
        int32_t __stdcall get_OpenedTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedLengthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedLengthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetFromCenterProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetFromCenterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationDirectionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation>
    {
        int32_t __stdcall get_OpenedTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OpenedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpenedTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().OpenedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpenedTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenedTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ClosedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ClosedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyObject>(this->shim().ContentTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTarget(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OpenedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OpenedLength(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedLength(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ClosedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosedLength(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetFromCenter(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OffsetFromCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OffsetFromCenter(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OffsetFromCenter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().ContentTranslationDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTranslationDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTranslationDirection(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ContentTranslationOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentTranslationOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentTranslationOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>
    {
        int32_t __stdcall get_OpenedTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTargetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OpenedLengthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosedLengthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OffsetFromCenterProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetFromCenterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationDirectionProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentTranslationOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IStoryboard> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IStoryboard>
    {
        int32_t __stdcall get_Children(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::TimelineCollection>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Seek(int64_t offset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Seek(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&offset));
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
        int32_t __stdcall Begin() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Begin();
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
        int32_t __stdcall GetCurrentState(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Media::Animation::ClockState>(this->shim().GetCurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentTime(int64_t* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().GetCurrentTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SeekAlignedToLastTick(int64_t offset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SeekAlignedToLastTick(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SkipToFill() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SkipToFill();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics>
    {
        int32_t __stdcall get_TargetPropertyProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetPropertyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTargetProperty(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetTargetProperty(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Timeline const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetTargetProperty(void* element, void* path) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTargetProperty(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Timeline const*>(&element), *reinterpret_cast<hstring const*>(&path));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTargetName(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetTargetName(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Timeline const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetTargetName(void* element, void* name) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTargetName(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Timeline const*>(&element), *reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetTarget(void* timeline, void* target) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTarget(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::Timeline const*>(&timeline), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FromVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FromVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation>
    {
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToHorizontalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ToHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToHorizontalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToVerticalOffset(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ToVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ToVerticalOffset(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ToVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics>
    {
        int32_t __stdcall get_TargetNameProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToHorizontalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ToHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ToVerticalOffsetProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ToVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ITimeline> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ITimeline>
    {
        int32_t __stdcall get_AutoReverse(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoReverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoReverse(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoReverse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BeginTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().BeginTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BeginTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeginTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(struct struct_Windows_UI_Xaml_Duration* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Duration>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Duration>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(struct struct_Windows_UI_Xaml_Duration value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::UI::Xaml::Duration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeedRatio(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SpeedRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpeedRatio(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpeedRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FillBehavior(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::FillBehavior>(this->shim().FillBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FillBehavior(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FillBehavior(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::FillBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RepeatBehavior(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().RepeatBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RepeatBehavior(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RepeatBehavior(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Completed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Completed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ITimelineFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ITimelineFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Animation::Timeline>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics>
    {
        int32_t __stdcall get_AllowDependentAnimations(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowDependentAnimations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowDependentAnimations(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowDependentAnimations(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoReverseProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AutoReverseProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BeginTimeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().BeginTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DurationProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DurationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeedRatioProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SpeedRatioProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FillBehaviorProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().FillBehaviorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RepeatBehaviorProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RepeatBehaviorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ITransition> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ITransition>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Animation::ITransitionFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Animation::ITransitionFactory>
    {
    };
#endif
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides>
{
    auto GetNavigationStateCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetNavigationStateCore();
        }

        return this->shim().GetNavigationStateCore();
    }
    auto SetNavigationStateCore(hstring const& navigationState)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.SetNavigationStateCore(navigationState);
        }

        return this->shim().SetNavigationStateCore(navigationState);
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Animation
{
    inline AddDeleteThemeTransition::AddDeleteThemeTransition() :
        AddDeleteThemeTransition(impl::call_factory_cast<AddDeleteThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), AddDeleteThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AddDeleteThemeTransition>(); }))
    {
    }
    inline BackEase::BackEase() :
        BackEase(impl::call_factory_cast<BackEase(*)(winrt::Windows::Foundation::IActivationFactory const&), BackEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BackEase>(); }))
    {
    }
    inline auto BackEase::AmplitudeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBackEaseStatics const&), BackEase, IBackEaseStatics>([](IBackEaseStatics const& f) { return f.AmplitudeProperty(); });
    }
    inline BasicConnectedAnimationConfiguration::BasicConnectedAnimationConfiguration()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<BasicConnectedAnimationConfiguration, IBasicConnectedAnimationConfigurationFactory>([&](IBasicConnectedAnimationConfigurationFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline BeginStoryboard::BeginStoryboard() :
        BeginStoryboard(impl::call_factory_cast<BeginStoryboard(*)(winrt::Windows::Foundation::IActivationFactory const&), BeginStoryboard>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BeginStoryboard>(); }))
    {
    }
    inline auto BeginStoryboard::StoryboardProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBeginStoryboardStatics const&), BeginStoryboard, IBeginStoryboardStatics>([](IBeginStoryboardStatics const& f) { return f.StoryboardProperty(); });
    }
    inline BounceEase::BounceEase() :
        BounceEase(impl::call_factory_cast<BounceEase(*)(winrt::Windows::Foundation::IActivationFactory const&), BounceEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BounceEase>(); }))
    {
    }
    inline auto BounceEase::BouncesProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBounceEaseStatics const&), BounceEase, IBounceEaseStatics>([](IBounceEaseStatics const& f) { return f.BouncesProperty(); });
    }
    inline auto BounceEase::BouncinessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBounceEaseStatics const&), BounceEase, IBounceEaseStatics>([](IBounceEaseStatics const& f) { return f.BouncinessProperty(); });
    }
    inline CircleEase::CircleEase() :
        CircleEase(impl::call_factory_cast<CircleEase(*)(winrt::Windows::Foundation::IActivationFactory const&), CircleEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CircleEase>(); }))
    {
    }
    inline ColorAnimation::ColorAnimation() :
        ColorAnimation(impl::call_factory_cast<ColorAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), ColorAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ColorAnimation>(); }))
    {
    }
    inline auto ColorAnimation::FromProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorAnimationStatics const&), ColorAnimation, IColorAnimationStatics>([](IColorAnimationStatics const& f) { return f.FromProperty(); });
    }
    inline auto ColorAnimation::ToProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorAnimationStatics const&), ColorAnimation, IColorAnimationStatics>([](IColorAnimationStatics const& f) { return f.ToProperty(); });
    }
    inline auto ColorAnimation::ByProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorAnimationStatics const&), ColorAnimation, IColorAnimationStatics>([](IColorAnimationStatics const& f) { return f.ByProperty(); });
    }
    inline auto ColorAnimation::EasingFunctionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorAnimationStatics const&), ColorAnimation, IColorAnimationStatics>([](IColorAnimationStatics const& f) { return f.EasingFunctionProperty(); });
    }
    inline auto ColorAnimation::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorAnimationStatics const&), ColorAnimation, IColorAnimationStatics>([](IColorAnimationStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline ColorAnimationUsingKeyFrames::ColorAnimationUsingKeyFrames() :
        ColorAnimationUsingKeyFrames(impl::call_factory_cast<ColorAnimationUsingKeyFrames(*)(winrt::Windows::Foundation::IActivationFactory const&), ColorAnimationUsingKeyFrames>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ColorAnimationUsingKeyFrames>(); }))
    {
    }
    inline auto ColorAnimationUsingKeyFrames::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorAnimationUsingKeyFramesStatics const&), ColorAnimationUsingKeyFrames, IColorAnimationUsingKeyFramesStatics>([](IColorAnimationUsingKeyFramesStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline auto ColorKeyFrame::ValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorKeyFrameStatics const&), ColorKeyFrame, IColorKeyFrameStatics>([](IColorKeyFrameStatics const& f) { return f.ValueProperty(); });
    }
    inline auto ColorKeyFrame::KeyTimeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IColorKeyFrameStatics const&), ColorKeyFrame, IColorKeyFrameStatics>([](IColorKeyFrameStatics const& f) { return f.KeyTimeProperty(); });
    }
    inline ColorKeyFrameCollection::ColorKeyFrameCollection() :
        ColorKeyFrameCollection(impl::call_factory_cast<ColorKeyFrameCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), ColorKeyFrameCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ColorKeyFrameCollection>(); }))
    {
    }
    inline CommonNavigationTransitionInfo::CommonNavigationTransitionInfo() :
        CommonNavigationTransitionInfo(impl::call_factory_cast<CommonNavigationTransitionInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), CommonNavigationTransitionInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CommonNavigationTransitionInfo>(); }))
    {
    }
    inline auto CommonNavigationTransitionInfo::IsStaggeringEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICommonNavigationTransitionInfoStatics const&), CommonNavigationTransitionInfo, ICommonNavigationTransitionInfoStatics>([](ICommonNavigationTransitionInfoStatics const& f) { return f.IsStaggeringEnabledProperty(); });
    }
    inline auto CommonNavigationTransitionInfo::IsStaggerElementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICommonNavigationTransitionInfoStatics const&), CommonNavigationTransitionInfo, ICommonNavigationTransitionInfoStatics>([](ICommonNavigationTransitionInfoStatics const& f) { return f.IsStaggerElementProperty(); });
    }
    inline auto CommonNavigationTransitionInfo::GetIsStaggerElement(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<CommonNavigationTransitionInfo, ICommonNavigationTransitionInfoStatics>([&](ICommonNavigationTransitionInfoStatics const& f) { return f.GetIsStaggerElement(element); });
    }
    inline auto CommonNavigationTransitionInfo::SetIsStaggerElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value)
    {
        impl::call_factory<CommonNavigationTransitionInfo, ICommonNavigationTransitionInfoStatics>([&](ICommonNavigationTransitionInfoStatics const& f) { return f.SetIsStaggerElement(element, value); });
    }
    inline auto ConnectedAnimationService::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService(*)(IConnectedAnimationServiceStatics const&), ConnectedAnimationService, IConnectedAnimationServiceStatics>([](IConnectedAnimationServiceStatics const& f) { return f.GetForCurrentView(); });
    }
    inline ContentThemeTransition::ContentThemeTransition() :
        ContentThemeTransition(impl::call_factory_cast<ContentThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), ContentThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContentThemeTransition>(); }))
    {
    }
    inline auto ContentThemeTransition::HorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentThemeTransitionStatics const&), ContentThemeTransition, IContentThemeTransitionStatics>([](IContentThemeTransitionStatics const& f) { return f.HorizontalOffsetProperty(); });
    }
    inline auto ContentThemeTransition::VerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContentThemeTransitionStatics const&), ContentThemeTransition, IContentThemeTransitionStatics>([](IContentThemeTransitionStatics const& f) { return f.VerticalOffsetProperty(); });
    }
    inline ContinuumNavigationTransitionInfo::ContinuumNavigationTransitionInfo() :
        ContinuumNavigationTransitionInfo(impl::call_factory_cast<ContinuumNavigationTransitionInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), ContinuumNavigationTransitionInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContinuumNavigationTransitionInfo>(); }))
    {
    }
    inline auto ContinuumNavigationTransitionInfo::ExitElementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContinuumNavigationTransitionInfoStatics const&), ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([](IContinuumNavigationTransitionInfoStatics const& f) { return f.ExitElementProperty(); });
    }
    inline auto ContinuumNavigationTransitionInfo::IsEntranceElementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContinuumNavigationTransitionInfoStatics const&), ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([](IContinuumNavigationTransitionInfoStatics const& f) { return f.IsEntranceElementProperty(); });
    }
    inline auto ContinuumNavigationTransitionInfo::GetIsEntranceElement(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([&](IContinuumNavigationTransitionInfoStatics const& f) { return f.GetIsEntranceElement(element); });
    }
    inline auto ContinuumNavigationTransitionInfo::SetIsEntranceElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value)
    {
        impl::call_factory<ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([&](IContinuumNavigationTransitionInfoStatics const& f) { return f.SetIsEntranceElement(element, value); });
    }
    inline auto ContinuumNavigationTransitionInfo::IsExitElementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContinuumNavigationTransitionInfoStatics const&), ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([](IContinuumNavigationTransitionInfoStatics const& f) { return f.IsExitElementProperty(); });
    }
    inline auto ContinuumNavigationTransitionInfo::GetIsExitElement(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([&](IContinuumNavigationTransitionInfoStatics const& f) { return f.GetIsExitElement(element); });
    }
    inline auto ContinuumNavigationTransitionInfo::SetIsExitElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value)
    {
        impl::call_factory<ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([&](IContinuumNavigationTransitionInfoStatics const& f) { return f.SetIsExitElement(element, value); });
    }
    inline auto ContinuumNavigationTransitionInfo::ExitElementContainerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IContinuumNavigationTransitionInfoStatics const&), ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([](IContinuumNavigationTransitionInfoStatics const& f) { return f.ExitElementContainerProperty(); });
    }
    inline auto ContinuumNavigationTransitionInfo::GetExitElementContainer(winrt::Windows::UI::Xaml::Controls::ListViewBase const& element)
    {
        return impl::call_factory<ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([&](IContinuumNavigationTransitionInfoStatics const& f) { return f.GetExitElementContainer(element); });
    }
    inline auto ContinuumNavigationTransitionInfo::SetExitElementContainer(winrt::Windows::UI::Xaml::Controls::ListViewBase const& element, bool value)
    {
        impl::call_factory<ContinuumNavigationTransitionInfo, IContinuumNavigationTransitionInfoStatics>([&](IContinuumNavigationTransitionInfoStatics const& f) { return f.SetExitElementContainer(element, value); });
    }
    inline CubicEase::CubicEase() :
        CubicEase(impl::call_factory_cast<CubicEase(*)(winrt::Windows::Foundation::IActivationFactory const&), CubicEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CubicEase>(); }))
    {
    }
    inline DirectConnectedAnimationConfiguration::DirectConnectedAnimationConfiguration()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DirectConnectedAnimationConfiguration, IDirectConnectedAnimationConfigurationFactory>([&](IDirectConnectedAnimationConfigurationFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline DiscreteColorKeyFrame::DiscreteColorKeyFrame() :
        DiscreteColorKeyFrame(impl::call_factory_cast<DiscreteColorKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), DiscreteColorKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DiscreteColorKeyFrame>(); }))
    {
    }
    inline DiscreteDoubleKeyFrame::DiscreteDoubleKeyFrame() :
        DiscreteDoubleKeyFrame(impl::call_factory_cast<DiscreteDoubleKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), DiscreteDoubleKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DiscreteDoubleKeyFrame>(); }))
    {
    }
    inline DiscreteObjectKeyFrame::DiscreteObjectKeyFrame() :
        DiscreteObjectKeyFrame(impl::call_factory_cast<DiscreteObjectKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), DiscreteObjectKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DiscreteObjectKeyFrame>(); }))
    {
    }
    inline DiscretePointKeyFrame::DiscretePointKeyFrame() :
        DiscretePointKeyFrame(impl::call_factory_cast<DiscretePointKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), DiscretePointKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DiscretePointKeyFrame>(); }))
    {
    }
    inline DoubleAnimation::DoubleAnimation() :
        DoubleAnimation(impl::call_factory_cast<DoubleAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), DoubleAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DoubleAnimation>(); }))
    {
    }
    inline auto DoubleAnimation::FromProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleAnimationStatics const&), DoubleAnimation, IDoubleAnimationStatics>([](IDoubleAnimationStatics const& f) { return f.FromProperty(); });
    }
    inline auto DoubleAnimation::ToProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleAnimationStatics const&), DoubleAnimation, IDoubleAnimationStatics>([](IDoubleAnimationStatics const& f) { return f.ToProperty(); });
    }
    inline auto DoubleAnimation::ByProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleAnimationStatics const&), DoubleAnimation, IDoubleAnimationStatics>([](IDoubleAnimationStatics const& f) { return f.ByProperty(); });
    }
    inline auto DoubleAnimation::EasingFunctionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleAnimationStatics const&), DoubleAnimation, IDoubleAnimationStatics>([](IDoubleAnimationStatics const& f) { return f.EasingFunctionProperty(); });
    }
    inline auto DoubleAnimation::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleAnimationStatics const&), DoubleAnimation, IDoubleAnimationStatics>([](IDoubleAnimationStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline DoubleAnimationUsingKeyFrames::DoubleAnimationUsingKeyFrames() :
        DoubleAnimationUsingKeyFrames(impl::call_factory_cast<DoubleAnimationUsingKeyFrames(*)(winrt::Windows::Foundation::IActivationFactory const&), DoubleAnimationUsingKeyFrames>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DoubleAnimationUsingKeyFrames>(); }))
    {
    }
    inline auto DoubleAnimationUsingKeyFrames::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleAnimationUsingKeyFramesStatics const&), DoubleAnimationUsingKeyFrames, IDoubleAnimationUsingKeyFramesStatics>([](IDoubleAnimationUsingKeyFramesStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline auto DoubleKeyFrame::ValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleKeyFrameStatics const&), DoubleKeyFrame, IDoubleKeyFrameStatics>([](IDoubleKeyFrameStatics const& f) { return f.ValueProperty(); });
    }
    inline auto DoubleKeyFrame::KeyTimeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDoubleKeyFrameStatics const&), DoubleKeyFrame, IDoubleKeyFrameStatics>([](IDoubleKeyFrameStatics const& f) { return f.KeyTimeProperty(); });
    }
    inline DoubleKeyFrameCollection::DoubleKeyFrameCollection() :
        DoubleKeyFrameCollection(impl::call_factory_cast<DoubleKeyFrameCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), DoubleKeyFrameCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DoubleKeyFrameCollection>(); }))
    {
    }
    inline DragItemThemeAnimation::DragItemThemeAnimation() :
        DragItemThemeAnimation(impl::call_factory_cast<DragItemThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), DragItemThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DragItemThemeAnimation>(); }))
    {
    }
    inline auto DragItemThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDragItemThemeAnimationStatics const&), DragItemThemeAnimation, IDragItemThemeAnimationStatics>([](IDragItemThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline DragOverThemeAnimation::DragOverThemeAnimation() :
        DragOverThemeAnimation(impl::call_factory_cast<DragOverThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), DragOverThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DragOverThemeAnimation>(); }))
    {
    }
    inline auto DragOverThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDragOverThemeAnimationStatics const&), DragOverThemeAnimation, IDragOverThemeAnimationStatics>([](IDragOverThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline auto DragOverThemeAnimation::ToOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDragOverThemeAnimationStatics const&), DragOverThemeAnimation, IDragOverThemeAnimationStatics>([](IDragOverThemeAnimationStatics const& f) { return f.ToOffsetProperty(); });
    }
    inline auto DragOverThemeAnimation::DirectionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDragOverThemeAnimationStatics const&), DragOverThemeAnimation, IDragOverThemeAnimationStatics>([](IDragOverThemeAnimationStatics const& f) { return f.DirectionProperty(); });
    }
    inline DrillInNavigationTransitionInfo::DrillInNavigationTransitionInfo() :
        DrillInNavigationTransitionInfo(impl::call_factory_cast<DrillInNavigationTransitionInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), DrillInNavigationTransitionInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DrillInNavigationTransitionInfo>(); }))
    {
    }
    inline DrillInThemeAnimation::DrillInThemeAnimation() :
        DrillInThemeAnimation(impl::call_factory_cast<DrillInThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), DrillInThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DrillInThemeAnimation>(); }))
    {
    }
    inline auto DrillInThemeAnimation::EntranceTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillInThemeAnimationStatics const&), DrillInThemeAnimation, IDrillInThemeAnimationStatics>([](IDrillInThemeAnimationStatics const& f) { return f.EntranceTargetNameProperty(); });
    }
    inline auto DrillInThemeAnimation::EntranceTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillInThemeAnimationStatics const&), DrillInThemeAnimation, IDrillInThemeAnimationStatics>([](IDrillInThemeAnimationStatics const& f) { return f.EntranceTargetProperty(); });
    }
    inline auto DrillInThemeAnimation::ExitTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillInThemeAnimationStatics const&), DrillInThemeAnimation, IDrillInThemeAnimationStatics>([](IDrillInThemeAnimationStatics const& f) { return f.ExitTargetNameProperty(); });
    }
    inline auto DrillInThemeAnimation::ExitTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillInThemeAnimationStatics const&), DrillInThemeAnimation, IDrillInThemeAnimationStatics>([](IDrillInThemeAnimationStatics const& f) { return f.ExitTargetProperty(); });
    }
    inline DrillOutThemeAnimation::DrillOutThemeAnimation() :
        DrillOutThemeAnimation(impl::call_factory_cast<DrillOutThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), DrillOutThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DrillOutThemeAnimation>(); }))
    {
    }
    inline auto DrillOutThemeAnimation::EntranceTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillOutThemeAnimationStatics const&), DrillOutThemeAnimation, IDrillOutThemeAnimationStatics>([](IDrillOutThemeAnimationStatics const& f) { return f.EntranceTargetNameProperty(); });
    }
    inline auto DrillOutThemeAnimation::EntranceTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillOutThemeAnimationStatics const&), DrillOutThemeAnimation, IDrillOutThemeAnimationStatics>([](IDrillOutThemeAnimationStatics const& f) { return f.EntranceTargetProperty(); });
    }
    inline auto DrillOutThemeAnimation::ExitTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillOutThemeAnimationStatics const&), DrillOutThemeAnimation, IDrillOutThemeAnimationStatics>([](IDrillOutThemeAnimationStatics const& f) { return f.ExitTargetNameProperty(); });
    }
    inline auto DrillOutThemeAnimation::ExitTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDrillOutThemeAnimationStatics const&), DrillOutThemeAnimation, IDrillOutThemeAnimationStatics>([](IDrillOutThemeAnimationStatics const& f) { return f.ExitTargetProperty(); });
    }
    inline DropTargetItemThemeAnimation::DropTargetItemThemeAnimation() :
        DropTargetItemThemeAnimation(impl::call_factory_cast<DropTargetItemThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), DropTargetItemThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DropTargetItemThemeAnimation>(); }))
    {
    }
    inline auto DropTargetItemThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IDropTargetItemThemeAnimationStatics const&), DropTargetItemThemeAnimation, IDropTargetItemThemeAnimationStatics>([](IDropTargetItemThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline EasingColorKeyFrame::EasingColorKeyFrame() :
        EasingColorKeyFrame(impl::call_factory_cast<EasingColorKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), EasingColorKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EasingColorKeyFrame>(); }))
    {
    }
    inline auto EasingColorKeyFrame::EasingFunctionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEasingColorKeyFrameStatics const&), EasingColorKeyFrame, IEasingColorKeyFrameStatics>([](IEasingColorKeyFrameStatics const& f) { return f.EasingFunctionProperty(); });
    }
    inline EasingDoubleKeyFrame::EasingDoubleKeyFrame() :
        EasingDoubleKeyFrame(impl::call_factory_cast<EasingDoubleKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), EasingDoubleKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EasingDoubleKeyFrame>(); }))
    {
    }
    inline auto EasingDoubleKeyFrame::EasingFunctionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEasingDoubleKeyFrameStatics const&), EasingDoubleKeyFrame, IEasingDoubleKeyFrameStatics>([](IEasingDoubleKeyFrameStatics const& f) { return f.EasingFunctionProperty(); });
    }
    inline auto EasingFunctionBase::EasingModeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEasingFunctionBaseStatics const&), EasingFunctionBase, IEasingFunctionBaseStatics>([](IEasingFunctionBaseStatics const& f) { return f.EasingModeProperty(); });
    }
    inline EasingPointKeyFrame::EasingPointKeyFrame() :
        EasingPointKeyFrame(impl::call_factory_cast<EasingPointKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), EasingPointKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EasingPointKeyFrame>(); }))
    {
    }
    inline auto EasingPointKeyFrame::EasingFunctionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEasingPointKeyFrameStatics const&), EasingPointKeyFrame, IEasingPointKeyFrameStatics>([](IEasingPointKeyFrameStatics const& f) { return f.EasingFunctionProperty(); });
    }
    inline EdgeUIThemeTransition::EdgeUIThemeTransition() :
        EdgeUIThemeTransition(impl::call_factory_cast<EdgeUIThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), EdgeUIThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EdgeUIThemeTransition>(); }))
    {
    }
    inline auto EdgeUIThemeTransition::EdgeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEdgeUIThemeTransitionStatics const&), EdgeUIThemeTransition, IEdgeUIThemeTransitionStatics>([](IEdgeUIThemeTransitionStatics const& f) { return f.EdgeProperty(); });
    }
    inline ElasticEase::ElasticEase() :
        ElasticEase(impl::call_factory_cast<ElasticEase(*)(winrt::Windows::Foundation::IActivationFactory const&), ElasticEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ElasticEase>(); }))
    {
    }
    inline auto ElasticEase::OscillationsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IElasticEaseStatics const&), ElasticEase, IElasticEaseStatics>([](IElasticEaseStatics const& f) { return f.OscillationsProperty(); });
    }
    inline auto ElasticEase::SpringinessProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IElasticEaseStatics const&), ElasticEase, IElasticEaseStatics>([](IElasticEaseStatics const& f) { return f.SpringinessProperty(); });
    }
    inline EntranceNavigationTransitionInfo::EntranceNavigationTransitionInfo() :
        EntranceNavigationTransitionInfo(impl::call_factory_cast<EntranceNavigationTransitionInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), EntranceNavigationTransitionInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EntranceNavigationTransitionInfo>(); }))
    {
    }
    inline auto EntranceNavigationTransitionInfo::IsTargetElementProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEntranceNavigationTransitionInfoStatics const&), EntranceNavigationTransitionInfo, IEntranceNavigationTransitionInfoStatics>([](IEntranceNavigationTransitionInfoStatics const& f) { return f.IsTargetElementProperty(); });
    }
    inline auto EntranceNavigationTransitionInfo::GetIsTargetElement(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<EntranceNavigationTransitionInfo, IEntranceNavigationTransitionInfoStatics>([&](IEntranceNavigationTransitionInfoStatics const& f) { return f.GetIsTargetElement(element); });
    }
    inline auto EntranceNavigationTransitionInfo::SetIsTargetElement(winrt::Windows::UI::Xaml::UIElement const& element, bool value)
    {
        impl::call_factory<EntranceNavigationTransitionInfo, IEntranceNavigationTransitionInfoStatics>([&](IEntranceNavigationTransitionInfoStatics const& f) { return f.SetIsTargetElement(element, value); });
    }
    inline EntranceThemeTransition::EntranceThemeTransition() :
        EntranceThemeTransition(impl::call_factory_cast<EntranceThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), EntranceThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<EntranceThemeTransition>(); }))
    {
    }
    inline auto EntranceThemeTransition::FromHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEntranceThemeTransitionStatics const&), EntranceThemeTransition, IEntranceThemeTransitionStatics>([](IEntranceThemeTransitionStatics const& f) { return f.FromHorizontalOffsetProperty(); });
    }
    inline auto EntranceThemeTransition::FromVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEntranceThemeTransitionStatics const&), EntranceThemeTransition, IEntranceThemeTransitionStatics>([](IEntranceThemeTransitionStatics const& f) { return f.FromVerticalOffsetProperty(); });
    }
    inline auto EntranceThemeTransition::IsStaggeringEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IEntranceThemeTransitionStatics const&), EntranceThemeTransition, IEntranceThemeTransitionStatics>([](IEntranceThemeTransitionStatics const& f) { return f.IsStaggeringEnabledProperty(); });
    }
    inline ExponentialEase::ExponentialEase() :
        ExponentialEase(impl::call_factory_cast<ExponentialEase(*)(winrt::Windows::Foundation::IActivationFactory const&), ExponentialEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ExponentialEase>(); }))
    {
    }
    inline auto ExponentialEase::ExponentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IExponentialEaseStatics const&), ExponentialEase, IExponentialEaseStatics>([](IExponentialEaseStatics const& f) { return f.ExponentProperty(); });
    }
    inline FadeInThemeAnimation::FadeInThemeAnimation() :
        FadeInThemeAnimation(impl::call_factory_cast<FadeInThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), FadeInThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FadeInThemeAnimation>(); }))
    {
    }
    inline auto FadeInThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFadeInThemeAnimationStatics const&), FadeInThemeAnimation, IFadeInThemeAnimationStatics>([](IFadeInThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline FadeOutThemeAnimation::FadeOutThemeAnimation() :
        FadeOutThemeAnimation(impl::call_factory_cast<FadeOutThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), FadeOutThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FadeOutThemeAnimation>(); }))
    {
    }
    inline auto FadeOutThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IFadeOutThemeAnimationStatics const&), FadeOutThemeAnimation, IFadeOutThemeAnimationStatics>([](IFadeOutThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline GravityConnectedAnimationConfiguration::GravityConnectedAnimationConfiguration()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GravityConnectedAnimationConfiguration, IGravityConnectedAnimationConfigurationFactory>([&](IGravityConnectedAnimationConfigurationFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline KeySpline::KeySpline() :
        KeySpline(impl::call_factory_cast<KeySpline(*)(winrt::Windows::Foundation::IActivationFactory const&), KeySpline>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<KeySpline>(); }))
    {
    }
    inline auto KeyTimeHelper::FromTimeSpan(winrt::Windows::Foundation::TimeSpan const& timeSpan)
    {
        return impl::call_factory<KeyTimeHelper, IKeyTimeHelperStatics>([&](IKeyTimeHelperStatics const& f) { return f.FromTimeSpan(timeSpan); });
    }
    inline LinearColorKeyFrame::LinearColorKeyFrame() :
        LinearColorKeyFrame(impl::call_factory_cast<LinearColorKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), LinearColorKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LinearColorKeyFrame>(); }))
    {
    }
    inline LinearDoubleKeyFrame::LinearDoubleKeyFrame() :
        LinearDoubleKeyFrame(impl::call_factory_cast<LinearDoubleKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), LinearDoubleKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LinearDoubleKeyFrame>(); }))
    {
    }
    inline LinearPointKeyFrame::LinearPointKeyFrame() :
        LinearPointKeyFrame(impl::call_factory_cast<LinearPointKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), LinearPointKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<LinearPointKeyFrame>(); }))
    {
    }
    inline NavigationThemeTransition::NavigationThemeTransition() :
        NavigationThemeTransition(impl::call_factory_cast<NavigationThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), NavigationThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NavigationThemeTransition>(); }))
    {
    }
    inline auto NavigationThemeTransition::DefaultNavigationTransitionInfoProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(INavigationThemeTransitionStatics const&), NavigationThemeTransition, INavigationThemeTransitionStatics>([](INavigationThemeTransitionStatics const& f) { return f.DefaultNavigationTransitionInfoProperty(); });
    }
    inline ObjectAnimationUsingKeyFrames::ObjectAnimationUsingKeyFrames() :
        ObjectAnimationUsingKeyFrames(impl::call_factory_cast<ObjectAnimationUsingKeyFrames(*)(winrt::Windows::Foundation::IActivationFactory const&), ObjectAnimationUsingKeyFrames>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ObjectAnimationUsingKeyFrames>(); }))
    {
    }
    inline auto ObjectAnimationUsingKeyFrames::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IObjectAnimationUsingKeyFramesStatics const&), ObjectAnimationUsingKeyFrames, IObjectAnimationUsingKeyFramesStatics>([](IObjectAnimationUsingKeyFramesStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline auto ObjectKeyFrame::ValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IObjectKeyFrameStatics const&), ObjectKeyFrame, IObjectKeyFrameStatics>([](IObjectKeyFrameStatics const& f) { return f.ValueProperty(); });
    }
    inline auto ObjectKeyFrame::KeyTimeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IObjectKeyFrameStatics const&), ObjectKeyFrame, IObjectKeyFrameStatics>([](IObjectKeyFrameStatics const& f) { return f.KeyTimeProperty(); });
    }
    inline ObjectKeyFrameCollection::ObjectKeyFrameCollection() :
        ObjectKeyFrameCollection(impl::call_factory_cast<ObjectKeyFrameCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), ObjectKeyFrameCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ObjectKeyFrameCollection>(); }))
    {
    }
    inline PaneThemeTransition::PaneThemeTransition() :
        PaneThemeTransition(impl::call_factory_cast<PaneThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), PaneThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PaneThemeTransition>(); }))
    {
    }
    inline auto PaneThemeTransition::EdgeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPaneThemeTransitionStatics const&), PaneThemeTransition, IPaneThemeTransitionStatics>([](IPaneThemeTransitionStatics const& f) { return f.EdgeProperty(); });
    }
    inline PointAnimation::PointAnimation() :
        PointAnimation(impl::call_factory_cast<PointAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), PointAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PointAnimation>(); }))
    {
    }
    inline auto PointAnimation::FromProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointAnimationStatics const&), PointAnimation, IPointAnimationStatics>([](IPointAnimationStatics const& f) { return f.FromProperty(); });
    }
    inline auto PointAnimation::ToProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointAnimationStatics const&), PointAnimation, IPointAnimationStatics>([](IPointAnimationStatics const& f) { return f.ToProperty(); });
    }
    inline auto PointAnimation::ByProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointAnimationStatics const&), PointAnimation, IPointAnimationStatics>([](IPointAnimationStatics const& f) { return f.ByProperty(); });
    }
    inline auto PointAnimation::EasingFunctionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointAnimationStatics const&), PointAnimation, IPointAnimationStatics>([](IPointAnimationStatics const& f) { return f.EasingFunctionProperty(); });
    }
    inline auto PointAnimation::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointAnimationStatics const&), PointAnimation, IPointAnimationStatics>([](IPointAnimationStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline PointAnimationUsingKeyFrames::PointAnimationUsingKeyFrames() :
        PointAnimationUsingKeyFrames(impl::call_factory_cast<PointAnimationUsingKeyFrames(*)(winrt::Windows::Foundation::IActivationFactory const&), PointAnimationUsingKeyFrames>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PointAnimationUsingKeyFrames>(); }))
    {
    }
    inline auto PointAnimationUsingKeyFrames::EnableDependentAnimationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointAnimationUsingKeyFramesStatics const&), PointAnimationUsingKeyFrames, IPointAnimationUsingKeyFramesStatics>([](IPointAnimationUsingKeyFramesStatics const& f) { return f.EnableDependentAnimationProperty(); });
    }
    inline auto PointKeyFrame::ValueProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointKeyFrameStatics const&), PointKeyFrame, IPointKeyFrameStatics>([](IPointKeyFrameStatics const& f) { return f.ValueProperty(); });
    }
    inline auto PointKeyFrame::KeyTimeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointKeyFrameStatics const&), PointKeyFrame, IPointKeyFrameStatics>([](IPointKeyFrameStatics const& f) { return f.KeyTimeProperty(); });
    }
    inline PointKeyFrameCollection::PointKeyFrameCollection() :
        PointKeyFrameCollection(impl::call_factory_cast<PointKeyFrameCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), PointKeyFrameCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PointKeyFrameCollection>(); }))
    {
    }
    inline PointerDownThemeAnimation::PointerDownThemeAnimation() :
        PointerDownThemeAnimation(impl::call_factory_cast<PointerDownThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), PointerDownThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PointerDownThemeAnimation>(); }))
    {
    }
    inline auto PointerDownThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointerDownThemeAnimationStatics const&), PointerDownThemeAnimation, IPointerDownThemeAnimationStatics>([](IPointerDownThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline PointerUpThemeAnimation::PointerUpThemeAnimation() :
        PointerUpThemeAnimation(impl::call_factory_cast<PointerUpThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), PointerUpThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PointerUpThemeAnimation>(); }))
    {
    }
    inline auto PointerUpThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPointerUpThemeAnimationStatics const&), PointerUpThemeAnimation, IPointerUpThemeAnimationStatics>([](IPointerUpThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline PopInThemeAnimation::PopInThemeAnimation() :
        PopInThemeAnimation(impl::call_factory_cast<PopInThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), PopInThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PopInThemeAnimation>(); }))
    {
    }
    inline auto PopInThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopInThemeAnimationStatics const&), PopInThemeAnimation, IPopInThemeAnimationStatics>([](IPopInThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline auto PopInThemeAnimation::FromHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopInThemeAnimationStatics const&), PopInThemeAnimation, IPopInThemeAnimationStatics>([](IPopInThemeAnimationStatics const& f) { return f.FromHorizontalOffsetProperty(); });
    }
    inline auto PopInThemeAnimation::FromVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopInThemeAnimationStatics const&), PopInThemeAnimation, IPopInThemeAnimationStatics>([](IPopInThemeAnimationStatics const& f) { return f.FromVerticalOffsetProperty(); });
    }
    inline PopOutThemeAnimation::PopOutThemeAnimation() :
        PopOutThemeAnimation(impl::call_factory_cast<PopOutThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), PopOutThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PopOutThemeAnimation>(); }))
    {
    }
    inline auto PopOutThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopOutThemeAnimationStatics const&), PopOutThemeAnimation, IPopOutThemeAnimationStatics>([](IPopOutThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline PopupThemeTransition::PopupThemeTransition() :
        PopupThemeTransition(impl::call_factory_cast<PopupThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), PopupThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PopupThemeTransition>(); }))
    {
    }
    inline auto PopupThemeTransition::FromHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupThemeTransitionStatics const&), PopupThemeTransition, IPopupThemeTransitionStatics>([](IPopupThemeTransitionStatics const& f) { return f.FromHorizontalOffsetProperty(); });
    }
    inline auto PopupThemeTransition::FromVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPopupThemeTransitionStatics const&), PopupThemeTransition, IPopupThemeTransitionStatics>([](IPopupThemeTransitionStatics const& f) { return f.FromVerticalOffsetProperty(); });
    }
    inline PowerEase::PowerEase() :
        PowerEase(impl::call_factory_cast<PowerEase(*)(winrt::Windows::Foundation::IActivationFactory const&), PowerEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PowerEase>(); }))
    {
    }
    inline auto PowerEase::PowerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IPowerEaseStatics const&), PowerEase, IPowerEaseStatics>([](IPowerEaseStatics const& f) { return f.PowerProperty(); });
    }
    inline QuadraticEase::QuadraticEase() :
        QuadraticEase(impl::call_factory_cast<QuadraticEase(*)(winrt::Windows::Foundation::IActivationFactory const&), QuadraticEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<QuadraticEase>(); }))
    {
    }
    inline QuarticEase::QuarticEase() :
        QuarticEase(impl::call_factory_cast<QuarticEase(*)(winrt::Windows::Foundation::IActivationFactory const&), QuarticEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<QuarticEase>(); }))
    {
    }
    inline QuinticEase::QuinticEase() :
        QuinticEase(impl::call_factory_cast<QuinticEase(*)(winrt::Windows::Foundation::IActivationFactory const&), QuinticEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<QuinticEase>(); }))
    {
    }
    inline ReorderThemeTransition::ReorderThemeTransition() :
        ReorderThemeTransition(impl::call_factory_cast<ReorderThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), ReorderThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ReorderThemeTransition>(); }))
    {
    }
    inline auto RepeatBehaviorHelper::Forever()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior(*)(IRepeatBehaviorHelperStatics const&), RepeatBehaviorHelper, IRepeatBehaviorHelperStatics>([](IRepeatBehaviorHelperStatics const& f) { return f.Forever(); });
    }
    inline auto RepeatBehaviorHelper::FromCount(double count)
    {
        return impl::call_factory<RepeatBehaviorHelper, IRepeatBehaviorHelperStatics>([&](IRepeatBehaviorHelperStatics const& f) { return f.FromCount(count); });
    }
    inline auto RepeatBehaviorHelper::FromDuration(winrt::Windows::Foundation::TimeSpan const& duration)
    {
        return impl::call_factory<RepeatBehaviorHelper, IRepeatBehaviorHelperStatics>([&](IRepeatBehaviorHelperStatics const& f) { return f.FromDuration(duration); });
    }
    inline auto RepeatBehaviorHelper::GetHasCount(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target)
    {
        return impl::call_factory<RepeatBehaviorHelper, IRepeatBehaviorHelperStatics>([&](IRepeatBehaviorHelperStatics const& f) { return f.GetHasCount(target); });
    }
    inline auto RepeatBehaviorHelper::GetHasDuration(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target)
    {
        return impl::call_factory<RepeatBehaviorHelper, IRepeatBehaviorHelperStatics>([&](IRepeatBehaviorHelperStatics const& f) { return f.GetHasDuration(target); });
    }
    inline auto RepeatBehaviorHelper::Equals(winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target, winrt::Windows::UI::Xaml::Media::Animation::RepeatBehavior const& value)
    {
        return impl::call_factory<RepeatBehaviorHelper, IRepeatBehaviorHelperStatics>([&](IRepeatBehaviorHelperStatics const& f) { return f.Equals(target, value); });
    }
    inline RepositionThemeAnimation::RepositionThemeAnimation() :
        RepositionThemeAnimation(impl::call_factory_cast<RepositionThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), RepositionThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RepositionThemeAnimation>(); }))
    {
    }
    inline auto RepositionThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRepositionThemeAnimationStatics const&), RepositionThemeAnimation, IRepositionThemeAnimationStatics>([](IRepositionThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline auto RepositionThemeAnimation::FromHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRepositionThemeAnimationStatics const&), RepositionThemeAnimation, IRepositionThemeAnimationStatics>([](IRepositionThemeAnimationStatics const& f) { return f.FromHorizontalOffsetProperty(); });
    }
    inline auto RepositionThemeAnimation::FromVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRepositionThemeAnimationStatics const&), RepositionThemeAnimation, IRepositionThemeAnimationStatics>([](IRepositionThemeAnimationStatics const& f) { return f.FromVerticalOffsetProperty(); });
    }
    inline RepositionThemeTransition::RepositionThemeTransition() :
        RepositionThemeTransition(impl::call_factory_cast<RepositionThemeTransition(*)(winrt::Windows::Foundation::IActivationFactory const&), RepositionThemeTransition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RepositionThemeTransition>(); }))
    {
    }
    inline auto RepositionThemeTransition::IsStaggeringEnabledProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRepositionThemeTransitionStatics2 const&), RepositionThemeTransition, IRepositionThemeTransitionStatics2>([](IRepositionThemeTransitionStatics2 const& f) { return f.IsStaggeringEnabledProperty(); });
    }
    inline SineEase::SineEase() :
        SineEase(impl::call_factory_cast<SineEase(*)(winrt::Windows::Foundation::IActivationFactory const&), SineEase>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SineEase>(); }))
    {
    }
    inline SlideNavigationTransitionInfo::SlideNavigationTransitionInfo() :
        SlideNavigationTransitionInfo(impl::call_factory_cast<SlideNavigationTransitionInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), SlideNavigationTransitionInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SlideNavigationTransitionInfo>(); }))
    {
    }
    inline auto SlideNavigationTransitionInfo::EffectProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISlideNavigationTransitionInfoStatics2 const&), SlideNavigationTransitionInfo, ISlideNavigationTransitionInfoStatics2>([](ISlideNavigationTransitionInfoStatics2 const& f) { return f.EffectProperty(); });
    }
    inline SplineColorKeyFrame::SplineColorKeyFrame() :
        SplineColorKeyFrame(impl::call_factory_cast<SplineColorKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), SplineColorKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SplineColorKeyFrame>(); }))
    {
    }
    inline auto SplineColorKeyFrame::KeySplineProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplineColorKeyFrameStatics const&), SplineColorKeyFrame, ISplineColorKeyFrameStatics>([](ISplineColorKeyFrameStatics const& f) { return f.KeySplineProperty(); });
    }
    inline SplineDoubleKeyFrame::SplineDoubleKeyFrame() :
        SplineDoubleKeyFrame(impl::call_factory_cast<SplineDoubleKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), SplineDoubleKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SplineDoubleKeyFrame>(); }))
    {
    }
    inline auto SplineDoubleKeyFrame::KeySplineProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplineDoubleKeyFrameStatics const&), SplineDoubleKeyFrame, ISplineDoubleKeyFrameStatics>([](ISplineDoubleKeyFrameStatics const& f) { return f.KeySplineProperty(); });
    }
    inline SplinePointKeyFrame::SplinePointKeyFrame() :
        SplinePointKeyFrame(impl::call_factory_cast<SplinePointKeyFrame(*)(winrt::Windows::Foundation::IActivationFactory const&), SplinePointKeyFrame>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SplinePointKeyFrame>(); }))
    {
    }
    inline auto SplinePointKeyFrame::KeySplineProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplinePointKeyFrameStatics const&), SplinePointKeyFrame, ISplinePointKeyFrameStatics>([](ISplinePointKeyFrameStatics const& f) { return f.KeySplineProperty(); });
    }
    inline SplitCloseThemeAnimation::SplitCloseThemeAnimation() :
        SplitCloseThemeAnimation(impl::call_factory_cast<SplitCloseThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), SplitCloseThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SplitCloseThemeAnimation>(); }))
    {
    }
    inline auto SplitCloseThemeAnimation::OpenedTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.OpenedTargetNameProperty(); });
    }
    inline auto SplitCloseThemeAnimation::OpenedTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.OpenedTargetProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ClosedTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ClosedTargetNameProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ClosedTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ClosedTargetProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ContentTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ContentTargetNameProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ContentTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ContentTargetProperty(); });
    }
    inline auto SplitCloseThemeAnimation::OpenedLengthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.OpenedLengthProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ClosedLengthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ClosedLengthProperty(); });
    }
    inline auto SplitCloseThemeAnimation::OffsetFromCenterProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.OffsetFromCenterProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ContentTranslationDirectionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ContentTranslationDirectionProperty(); });
    }
    inline auto SplitCloseThemeAnimation::ContentTranslationOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitCloseThemeAnimationStatics const&), SplitCloseThemeAnimation, ISplitCloseThemeAnimationStatics>([](ISplitCloseThemeAnimationStatics const& f) { return f.ContentTranslationOffsetProperty(); });
    }
    inline SplitOpenThemeAnimation::SplitOpenThemeAnimation() :
        SplitOpenThemeAnimation(impl::call_factory_cast<SplitOpenThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), SplitOpenThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SplitOpenThemeAnimation>(); }))
    {
    }
    inline auto SplitOpenThemeAnimation::OpenedTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.OpenedTargetNameProperty(); });
    }
    inline auto SplitOpenThemeAnimation::OpenedTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.OpenedTargetProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ClosedTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ClosedTargetNameProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ClosedTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ClosedTargetProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ContentTargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ContentTargetNameProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ContentTargetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ContentTargetProperty(); });
    }
    inline auto SplitOpenThemeAnimation::OpenedLengthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.OpenedLengthProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ClosedLengthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ClosedLengthProperty(); });
    }
    inline auto SplitOpenThemeAnimation::OffsetFromCenterProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.OffsetFromCenterProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ContentTranslationDirectionProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ContentTranslationDirectionProperty(); });
    }
    inline auto SplitOpenThemeAnimation::ContentTranslationOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISplitOpenThemeAnimationStatics const&), SplitOpenThemeAnimation, ISplitOpenThemeAnimationStatics>([](ISplitOpenThemeAnimationStatics const& f) { return f.ContentTranslationOffsetProperty(); });
    }
    inline Storyboard::Storyboard() :
        Storyboard(impl::call_factory_cast<Storyboard(*)(winrt::Windows::Foundation::IActivationFactory const&), Storyboard>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Storyboard>(); }))
    {
    }
    inline auto Storyboard::TargetPropertyProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IStoryboardStatics const&), Storyboard, IStoryboardStatics>([](IStoryboardStatics const& f) { return f.TargetPropertyProperty(); });
    }
    inline auto Storyboard::GetTargetProperty(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element)
    {
        return impl::call_factory<Storyboard, IStoryboardStatics>([&](IStoryboardStatics const& f) { return f.GetTargetProperty(element); });
    }
    inline auto Storyboard::SetTargetProperty(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& path)
    {
        impl::call_factory<Storyboard, IStoryboardStatics>([&](IStoryboardStatics const& f) { return f.SetTargetProperty(element, path); });
    }
    inline auto Storyboard::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IStoryboardStatics const&), Storyboard, IStoryboardStatics>([](IStoryboardStatics const& f) { return f.TargetNameProperty(); });
    }
    inline auto Storyboard::GetTargetName(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element)
    {
        return impl::call_factory<Storyboard, IStoryboardStatics>([&](IStoryboardStatics const& f) { return f.GetTargetName(element); });
    }
    inline auto Storyboard::SetTargetName(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& name)
    {
        impl::call_factory<Storyboard, IStoryboardStatics>([&](IStoryboardStatics const& f) { return f.SetTargetName(element, name); });
    }
    inline auto Storyboard::SetTarget(winrt::Windows::UI::Xaml::Media::Animation::Timeline const& timeline, winrt::Windows::UI::Xaml::DependencyObject const& target)
    {
        impl::call_factory<Storyboard, IStoryboardStatics>([&](IStoryboardStatics const& f) { return f.SetTarget(timeline, target); });
    }
    inline SuppressNavigationTransitionInfo::SuppressNavigationTransitionInfo() :
        SuppressNavigationTransitionInfo(impl::call_factory_cast<SuppressNavigationTransitionInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), SuppressNavigationTransitionInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SuppressNavigationTransitionInfo>(); }))
    {
    }
    inline SwipeBackThemeAnimation::SwipeBackThemeAnimation() :
        SwipeBackThemeAnimation(impl::call_factory_cast<SwipeBackThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), SwipeBackThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SwipeBackThemeAnimation>(); }))
    {
    }
    inline auto SwipeBackThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISwipeBackThemeAnimationStatics const&), SwipeBackThemeAnimation, ISwipeBackThemeAnimationStatics>([](ISwipeBackThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline auto SwipeBackThemeAnimation::FromHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISwipeBackThemeAnimationStatics const&), SwipeBackThemeAnimation, ISwipeBackThemeAnimationStatics>([](ISwipeBackThemeAnimationStatics const& f) { return f.FromHorizontalOffsetProperty(); });
    }
    inline auto SwipeBackThemeAnimation::FromVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISwipeBackThemeAnimationStatics const&), SwipeBackThemeAnimation, ISwipeBackThemeAnimationStatics>([](ISwipeBackThemeAnimationStatics const& f) { return f.FromVerticalOffsetProperty(); });
    }
    inline SwipeHintThemeAnimation::SwipeHintThemeAnimation() :
        SwipeHintThemeAnimation(impl::call_factory_cast<SwipeHintThemeAnimation(*)(winrt::Windows::Foundation::IActivationFactory const&), SwipeHintThemeAnimation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SwipeHintThemeAnimation>(); }))
    {
    }
    inline auto SwipeHintThemeAnimation::TargetNameProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISwipeHintThemeAnimationStatics const&), SwipeHintThemeAnimation, ISwipeHintThemeAnimationStatics>([](ISwipeHintThemeAnimationStatics const& f) { return f.TargetNameProperty(); });
    }
    inline auto SwipeHintThemeAnimation::ToHorizontalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISwipeHintThemeAnimationStatics const&), SwipeHintThemeAnimation, ISwipeHintThemeAnimationStatics>([](ISwipeHintThemeAnimationStatics const& f) { return f.ToHorizontalOffsetProperty(); });
    }
    inline auto SwipeHintThemeAnimation::ToVerticalOffsetProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISwipeHintThemeAnimationStatics const&), SwipeHintThemeAnimation, ISwipeHintThemeAnimationStatics>([](ISwipeHintThemeAnimationStatics const& f) { return f.ToVerticalOffsetProperty(); });
    }
    inline auto Timeline::AllowDependentAnimations()
    {
        return impl::call_factory_cast<bool(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.AllowDependentAnimations(); });
    }
    inline auto Timeline::AllowDependentAnimations(bool value)
    {
        impl::call_factory<Timeline, ITimelineStatics>([&](ITimelineStatics const& f) { return f.AllowDependentAnimations(value); });
    }
    inline auto Timeline::AutoReverseProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.AutoReverseProperty(); });
    }
    inline auto Timeline::BeginTimeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.BeginTimeProperty(); });
    }
    inline auto Timeline::DurationProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.DurationProperty(); });
    }
    inline auto Timeline::SpeedRatioProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.SpeedRatioProperty(); });
    }
    inline auto Timeline::FillBehaviorProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.FillBehaviorProperty(); });
    }
    inline auto Timeline::RepeatBehaviorProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ITimelineStatics const&), Timeline, ITimelineStatics>([](ITimelineStatics const& f) { return f.RepeatBehaviorProperty(); });
    }
    inline TimelineCollection::TimelineCollection() :
        TimelineCollection(impl::call_factory_cast<TimelineCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), TimelineCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimelineCollection>(); }))
    {
    }
    inline TransitionCollection::TransitionCollection() :
        TransitionCollection(impl::call_factory_cast<TransitionCollection(*)(winrt::Windows::Foundation::IActivationFactory const&), TransitionCollection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TransitionCollection>(); }))
    {
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) INavigationTransitionInfoOverridesT<D>::GetNavigationStateCore() const
    {
        return shim().template try_as<INavigationTransitionInfoOverrides>().GetNavigationStateCore();
    }
    template <typename D> WINRT_IMPL_AUTO(void) INavigationTransitionInfoOverridesT<D>::SetNavigationStateCore(param::hstring const& navigationState) const
    {
        return shim().template try_as<INavigationTransitionInfoOverrides>().SetNavigationStateCore(navigationState);
    }
    template <typename D, typename... Interfaces>
    struct BasicConnectedAnimationConfigurationT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>,
        impl::base<D, BasicConnectedAnimationConfiguration, winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>
    {
        using composable = BasicConnectedAnimationConfiguration;
    protected:
        BasicConnectedAnimationConfigurationT()
        {
            impl::call_factory<BasicConnectedAnimationConfiguration, IBasicConnectedAnimationConfigurationFactory>([&](IBasicConnectedAnimationConfigurationFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ColorKeyFrameT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ColorKeyFrame, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = ColorKeyFrame;
    protected:
        ColorKeyFrameT()
        {
            impl::call_factory<ColorKeyFrame, IColorKeyFrameFactory>([&](IColorKeyFrameFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DirectConnectedAnimationConfigurationT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>,
        impl::base<D, DirectConnectedAnimationConfiguration, winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>
    {
        using composable = DirectConnectedAnimationConfiguration;
    protected:
        DirectConnectedAnimationConfigurationT()
        {
            impl::call_factory<DirectConnectedAnimationConfiguration, IDirectConnectedAnimationConfigurationFactory>([&](IDirectConnectedAnimationConfigurationFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DoubleKeyFrameT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, DoubleKeyFrame, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = DoubleKeyFrame;
    protected:
        DoubleKeyFrameT()
        {
            impl::call_factory<DoubleKeyFrame, IDoubleKeyFrameFactory>([&](IDoubleKeyFrameFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GravityConnectedAnimationConfigurationT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration, winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2, winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>,
        impl::base<D, GravityConnectedAnimationConfiguration, winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>
    {
        using composable = GravityConnectedAnimationConfiguration;
    protected:
        GravityConnectedAnimationConfigurationT()
        {
            impl::call_factory<GravityConnectedAnimationConfiguration, IGravityConnectedAnimationConfigurationFactory>([&](IGravityConnectedAnimationConfigurationFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct NavigationTransitionInfoT :
        implements<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, NavigationTransitionInfo, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverridesT<D>
    {
        using composable = NavigationTransitionInfo;
    protected:
        NavigationTransitionInfoT()
        {
            impl::call_factory<NavigationTransitionInfo, INavigationTransitionInfoFactory>([&](INavigationTransitionInfoFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ObjectKeyFrameT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ObjectKeyFrame, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = ObjectKeyFrame;
    protected:
        ObjectKeyFrameT()
        {
            impl::call_factory<ObjectKeyFrame, IObjectKeyFrameFactory>([&](IObjectKeyFrameFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct PointKeyFrameT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, PointKeyFrame, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = PointKeyFrame;
    protected:
        PointKeyFrameT()
        {
            impl::call_factory<PointKeyFrame, IPointKeyFrameFactory>([&](IPointKeyFrameFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct TimelineT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Animation::ITimeline, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Timeline, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = Timeline;
    protected:
        TimelineT()
        {
            impl::call_factory<Timeline, ITimelineFactory>([&](ITimelineFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBackEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBackEaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBounceEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICircleEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICubicEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IElasticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IKeySpline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPowerEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPowerEaseStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IQuadraticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IQuarticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IQuinticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IReorderThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISineEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IStoryboard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITimeline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITimelineFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITransitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::AddDeleteThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BackEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BeginStoryboard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BounceEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::CircleEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::CommonNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ContentThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ContinuumNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::CubicEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscreteColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscreteDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscreteObjectKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscretePointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DragItemThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DragOverThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DrillInNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DrillInThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DrillOutThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DropTargetItemThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingPointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EdgeUIThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ElasticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EntranceNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EntranceThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ExponentialEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::FadeInThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::FadeOutThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::KeySpline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::KeyTimeHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::LinearColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::LinearDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::LinearPointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::NavigationThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ObjectAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PaneThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointAnimationUsingKeyFrames> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointerDownThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointerUpThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PopInThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PopOutThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PopupThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PowerEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::QuadraticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::QuarticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::QuinticEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ReorderThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehaviorHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::RepositionThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::RepositionThemeTransition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SineEase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplineColorKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplineDoubleKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplinePointKeyFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplitCloseThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplitOpenThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::Storyboard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SuppressNavigationTransitionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SwipeBackThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SwipeHintThemeAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::Timeline> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::TimelineCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::Transition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
