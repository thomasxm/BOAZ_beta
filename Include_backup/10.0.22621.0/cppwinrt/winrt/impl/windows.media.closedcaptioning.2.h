// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_ClosedCaptioning_2_H
#define WINRT_Windows_Media_ClosedCaptioning_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Media.ClosedCaptioning.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::ClosedCaptioning
{
    struct ClosedCaptionProperties
    {
        ClosedCaptionProperties() = delete;
        [[nodiscard]] static auto FontColor();
        [[nodiscard]] static auto ComputedFontColor();
        [[nodiscard]] static auto FontOpacity();
        [[nodiscard]] static auto FontSize();
        [[nodiscard]] static auto FontStyle();
        [[nodiscard]] static auto FontEffect();
        [[nodiscard]] static auto BackgroundColor();
        [[nodiscard]] static auto ComputedBackgroundColor();
        [[nodiscard]] static auto BackgroundOpacity();
        [[nodiscard]] static auto RegionColor();
        [[nodiscard]] static auto ComputedRegionColor();
        [[nodiscard]] static auto RegionOpacity();
        static auto PropertiesChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using PropertiesChanged_revoker = impl::factory_event_revoker<winrt::Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics2, &impl::abi_t<winrt::Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics2>::remove_PropertiesChanged>;
        [[nodiscard]] static PropertiesChanged_revoker PropertiesChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto PropertiesChanged(winrt::event_token const& token);
    };
}
#endif
