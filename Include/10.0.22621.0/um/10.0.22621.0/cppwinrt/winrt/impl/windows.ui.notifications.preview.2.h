// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Notifications_Preview_2_H
#define WINRT_Windows_UI_Notifications_Preview_2_H
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Notifications.Preview.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Preview
{
    struct ToastOcclusionManagerPreview
    {
        ToastOcclusionManagerPreview() = delete;
        static auto SetToastWindowMargin(winrt::Windows::UI::WindowId const& appWindowId, double margin);
    };
}
#endif
